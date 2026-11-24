//! Detached exec storage and registry (0.6.4, plan sections 2 and 7).
//!
//! A detached exec has no client: its stdout and stderr go to two pipes the
//! supervisor owns. One pump thread per stream appends to a file in
//! `<workspace>/exec/` (dir 0700, files 0600), and a small state file
//! (`hisn-exec-state/v1`) is written atomically at start and at the end.
//! Files are named `<incarnation>-e<N>.<kind>`, so an exec id is unambiguous
//! across supervisor restarts (B4). Nothing here starts a process: the exec
//! is spawned by `Shared::do_exec` through the one exec-helper call.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// At most this many live detached execs per session (`E_BUSY` beyond).
pub const MAX_DETACHED: usize = 32;
pub const STATE_SCHEMA: &str = "hisn-exec-state/v1";
/// How long the waiter lets the pumps drain after the status arrived (B10).
pub const DRAIN_WAIT: Duration = Duration::from_secs(2);
/// How long a waiter that saw the status socket close waits for the session
/// stop flag before it calls the exec `lost` (B9).
pub const STOP_FLAG_WAIT: Duration = Duration::from_secs(3);

// ------------------------------------------------------------ incarnation

/// `<UTC compact YYYYMMDDTHHMMSSZ>-<4 hex>`: safe in a file name. Pure.
pub fn incarnation_from(rfc3339: &str, rnd: [u8; 2]) -> String {
    let compact: String = rfc3339.chars().filter(|c| *c != '-' && *c != ':').collect();
    format!("{compact}-{:02x}{:02x}", rnd[0], rnd[1])
}

/// A fresh incarnation id for this supervisor (created once at start).
pub fn new_incarnation() -> String {
    let mut rnd = [0u8; 2];
    // SAFETY: getrandom writes at most `rnd.len()` bytes into our buffer.
    let n = unsafe { libc::getrandom(rnd.as_mut_ptr().cast(), rnd.len(), 0) };
    if n != rnd.len() as isize {
        // Never fatal: the timestamp alone is enough in practice; mix the pid.
        let p = std::process::id();
        rnd = [(p >> 8) as u8, p as u8];
    }
    incarnation_from(&crate::session::rfc3339_now(), rnd)
}

// ------------------------------------------------------------------ paths

/// The `exec/` directory of a workspace, created `0700` (never through a
/// symlink; a pre-existing directory is tightened to `0700`).
pub fn exec_dir(workspace_dir: &Path) -> io::Result<PathBuf> {
    let dir = workspace_dir.join("exec");
    match fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let md = fs::symlink_metadata(&dir)?;
    if !md.is_dir() {
        return Err(io::Error::other("exec path is not a directory"));
    }
    if md.permissions().mode() & 0o777 != 0o700 {
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

/// `<dir>/<incarnation>-e<N>.<kind>` (`kind`: `state.json`, `stdout`, ...).
pub fn exec_file(dir: &Path, incarnation: &str, exec_id: u64, kind: &str) -> PathBuf {
    dir.join(format!("{incarnation}-e{exec_id}.{kind}"))
}

// ------------------------------------------------------------ state file

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamCounts {
    pub total: u64,
    pub base: u64,
}

/// `hisn-exec-state/v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecState {
    pub schema: String,
    pub incarnation: String,
    pub exec_id: String,
    pub seat: Option<String>,
    pub argv0: String,
    pub started: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<String>,
    /// `running` | `exited` | `signalled` | `lost`.
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal_name: Option<String>,
    /// `exit` | `signal` | `exec-signal` | `session-stop` | `lost`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    pub pid: i32,
    /// True while a pump has not seen EOF (a grandchild holds the pipe).
    pub output_open: bool,
    pub stdout: StreamCounts,
    pub stderr: StreamCounts,
    /// The writing supervisor's host pid and `/proc` starttime (plan 9.1 D6):
    /// the identity the foreign-state rule tests. `pid` above is a pid inside
    /// the sandbox and says nothing on the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supervisor_pid: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supervisor_start: Option<u64>,
}

/// Write `st` atomically (temp file `0600` + rename).
pub fn write_state(path: &Path, st: &ExecState) -> io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(&serde_json::to_vec(st).map_err(io::Error::other)?)?;
    f.write_all(b"\n")?;
    drop(f);
    fs::rename(&tmp, path)
}

pub fn read_state(path: &Path) -> io::Result<ExecState> {
    let b = fs::read(path)?;
    serde_json::from_slice(&b).map_err(io::Error::other)
}

// ------------------------------------------------------------------ pump

/// Upper bound of one `exec-output` reply (and its default).
pub const READ_MAX: usize = 1024 * 1024;
/// A stream file is rotated when it reaches this size: the current file plus
/// one previous file are kept, so at most twice this per stream (plan 2.3).
pub const EXEC_ROTATE_BYTES: u64 = 8 * 1024 * 1024;
/// At most this many finished execs keep their files (plan 2.5).
pub const MAX_FINISHED: usize = 256;

#[derive(Debug, Default)]
struct StreamInner {
    /// Absolute offset of the first byte of the current file.
    cur_base: u64,
    /// Absolute offset of the first byte of the previous file, if it exists.
    prev_base: Option<u64>,
}

/// Live state of one output stream, shared with its pump thread. Writes and
/// reads both take `inner`, so a read never sees a half-moved file.
#[derive(Default)]
pub struct Stream {
    /// Bytes appended to the stream so far (updated under `inner`).
    pub total: AtomicU64,
    /// The pump saw EOF on the pipe (every writer closed it).
    pub eof: AtomicBool,
    path: PathBuf,
    inner: Mutex<StreamInner>,
    /// Rotation size; 0 = [`EXEC_ROTATE_BYTES`] (tests inject a small one).
    limit: u64,
    /// Called by the pump thread after a rotation (outside `inner`), so the
    /// state file's `base` follows the files.
    on_rotate: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream")
            .field("path", &self.path)
            .field("total", &self.total.load(Ordering::SeqCst))
            .finish()
    }
}

/// `<path>.1`: the previous file of a stream.
pub fn prev_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".1");
    PathBuf::from(s)
}

impl Stream {
    fn new(path: &Path, limit: u64) -> Self {
        Self {
            path: path.to_path_buf(),
            limit,
            ..Self::default()
        }
    }

    fn rotate_at(&self) -> u64 {
        if self.limit == 0 {
            EXEC_ROTATE_BYTES
        } else {
            self.limit
        }
    }

    /// Register the callback run after each rotation.
    pub fn set_on_rotate(&self, f: Arc<dyn Fn() + Send + Sync>) {
        *self.on_rotate.lock().expect("on_rotate") = Some(f);
    }

    /// `total` and the oldest offset still kept, for the state file.
    pub fn counts(&self) -> StreamCounts {
        let g = self.inner.lock().expect("stream");
        StreamCounts {
            total: self.total.load(Ordering::SeqCst),
            base: g.prev_base.unwrap_or(g.cur_base),
        }
    }

    /// Read at most `max` bytes from absolute `offset` (see [`read_layout`]).
    pub fn read(&self, offset: u64, max: usize) -> io::Result<ReadOut> {
        let g = self.inner.lock().expect("stream");
        let l = Layout {
            cur: self.path.clone(),
            prev: g.prev_base.map(|_| prev_path(&self.path)),
            prev_base: g.prev_base.unwrap_or(0),
            cur_base: g.cur_base,
            total: self.total.load(Ordering::SeqCst),
        };
        read_layout(&l, offset, max)
    }

    /// Append `chunk`, rotating whenever the current file reaches the limit.
    /// A write error discards the rest of the chunk (nothing is counted);
    /// a failed rotation keeps writing to the current file (R-a). Returns
    /// whether a rotation happened.
    fn append(&self, file: &mut fs::File, mut chunk: &[u8]) -> bool {
        let mut rotated = false;
        let mut g = self.inner.lock().expect("stream");
        while !chunk.is_empty() {
            let cur_len = self.total.load(Ordering::SeqCst).saturating_sub(g.cur_base);
            let room = self.rotate_at().saturating_sub(cur_len);
            let n = if room == 0 {
                chunk.len()
            } else {
                chunk.len().min(room as usize)
            };
            if file.write_all(&chunk[..n]).is_err() {
                return rotated;
            }
            self.total.fetch_add(n as u64, Ordering::SeqCst);
            chunk = &chunk[n..];
            let cur_len = self.total.load(Ordering::SeqCst).saturating_sub(g.cur_base);
            if cur_len >= self.rotate_at() && self.rotate(&mut g, file) {
                rotated = true;
            }
        }
        rotated
    }

    /// Move the current file to `<path>.1` (replacing the previous one) and
    /// start a new current file. `false` = nothing changed.
    fn rotate(&self, g: &mut StreamInner, file: &mut fs::File) -> bool {
        let prev = prev_path(&self.path);
        if fs::rename(&self.path, &prev).is_err() {
            return false;
        }
        match fs::OpenOptions::new()
            .append(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.path)
        {
            Ok(f) => {
                *file = f;
                g.prev_base = Some(g.cur_base);
                g.cur_base = self.total.load(Ordering::SeqCst);
                true
            }
            Err(_) => {
                // Undo: the old descriptor keeps writing to the old file.
                let _ = fs::rename(&prev, &self.path);
                false
            }
        }
    }
}

/// Where the bytes of one stream are: the current file, the previous file if
/// any, and the absolute offsets of their first bytes.
#[derive(Debug, Clone)]
pub struct Layout {
    pub cur: PathBuf,
    pub prev: Option<PathBuf>,
    pub prev_base: u64,
    pub cur_base: u64,
    pub total: u64,
}

/// The result of one read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOut {
    pub data: Vec<u8>,
    /// Absolute offset of `data[0]` (the requested one unless rotated away).
    pub offset: u64,
    pub next: u64,
    pub total: u64,
    /// The oldest offset still kept.
    pub oldest: u64,
    pub rotated_away: bool,
}

fn read_at_most(path: &Path, pos: u64, n: usize) -> io::Result<Vec<u8>> {
    let f = fs::File::open(path)?;
    let mut buf = vec![0u8; n];
    let mut got = 0;
    while got < n {
        match f.read_at(&mut buf[got..], pos + got as u64) {
            Ok(0) => break,
            Ok(k) => got += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    buf.truncate(got);
    Ok(buf)
}

/// Read from absolute `offset` across the previous and current file (plan
/// 2.4, D7): an offset older than the oldest kept byte starts at the oldest
/// and sets `rotated_away`; an offset beyond `total` returns nothing with
/// `next == total`. Arithmetic is saturating.
pub fn read_layout(l: &Layout, offset: u64, max: usize) -> io::Result<ReadOut> {
    let oldest = if l.prev.is_some() {
        l.prev_base
    } else {
        l.cur_base
    };
    let rotated_away = offset < oldest;
    let start = offset.max(oldest).min(l.total);
    let max = max.min(READ_MAX);
    let mut data = Vec::new();
    let mut pos = start;
    while data.len() < max && pos < l.total {
        let (path, base, limit) = match &l.prev {
            Some(p) if pos < l.cur_base => (p.as_path(), l.prev_base, l.cur_base),
            _ => (l.cur.as_path(), l.cur_base, l.total),
        };
        let n = (max - data.len()).min(limit.saturating_sub(pos) as usize);
        let got = read_at_most(path, pos.saturating_sub(base), n)?;
        if got.is_empty() {
            break;
        }
        pos = pos.saturating_add(got.len() as u64);
        data.extend_from_slice(&got);
    }
    Ok(ReadOut {
        data,
        offset: start,
        next: pos,
        total: l.total,
        oldest,
        rotated_away,
    })
}

/// The layout of a stream with no live pump (a finished exec, or another
/// supervisor's), from its files and the state file's `base`: with a
/// previous file the current one starts where it ends.
pub fn layout_from_files(cur: &Path, base: u64) -> io::Result<Layout> {
    let cur_len = fs::metadata(cur)?.len();
    let prev = prev_path(cur);
    match fs::metadata(&prev) {
        Ok(m) => {
            let cur_base = base.saturating_add(m.len());
            Ok(Layout {
                cur: cur.to_path_buf(),
                prev: Some(prev),
                prev_base: base,
                cur_base,
                total: cur_base.saturating_add(cur_len),
            })
        }
        Err(_) => Ok(Layout {
            cur: cur.to_path_buf(),
            prev: None,
            prev_base: 0,
            cur_base: base,
            total: base.saturating_add(cur_len),
        }),
    }
}

/// A fresh anonymous pipe as `(read, write)`, both close-on-exec.
pub fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe2 writes two descriptors into the array we own.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both are fresh descriptors owned by nobody else.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Start the pump of one stream: a thread that reads `read` until EOF and
/// appends to a new `0600` file at `path`, rotating at [`EXEC_ROTATE_BYTES`].
/// A write error (ENOSPC, ...) keeps draining and discards, so the program
/// never blocks on a full pipe (B10).
pub fn start_pump(read: OwnedFd, path: &Path) -> io::Result<Arc<Stream>> {
    start_pump_limit(read, path, EXEC_ROTATE_BYTES)
}

/// [`start_pump`] with an injected rotation size.
pub fn start_pump_limit(read: OwnedFd, path: &Path, limit: u64) -> io::Result<Arc<Stream>> {
    let file = fs::OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    let stream = Arc::new(Stream::new(path, limit));
    pump_into(read, file, &stream)?;
    Ok(stream)
}

fn pump_into(read: OwnedFd, mut file: fs::File, stream: &Arc<Stream>) -> io::Result<()> {
    let s = Arc::clone(stream);
    std::thread::Builder::new()
        .name("exec-pump".into())
        .spawn(move || {
            let mut src = fs::File::from(read);
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match src.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if s.append(&mut file, &buf[..n]) {
                            let cb = s.on_rotate.lock().expect("on_rotate").clone();
                            if let Some(cb) = cb {
                                cb();
                            }
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            s.eof.store(true, Ordering::SeqCst);
        })?;
    Ok(())
}

/// The `eof` of one `exec-output` reply (plan 7 B10): the exec's state was
/// final **and** this stream's pump had seen EOF — both observed *before*
/// the read, so `total` is final — and the reader reached `total`.
pub fn output_eof(final_before: bool, pump_eof_before: bool, next: u64, total: u64) -> bool {
    final_before && pump_eof_before && next >= total
}

/// Wait until every stream's pump has seen EOF, at most `timeout`.
pub fn wait_pumps(streams: &[&Stream], timeout: Duration) -> bool {
    let end = Instant::now() + timeout;
    loop {
        if streams.iter().all(|s| s.eof.load(Ordering::SeqCst)) {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

// ----------------------------------------------------------------- slots

/// The 32-exec limit. A slot is reserved before the spawn and released by
/// the guard's drop, so a failed spawn can never leak one.
#[derive(Debug)]
pub struct Slots {
    used: AtomicUsize,
    max: usize,
}

impl Slots {
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            used: AtomicUsize::new(0),
            max,
        })
    }

    pub fn reserve(self: &Arc<Self>) -> Option<SlotGuard> {
        let mut cur = self.used.load(Ordering::SeqCst);
        loop {
            if cur >= self.max {
                return None;
            }
            match self
                .used
                .compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Some(SlotGuard(Arc::clone(self))),
                Err(c) => cur = c,
            }
        }
    }

    pub fn used(&self) -> usize {
        self.used.load(Ordering::SeqCst)
    }
}

#[derive(Debug)]
pub struct SlotGuard(Arc<Slots>);

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.used.fetch_sub(1, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------- status & ids

/// `e-N` -> `N`.
pub fn parse_exec_id(s: &str) -> Option<u64> {
    s.strip_prefix("e-")?.parse().ok()
}

/// An incarnation as it may appear in a file name: ASCII alphanumerics and
/// `-`, non-empty, short. A request value is checked before it is used in a
/// path.
pub fn valid_incarnation(s: &str) -> bool {
    !s.is_empty() && s.len() <= 40 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Is the supervisor that wrote `st` gone? `None` = the file carries no
/// supervisor identity (written by an older build), so nothing can be said.
pub fn writer_gone(st: &ExecState) -> Option<bool> {
    let (pid, start) = (st.supervisor_pid?, st.supervisor_start?);
    Some(match crate::sys::stat_starttime(pid) {
        Ok(cur) => cur != start,
        Err(_) => true,
    })
}

/// The state a reader reports: a `running` file of another incarnation whose
/// writer is gone (or unknowable) is `lost` (plan 2.2, B5).
pub fn effective_state(mut st: ExecState, live_incarnation: &str) -> ExecState {
    if st.state == "running"
        && st.incarnation != live_incarnation
        && writer_gone(&st).unwrap_or(true)
    {
        st.state = "lost".into();
        st.cause = Some("lost".into());
    }
    st
}

/// The `exec-status` reply object: the state fields, `pid` only while
/// running, never the supervisor identity.
pub fn status_json(st: &ExecState) -> Value {
    let mut v = serde_json::to_value(st).unwrap_or(Value::Null);
    if let Some(o) = v.as_object_mut() {
        o.remove("supervisor_pid");
        o.remove("supervisor_start");
        if st.state != "running" {
            o.remove("pid");
        }
    }
    v
}

/// Is the exec's state final (no longer running)?
pub fn is_final(state: &str) -> bool {
    state != "running"
}

// ---------------------------------------------------------------- base64

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0;
    for ch in s.bytes().filter(|b| *b != b'=') {
        let v = B64.iter().position(|b| *b == ch)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

// ------------------------------------------------------------- retention

/// The files of one exec (`<incarnation>-e<N>.*`), all kinds.
fn exec_files_of(dir: &Path, stem: &str) -> Vec<PathBuf> {
    [
        "state.json",
        "state.json.tmp",
        "stdout",
        "stdout.1",
        "stderr",
        "stderr.1",
    ]
    .iter()
    .map(|k| dir.join(format!("{stem}.{k}")))
    .collect()
}

/// Delete the logs of finished execs (plan 2.5, B5): a finished exec whose
/// `ended` is older than `oldest_ts` (the oldest journal record; `None` = no
/// age rule), then the oldest beyond `max_finished`. A `running` file of the
/// live incarnation is never touched; one of another incarnation counts as
/// lost only when its writer is gone, and a file with no writer identity is
/// left alone. A file whose output is still open (pumps may be writing) is
/// skipped **while its writer may still be alive** (live incarnation, or a
/// foreign one whose writer is not known gone) and does not count against
/// `max_finished`; once the writer is gone the pumps are dead, so the files
/// are prunable. Best effort; returns the number of execs removed.
pub fn prune(
    dir: &Path,
    live_incarnation: &str,
    oldest_ts: Option<&str>,
    max_finished: usize,
) -> usize {
    let Ok(rd) = fs::read_dir(dir) else { return 0 };
    // (ended-or-started, stem)
    let mut finished: Vec<(String, String)> = Vec::new();
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".state.json") else {
            continue;
        };
        let Ok(st) = read_state(&e.path()) else {
            continue;
        };
        if st.state == "running" {
            if st.incarnation == live_incarnation || writer_gone(&st) != Some(true) {
                continue;
            }
            finished.push((st.started.clone(), stem.to_owned()));
        } else {
            // 0.6.5 (round 2 finding): a finished exec whose pumps are still
            // writing (grandchild holding the pipes) must not be unlinked under
            // a live pump. `output_open` is false only after both pumps saw EOF
            // and the final state was written. Skip only while the writer is
            // positively alive (live incarnation, or a foreign one whose
            // supervisor pid/starttime still match): then the pumps may run.
            // A gone writer means dead pumps; no identity at all means an old
            // build that never maintained the flag — both stay collectible,
            // as before. Skipped entries leave `finished` entirely, so they do
            // not count against `max_finished`.
            if st.output_open
                && (st.incarnation == live_incarnation || writer_gone(&st) == Some(false))
            {
                continue;
            }
            finished.push((
                st.ended.clone().unwrap_or(st.started.clone()),
                stem.to_owned(),
            ));
        }
    }
    finished.sort();
    let mut doomed: Vec<&str> = Vec::new();
    for (t, stem) in &finished {
        if oldest_ts.is_some_and(|o| t.as_str() < o) {
            doomed.push(stem);
        }
    }
    let kept = finished.len() - doomed.len();
    if kept > max_finished {
        let extra = kept - max_finished;
        let more: Vec<&str> = finished
            .iter()
            .map(|(_, stem)| stem.as_str())
            .filter(|stem| !doomed.contains(stem))
            .take(extra)
            .collect();
        doomed.extend(more);
    }
    for stem in &doomed {
        for f in exec_files_of(dir, stem) {
            let _ = fs::remove_file(f);
        }
    }
    doomed.len()
}

// -------------------------------------------------------------- registry

/// One live detached exec.
#[derive(Debug)]
pub struct DetachedExec {
    pub exec_id: u64,
    /// The seat that started it (`None` = the owner, no credential).
    pub seat: Option<String>,
    pub argv0: String,
    pub pid: i32,
    pub started: String,
    pub stdout: Arc<Stream>,
    pub stderr: Arc<Stream>,
    /// An `exec-signal` was delivered before the end (cause bookkeeping).
    pub signalled: AtomicBool,
    /// The state file's content (plan 9.1 D4): every write of the file goes
    /// through this mutex, so the waiter and the readers cannot race.
    state: Mutex<ExecState>,
    state_path: PathBuf,
}

impl DetachedExec {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        exec_id: u64,
        seat: Option<String>,
        argv0: String,
        pid: i32,
        started: String,
        stdout: Arc<Stream>,
        stderr: Arc<Stream>,
        state: ExecState,
        state_path: PathBuf,
    ) -> Self {
        Self {
            exec_id,
            seat,
            argv0,
            pid,
            started,
            stdout,
            stderr,
            signalled: AtomicBool::new(false),
            state: Mutex::new(state),
            state_path,
        }
    }

    fn refresh(&self, st: &mut ExecState) {
        st.stdout = self.stdout.counts();
        st.stderr = self.stderr.counts();
        st.output_open =
            !(self.stdout.eof.load(Ordering::SeqCst) && self.stderr.eof.load(Ordering::SeqCst));
    }

    /// The current state with live counters.
    pub fn snapshot(&self) -> ExecState {
        let mut st = self.state.lock().expect("exec state").clone();
        self.refresh(&mut st);
        st
    }

    /// Change the state, refresh the counters and write the state file
    /// (best effort: the live entry still answers if the write fails).
    pub fn update(&self, f: impl FnOnce(&mut ExecState)) -> ExecState {
        let mut g = self.state.lock().expect("exec state");
        f(&mut g);
        self.refresh(&mut g);
        let _ = write_state(&self.state_path, &g);
        g.clone()
    }
}

/// The live detached execs plus the session `stopping` flag (B9).
#[derive(Debug, Default)]
pub struct Registry {
    map: Mutex<BTreeMap<u64, Arc<DetachedExec>>>,
    stopping: AtomicBool,
}

impl Registry {
    pub fn insert(&self, e: Arc<DetachedExec>) {
        self.map.lock().expect("detached").insert(e.exec_id, e);
    }

    pub fn remove(&self, exec_id: u64) {
        self.map.lock().expect("detached").remove(&exec_id);
    }

    pub fn get(&self, exec_id: u64) -> Option<Arc<DetachedExec>> {
        self.map.lock().expect("detached").get(&exec_id).cloned()
    }

    pub fn running(&self) -> Vec<Arc<DetachedExec>> {
        self.map
            .lock()
            .expect("detached")
            .values()
            .cloned()
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.map.lock().expect("detached").is_empty()
    }

    pub fn set_stopping(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }

    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// Wait for the stop flag, at most `timeout`; true when it is set.
    pub fn wait_stopping(&self, timeout: Duration) -> bool {
        let end = Instant::now() + timeout;
        while !self.is_stopping() {
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        true
    }

    pub fn wait_empty(&self, timeout: Duration) -> bool {
        let end = Instant::now() + timeout;
        while !self.is_empty() {
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        true
    }
}

/// The session-stop sequence for detached execs (B9): set the stop flag,
/// snapshot the running ones, `TERM` them, `KILL` the survivors after
/// `term_wait`, wait at most `kill_wait` more for their waiters (which
/// journal `exec/exit` with cause `session-stop`). Returns the
/// `detached_execs_ended` list for the `session/stop` record, empty when
/// there was none. `send` delivers one signal to one exec.
pub fn stop_sequence(
    reg: &Registry,
    incarnation: &str,
    send: &dyn Fn(u64, i32),
    term_wait: Duration,
    kill_wait: Duration,
) -> Vec<Value> {
    reg.set_stopping();
    let snap = reg.running();
    if snap.is_empty() {
        return Vec::new();
    }
    for e in &snap {
        send(e.exec_id, libc::SIGTERM);
    }
    if !reg.wait_empty(term_wait) {
        for e in reg.running() {
            send(e.exec_id, libc::SIGKILL);
        }
        reg.wait_empty(kill_wait);
    }
    snap.iter()
        .map(|e| json!({ "exec_id": format!("e-{}", e.exec_id), "incarnation": incarnation, "pid": e.pid }))
        .collect()
}

/// The journal `cause` of a detached exec's end (plan 2.9 and B9). The stop
/// flag wins: whatever the status socket said, the session was ending.
pub fn detached_cause(
    exited: Option<crate::exec::Exit>,
    stopping: bool,
    signalled_by_hisn: bool,
) -> &'static str {
    use crate::exec::Exit;
    if stopping {
        return "session-stop";
    }
    match exited {
        Some(Exit::Code(_)) => "exit",
        Some(Exit::Signal(_)) if signalled_by_hisn => "exec-signal",
        Some(Exit::Signal(_)) => "signal",
        None => "lost",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::Exit;
    use std::os::unix::fs::MetadataExt;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hisn-execlog-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn state(id: u64) -> ExecState {
        ExecState {
            schema: STATE_SCHEMA.into(),
            incarnation: "20261122T101500Z-9f3a".into(),
            exec_id: format!("e-{id}"),
            seat: Some("bob".into()),
            argv0: "sleep".into(),
            started: "2026-11-22T10:15:00Z".into(),
            ended: None,
            state: "running".into(),
            exit_code: None,
            signal: None,
            signal_name: None,
            cause: None,
            pid: 7,
            output_open: true,
            stdout: StreamCounts::default(),
            stderr: StreamCounts::default(),
            supervisor_pid: None,
            supervisor_start: None,
        }
    }

    #[test]
    fn incarnation_format_is_filename_safe() {
        let i = incarnation_from("2026-11-22T10:15:00Z", [0x9f, 0x3a]);
        assert_eq!(i, "20261122T101500Z-9f3a");
        assert!(
            i.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "{i}"
        );
        let live = new_incarnation();
        assert_eq!(live.len(), "20261122T101500Z-9f3a".len(), "{live}");
        assert!(live.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    }

    #[test]
    fn exec_log_path_distinct_across_incarnations() {
        let d = Path::new("/w/exec");
        let a = exec_file(d, "20261122T101500Z-9f3a", 1, "stdout");
        let b = exec_file(d, "20261122T101600Z-0001", 1, "stdout");
        assert_ne!(a, b);
        assert!(
            a.to_str()
                .unwrap()
                .ends_with("20261122T101500Z-9f3a-e1.stdout")
        );
    }

    #[test]
    fn state_file_atomic_roundtrip() {
        let d = tmp("state");
        let p = exec_file(&d, "i", 3, "state.json");
        let mut st = state(3);
        write_state(&p, &st).unwrap();
        assert_eq!(read_state(&p).unwrap(), st);
        st.state = "exited".into();
        st.exit_code = Some(5);
        st.ended = Some("2026-11-22T10:16:00Z".into());
        write_state(&p, &st).unwrap();
        assert_eq!(read_state(&p).unwrap(), st);
        assert!(!p.with_extension("json.tmp").exists(), "temp renamed away");
        assert_eq!(fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
        let raw: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        assert_eq!(raw["schema"], "hisn-exec-state/v1");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn files_are_mode_600_dir_700() {
        let d = tmp("modes");
        let dir = exec_dir(&d).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        // A looser pre-existing directory is tightened.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        exec_dir(&d).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        let (r, w) = pipe().unwrap();
        let p = exec_file(&dir, "i", 1, "stdout");
        let s = start_pump(r, &p).unwrap();
        drop(w);
        assert!(wait_pumps(&[&s], Duration::from_secs(2)));
        assert_eq!(fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn pump_writes_stream_and_counts_bytes() {
        let d = tmp("pump");
        let (r, w) = pipe().unwrap();
        let p = exec_file(&d, "i", 1, "stdout");
        let s = start_pump(r, &p).unwrap();
        let mut w = fs::File::from(w);
        w.write_all(b"hello ").unwrap();
        w.write_all(b"world").unwrap();
        drop(w);
        assert!(wait_pumps(&[&s], Duration::from_secs(2)));
        assert_eq!(s.total.load(Ordering::SeqCst), 11);
        assert_eq!(fs::read(&p).unwrap(), b"hello world");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn stdout_and_stderr_are_separate() {
        let d = tmp("sep");
        let (ro, wo) = pipe().unwrap();
        let (re, we) = pipe().unwrap();
        let po = exec_file(&d, "i", 1, "stdout");
        let pe = exec_file(&d, "i", 1, "stderr");
        let so = start_pump(ro, &po).unwrap();
        let se = start_pump(re, &pe).unwrap();
        fs::File::from(wo).write_all(b"out").unwrap();
        fs::File::from(we).write_all(b"error!").unwrap();
        assert!(wait_pumps(&[&so, &se], Duration::from_secs(2)));
        assert_eq!(fs::read(&po).unwrap(), b"out");
        assert_eq!(fs::read(&pe).unwrap(), b"error!");
        assert_eq!(so.total.load(Ordering::SeqCst), 3);
        assert_eq!(se.total.load(Ordering::SeqCst), 6);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn pump_refuses_to_reuse_an_existing_file() {
        let d = tmp("excl");
        let p = exec_file(&d, "i", 1, "stdout");
        fs::write(&p, b"x").unwrap();
        let (r, _w) = pipe().unwrap();
        assert!(start_pump(r, &p).is_err());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn exited_state_set_when_status_arrives_even_if_pipe_open() {
        // A grandchild holding the pipe keeps the pump from seeing EOF:
        // `wait_pumps` times out (output_open stays true) instead of
        // blocking the final state forever.
        let d = tmp("open");
        let (r, w) = pipe().unwrap();
        let p = exec_file(&d, "i", 1, "stdout");
        let s = start_pump(r, &p).unwrap();
        assert!(!wait_pumps(&[&s], Duration::from_millis(60)));
        assert!(!s.eof.load(Ordering::SeqCst));
        drop(w);
        assert!(wait_pumps(&[&s], Duration::from_secs(2)));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn detach_limit_32_refused() {
        let slots = Slots::new(MAX_DETACHED);
        assert_eq!(MAX_DETACHED, 32);
        let guards: Vec<_> = (0..32).map(|_| slots.reserve().unwrap()).collect();
        assert!(slots.reserve().is_none(), "the 33rd is refused");
        assert_eq!(slots.used(), 32);
        drop(guards);
        assert_eq!(slots.used(), 0);
    }

    #[test]
    fn detach_slot_released_on_spawn_failure() {
        let slots = Slots::new(1);
        {
            let g = slots.reserve().unwrap();
            assert!(slots.reserve().is_none());
            // The spawn failed: the guard goes out of scope with the error.
            let _ = g;
        }
        assert!(slots.reserve().is_some(), "slot is free again");
    }

    fn entry(id: u64) -> Arc<DetachedExec> {
        Arc::new(DetachedExec::new(
            id,
            None,
            "sleep".into(),
            10 + id as i32,
            "t".into(),
            Arc::default(),
            Arc::default(),
            state(id),
            PathBuf::from("/nonexistent/state.json"),
        ))
    }

    #[test]
    fn stop_ends_running_detached_exec_and_lists_it() {
        let reg = Arc::new(Registry::default());
        reg.insert(entry(1));
        reg.insert(entry(2));
        let sent = Mutex::new(Vec::<(u64, i32)>::new());
        let reg2 = Arc::clone(&reg);
        // A fake waiter: a TERM ends exec 1, exec 2 ignores TERM and dies of KILL.
        let send = |id: u64, sig: i32| {
            sent.lock().unwrap().push((id, sig));
            if (id == 1 && sig == libc::SIGTERM) || sig == libc::SIGKILL {
                reg2.remove(id);
            }
        };
        let ended = stop_sequence(
            &reg,
            "20261122T101500Z-9f3a",
            &send,
            Duration::from_millis(60),
            Duration::from_millis(500),
        );
        assert!(reg.is_stopping());
        assert!(reg.is_empty());
        assert_eq!(
            ended,
            vec![
                json!({"exec_id":"e-1","incarnation":"20261122T101500Z-9f3a","pid":11}),
                json!({"exec_id":"e-2","incarnation":"20261122T101500Z-9f3a","pid":12}),
            ]
        );
        let sent = sent.lock().unwrap().clone();
        assert!(sent.contains(&(2, libc::SIGKILL)) && !sent.contains(&(1, libc::SIGKILL)));
    }

    #[test]
    fn stop_with_no_detached_exec_lists_nothing() {
        let reg = Registry::default();
        let v = stop_sequence(
            &reg,
            "i",
            &|_, _| panic!("nothing to signal"),
            Duration::from_millis(1),
            Duration::from_millis(1),
        );
        assert!(v.is_empty());
        assert!(reg.is_stopping());
    }

    #[test]
    fn cause_table() {
        assert_eq!(detached_cause(Some(Exit::Code(0)), false, false), "exit");
        assert_eq!(
            detached_cause(Some(Exit::Signal(9)), false, false),
            "signal"
        );
        assert_eq!(
            detached_cause(Some(Exit::Signal(15)), false, true),
            "exec-signal"
        );
        assert_eq!(detached_cause(None, false, false), "lost");
        assert_eq!(detached_cause(None, true, false), "session-stop");
        assert_eq!(
            detached_cause(Some(Exit::Signal(15)), true, true),
            "session-stop"
        );
    }

    #[test]
    fn registry_wait_stopping_sees_the_flag() {
        let reg = Arc::new(Registry::default());
        assert!(!reg.wait_stopping(Duration::from_millis(30)));
        let r2 = Arc::clone(&reg);
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            r2.set_stopping();
        });
        assert!(reg.wait_stopping(Duration::from_secs(2)));
        t.join().unwrap();
    }

    #[test]
    fn base64_roundtrip() {
        for n in 0..40usize {
            let d: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(b64_decode(&b64_encode(&d)).unwrap(), d, "len {n}");
        }
        assert_eq!(b64_encode(b"hello"), "aGVsbG8=");
        assert!(b64_decode("a*b=").is_none());
    }

    #[test]
    fn exec_id_and_incarnation_parsing() {
        assert_eq!(parse_exec_id("e-12"), Some(12));
        assert_eq!(parse_exec_id("12"), None);
        assert_eq!(parse_exec_id("e-x"), None);
        assert!(valid_incarnation("20261122T101500Z-9f3a"));
        assert!(!valid_incarnation("../x"));
        assert!(!valid_incarnation(""));
    }

    #[test]
    fn status_for_old_incarnation_reads_state_file() {
        // A running file of another incarnation, writer gone: reported lost;
        // a finished one is reported as written; pid only while running.
        let mut st = state(1);
        st.supervisor_pid = Some(i32::MAX);
        st.supervisor_start = Some(1);
        let lost = effective_state(st.clone(), "20261122T999999Z-0000");
        assert_eq!(lost.state, "lost");
        assert_eq!(lost.cause.as_deref(), Some("lost"));
        assert!(status_json(&lost).get("pid").is_none());
        // Same incarnation: untouched.
        assert_eq!(
            effective_state(st.clone(), &st.incarnation).state,
            "running"
        );
        assert!(status_json(&st).get("pid").is_some());
        // A live writer (this process) keeps it running.
        let mut alive = state(2);
        alive.supervisor_pid = Some(std::process::id() as i32);
        alive.supervisor_start =
            Some(crate::sys::stat_starttime(std::process::id() as i32).unwrap());
        assert_eq!(effective_state(alive, "other").state, "running");
        // Finished stays finished.
        let mut done = state(3);
        done.state = "exited".into();
        assert_eq!(effective_state(done, "other").state, "exited");
    }

    #[test]
    fn exec_status_json_shape() {
        let mut st = state(4);
        st.supervisor_pid = Some(5);
        let v = status_json(&st);
        for k in [
            "schema",
            "incarnation",
            "exec_id",
            "seat",
            "argv0",
            "started",
            "state",
            "pid",
            "output_open",
            "stdout",
            "stderr",
        ] {
            assert!(v.get(k).is_some(), "{k} in {v}");
        }
        assert!(v.get("supervisor_pid").is_none());
        assert_eq!(v["stdout"], json!({"total":0,"base":0}));
        assert_eq!(v["exec_id"], "e-4");
    }

    #[test]
    fn read_without_rotation_is_a_plain_file_read() {
        let d = tmp("plainread");
        let (r, w) = pipe().unwrap();
        let p = exec_file(&d, "i", 1, "stdout");
        let s = start_pump(r, &p).unwrap();
        fs::File::from(w).write_all(b"0123456789").unwrap();
        assert!(wait_pumps(&[&s], Duration::from_secs(2)));
        let o = s.read(0, 4).unwrap();
        assert_eq!(
            (o.data.as_slice(), o.offset, o.next, o.total),
            (&b"0123"[..], 0, 4, 10)
        );
        assert!(!o.rotated_away);
        let o = s.read(4, 100).unwrap();
        assert_eq!((o.data.as_slice(), o.next), (&b"456789"[..], 10));
        // Past the end: empty, next == total (D7).
        let o = s.read(99, 10).unwrap();
        assert!(o.data.is_empty());
        assert_eq!((o.offset, o.next, o.total), (10, 10, 10));
        assert_eq!(s.counts(), StreamCounts { total: 10, base: 0 });
        fs::remove_dir_all(&d).unwrap();
    }

    fn pump_with(limit: u64, name: &str) -> (PathBuf, Arc<Stream>, fs::File) {
        let d = tmp(name);
        let (r, w) = pipe().unwrap();
        let p = exec_file(&d, "i", 1, "stdout");
        let s = start_pump_limit(r, &p, limit).unwrap();
        (d, s, fs::File::from(w))
    }

    fn bytes(range: std::ops::Range<usize>) -> Vec<u8> {
        range.map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn pump_rotates_at_limit_and_keeps_previous() {
        let (d, s, mut w) = pump_with(100, "rot");
        let data = bytes(0..250);
        w.write_all(&data).unwrap();
        drop(w);
        assert!(wait_pumps(&[&s], Duration::from_secs(2)));
        let p = exec_file(&d, "i", 1, "stdout");
        // 250 bytes at limit 100: files hold [100..200) (previous) and [200..250).
        assert_eq!(fs::read(prev_path(&p)).unwrap(), &data[100..200]);
        assert_eq!(fs::read(&p).unwrap(), &data[200..250]);
        assert_eq!(
            s.counts(),
            StreamCounts {
                total: 250,
                base: 100
            }
        );
        // Reading from the start reports rotation and returns the oldest kept.
        let o = s.read(0, 1000).unwrap();
        assert!(o.rotated_away);
        assert_eq!((o.offset, o.oldest, o.total), (100, 100, 250));
        assert_eq!(o.data, &data[100..250]);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn pump_keeps_at_most_two_files_per_stream() {
        let (d, s, mut w) = pump_with(64, "two");
        w.write_all(&bytes(0..1000)).unwrap();
        drop(w);
        assert!(wait_pumps(&[&s], Duration::from_secs(2)));
        let names: Vec<String> = fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(names.iter().any(|n| n.ends_with("-e1.stdout")));
        assert!(names.iter().any(|n| n.ends_with("-e1.stdout.1")));
        let c = s.counts();
        assert!(c.total - c.base <= 128, "{c:?}");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn read_offset_across_rotation() {
        let (d, s, mut w) = pump_with(100, "across");
        let data = bytes(0..230);
        w.write_all(&data).unwrap();
        drop(w);
        assert!(wait_pumps(&[&s], Duration::from_secs(2)));
        // [100,200) previous, [200,230) current; a read spanning both is
        // stitched with no gap and no duplicate.
        let o = s.read(150, 60).unwrap();
        assert!(!o.rotated_away);
        assert_eq!(o.data, &data[150..210]);
        assert_eq!((o.offset, o.next), (150, 210));
        // Chunked reads from the oldest offset reassemble the kept tail.
        let mut got = Vec::new();
        let mut off = 0;
        loop {
            let o = s.read(off, 37).unwrap();
            if o.data.is_empty() {
                break;
            }
            got.extend_from_slice(&o.data);
            off = o.next;
        }
        assert_eq!(got, &data[100..230]);
        // The same layout is rebuilt from the files and the state's base.
        let p = exec_file(&d, "i", 1, "stdout");
        let l = layout_from_files(&p, 100).unwrap();
        assert_eq!((l.prev_base, l.cur_base, l.total), (100, 200, 230));
        let o = read_layout(&l, 150, 60).unwrap();
        assert_eq!(o.data, &data[150..210]);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn read_rotated_away_sets_flag_and_returns_oldest() {
        let (d, s, mut w) = pump_with(50, "away");
        let data = bytes(0..180);
        w.write_all(&data).unwrap();
        drop(w);
        assert!(wait_pumps(&[&s], Duration::from_secs(2)));
        let c = s.counts();
        assert_eq!(c.base, 100);
        let o = s.read(10, 1000).unwrap();
        assert!(o.rotated_away);
        assert_eq!((o.offset, o.oldest), (100, 100));
        assert_eq!(o.data, &data[100..]);
        // Continuing from `next` has no gap and no duplicate, and no flag.
        let o2 = s.read(o.next, 10).unwrap();
        assert!(o2.data.is_empty() && !o2.rotated_away);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn read_past_total_is_empty_not_eof_while_running() {
        let (d, s, mut w) = pump_with(100, "past");
        w.write_all(b"abc").unwrap();
        w.flush().unwrap();
        for _ in 0..200 {
            if s.total.load(Ordering::SeqCst) == 3 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let o = s.read(3, 10).unwrap();
        assert!(o.data.is_empty());
        assert_eq!((o.next, o.total), (3, 3));
        // The pump has not seen EOF (the write end is open): not eof.
        assert!(!output_eof(
            true,
            s.eof.load(Ordering::SeqCst),
            o.next,
            o.total
        ));
        drop(w);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn eof_requires_pump_eof_and_final_state() {
        assert!(output_eof(true, true, 10, 10));
        assert!(!output_eof(false, true, 10, 10), "exec still running");
        assert!(!output_eof(true, false, 10, 10), "pump still open");
        assert!(!output_eof(true, true, 9, 10), "not at the end yet");
        assert!(output_eof(true, true, 0, 0), "empty finished stream");
    }

    #[test]
    fn pump_keeps_draining_on_write_error() {
        // The file refuses every write (/dev/full): the pump still empties
        // the pipe, so a writer larger than the pipe buffer never blocks,
        // nothing is counted, and EOF is reached.
        let d = tmp("full");
        let (r, w) = pipe().unwrap();
        let full = fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap();
        let s = Arc::new(Stream::new(&d.join("x"), 0));
        pump_into(r, full, &s).unwrap();
        let mut w = fs::File::from(w);
        w.write_all(&vec![7u8; 300_000]).unwrap();
        drop(w);
        assert!(wait_pumps(&[&s], Duration::from_secs(5)));
        assert_eq!(s.total.load(Ordering::SeqCst), 0);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn rotation_callback_runs_outside_the_lock() {
        let (d, s, mut w) = pump_with(10, "cb");
        let s2 = Arc::clone(&s);
        let seen = Arc::new(Mutex::new(Vec::<u64>::new()));
        let seen2 = Arc::clone(&seen);
        // The callback reads `counts()`, which takes the stream lock: it
        // would deadlock if the pump held it.
        s.set_on_rotate(Arc::new(move || {
            seen2.lock().unwrap().push(s2.counts().base);
        }));
        w.write_all(&bytes(0..35)).unwrap();
        drop(w);
        assert!(wait_pumps(&[&s], Duration::from_secs(2)));
        let seen = seen.lock().unwrap().clone();
        assert!(!seen.is_empty());
        assert_eq!(s.counts().base, 20);
        fs::remove_dir_all(&d).unwrap();
    }

    fn write_finished(dir: &Path, inc: &str, id: u64, ended: &str) {
        let mut st = state(id);
        st.incarnation = inc.into();
        st.state = "exited".into();
        st.exit_code = Some(0);
        st.ended = Some(ended.into());
        write_state(&exec_file(dir, inc, id, "state.json"), &st).unwrap();
        for k in ["stdout", "stdout.1", "stderr"] {
            fs::write(exec_file(dir, inc, id, k), b"x").unwrap();
        }
    }

    fn count_state_files(dir: &Path) -> usize {
        fs::read_dir(dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".state.json")
            })
            .count()
    }

    #[test]
    fn prune_removes_logs_older_than_oldest_journal_record() {
        let d = tmp("prune-age");
        write_finished(&d, "I0", 1, "2026-11-01T00:00:00Z");
        write_finished(&d, "I0", 2, "2026-11-20T00:00:00Z");
        let n = prune(&d, "I1", Some("2026-11-10T00:00:00Z"), 256);
        assert_eq!(n, 1);
        assert!(!exec_file(&d, "I0", 1, "state.json").exists());
        assert!(!exec_file(&d, "I0", 1, "stdout.1").exists(), "all kinds go");
        assert!(exec_file(&d, "I0", 2, "state.json").exists());
        assert!(exec_file(&d, "I0", 2, "stdout").exists());
        // No age rule (empty journal): only the cap applies, nothing here.
        assert_eq!(prune(&d, "I1", None, 256), 0);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn prune_never_touches_running_exec() {
        let d = tmp("prune-run");
        let mut st = state(1);
        st.incarnation = "I1".into();
        st.started = "2020-01-01T00:00:00Z".into(); // ancient
        write_state(&exec_file(&d, "I1", 1, "state.json"), &st).unwrap();
        fs::write(exec_file(&d, "I1", 1, "stdout"), b"x").unwrap();
        // Live incarnation, running: untouched by age and by the cap alike.
        assert_eq!(prune(&d, "I1", Some("2026-11-10T00:00:00Z"), 0), 0);
        assert!(exec_file(&d, "I1", 1, "state.json").exists());
        assert!(exec_file(&d, "I1", 1, "stdout").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn prune_leaves_running_state_of_live_foreign_pid() {
        let d = tmp("prune-foreign");
        let me = std::process::id() as i32;
        let old = "2020-01-01T00:00:00Z";
        // 1: another incarnation, writer alive (this process): left alone.
        let mut a = state(1);
        a.incarnation = "I0".into();
        a.started = old.into();
        a.supervisor_pid = Some(me);
        a.supervisor_start = Some(crate::sys::stat_starttime(me).unwrap());
        write_state(&exec_file(&d, "I0", 1, "state.json"), &a).unwrap();
        // 2: writer's pid is alive but its start time differs (pid reuse): lost.
        let mut b = state(2);
        b.incarnation = "I0".into();
        b.started = old.into();
        b.supervisor_pid = Some(me);
        b.supervisor_start = Some(1);
        write_state(&exec_file(&d, "I0", 2, "state.json"), &b).unwrap();
        // 3: writer dead: lost.
        let mut c = state(3);
        c.incarnation = "I0".into();
        c.started = old.into();
        c.supervisor_pid = Some(i32::MAX);
        c.supervisor_start = Some(5);
        write_state(&exec_file(&d, "I0", 3, "state.json"), &c).unwrap();
        // 4: no writer identity (older build): unknowable, left alone.
        let mut e = state(4);
        e.incarnation = "I0".into();
        e.started = old.into();
        write_state(&exec_file(&d, "I0", 4, "state.json"), &e).unwrap();
        let n = prune(&d, "I1", Some("2026-11-10T00:00:00Z"), 256);
        assert_eq!(n, 2);
        assert!(exec_file(&d, "I0", 1, "state.json").exists());
        assert!(!exec_file(&d, "I0", 2, "state.json").exists());
        assert!(!exec_file(&d, "I0", 3, "state.json").exists());
        assert!(exec_file(&d, "I0", 4, "state.json").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn prune_skips_finished_with_output_open_and_live_writer() {
        // 0.6.5: a finished state with output_open=true and a positively live
        // writer (live incarnation) is skipped and does NOT count against the
        // cap: with max_finished=0 it must still survive.
        let d = tmp("prune-open-live");
        write_finished(&d, "I1", 1, "2026-11-01T00:00:00Z"); // output_open=true by default
        assert_eq!(prune(&d, "I1", Some("2026-11-10T00:00:00Z"), 0), 0);
        assert!(exec_file(&d, "I1", 1, "state.json").exists());
        assert!(exec_file(&d, "I1", 1, "stdout").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn prune_skips_finished_with_output_open_and_live_foreign_pid() {
        // 0.6.5: foreign incarnation, writer positively alive (this process)
        // with output_open=true: skipped.
        let d = tmp("prune-open-foreign-live");
        let me = std::process::id() as i32;
        write_finished(&d, "I0", 1, "2026-11-01T00:00:00Z");
        let p = exec_file(&d, "I0", 1, "state.json");
        let mut st = read_state(&p).unwrap();
        st.supervisor_pid = Some(me);
        st.supervisor_start = Some(crate::sys::stat_starttime(me).unwrap());
        write_state(&p, &st).unwrap();
        assert_eq!(prune(&d, "I1", Some("2026-11-10T00:00:00Z"), 256), 0);
        assert!(exec_file(&d, "I0", 1, "state.json").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn prune_collects_finished_with_output_open_and_no_identity() {
        // 0.6.5: output_open=true but NO writer identity (old build that
        // never maintained the flag): stays collectible, as before.
        let d = tmp("prune-open-noid");
        write_finished(&d, "I0", 1, "2026-11-01T00:00:00Z");
        // write_finished leaves supervisor_pid None
        assert_eq!(prune(&d, "I1", Some("2026-11-10T00:00:00Z"), 256), 1);
        assert!(!exec_file(&d, "I0", 1, "state.json").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn prune_collects_finished_with_output_open_and_gone_writer() {
        // 0.6.5: a finished state with output_open=true but a gone writer
        // (foreign incarnation, dead supervisor) is prunable: dead pumps.
        let d = tmp("prune-open-gone");
        write_finished(&d, "I0", 1, "2026-11-01T00:00:00Z");
        // give it a writer identity that is gone
        let p = exec_file(&d, "I0", 1, "state.json");
        let mut st = read_state(&p).unwrap();
        st.supervisor_pid = Some(i32::MAX);
        st.supervisor_start = Some(5);
        write_state(&p, &st).unwrap();
        assert_eq!(prune(&d, "I1", Some("2026-11-10T00:00:00Z"), 256), 1);
        assert!(!exec_file(&d, "I0", 1, "state.json").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn prune_collects_finished_with_output_closed() {
        // 0.6.5: output_open=false (pumps done) is prunable even live.
        let d = tmp("prune-closed");
        write_finished(&d, "I1", 1, "2026-11-01T00:00:00Z");
        let p = exec_file(&d, "I1", 1, "state.json");
        let mut st = read_state(&p).unwrap();
        st.output_open = false;
        write_state(&p, &st).unwrap();
        assert_eq!(prune(&d, "I1", Some("2026-11-10T00:00:00Z"), 256), 1);
        assert!(!exec_file(&d, "I1", 1, "state.json").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn prune_caps_finished_execs_at_256() {
        let d = tmp("prune-cap");
        for id in 1..=260u64 {
            write_finished(
                &d,
                "I0",
                id,
                &format!("2026-11-21T00:{:02}:{:02}Z", id / 60, id % 60),
            );
        }
        assert_eq!(prune(&d, "I1", None, MAX_FINISHED), 4);
        assert_eq!(count_state_files(&d), 256);
        // The four oldest went.
        for id in 1..=4u64 {
            assert!(!exec_file(&d, "I0", id, "state.json").exists(), "{id}");
        }
        assert!(exec_file(&d, "I0", 5, "state.json").exists());
        assert!(exec_file(&d, "I0", 260, "state.json").exists());
        fs::remove_dir_all(&d).unwrap();
    }
}
