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
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
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

/// Live counters of one output stream, shared with its pump thread.
#[derive(Debug, Default)]
pub struct Stream {
    /// Bytes appended to the stream file so far.
    pub total: AtomicU64,
    /// The pump saw EOF on the pipe (every writer closed it).
    pub eof: AtomicBool,
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
/// appends to a new `0600` file at `path`. A write error (ENOSPC, ...) keeps
/// draining and discards, so the program never blocks on a full pipe (B10).
pub fn start_pump(read: OwnedFd, path: &Path) -> io::Result<Arc<Stream>> {
    let mut file = fs::OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    let stream = Arc::new(Stream::default());
    let s = Arc::clone(&stream);
    std::thread::Builder::new()
        .name("exec-pump".into())
        .spawn(move || {
            let mut src = fs::File::from(read);
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match src.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if file.write_all(&buf[..n]).is_ok() {
                            s.total.fetch_add(n as u64, Ordering::SeqCst);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            s.eof.store(true, Ordering::SeqCst);
        })?;
    Ok(stream)
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
        Arc::new(DetachedExec {
            exec_id: id,
            seat: None,
            argv0: "sleep".into(),
            pid: 10 + id as i32,
            started: "t".into(),
            stdout: Arc::default(),
            stderr: Arc::default(),
            signalled: AtomicBool::new(false),
        })
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
}
