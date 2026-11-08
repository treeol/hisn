//! Session directory, ids, audit log, and session discovery (DESIGN §9).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::policy::is_valid_session_id;
use crate::sys;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("invalid session id {0:?} (allowed: [A-Za-z0-9._-]{{1,64}})")]
    BadId(String),
    #[error("session {0} already exists")]
    Exists(String),
    #[error("no such session {0}")]
    NotFound(String),
    #[error("{path}: {reason}")]
    Unsafe { path: PathBuf, reason: String },
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Candidate runtime roots, in preference order. Every candidate is
/// off-limits to mounts and grants (R1) even if it is not the one in use.
pub fn runtime_roots(xdg_runtime_dir: Option<&str>, uid: u32) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(x) = xdg_runtime_dir.filter(|x| x.starts_with('/')) {
        v.push(Path::new(x).join("hisn"));
    }
    v.push(PathBuf::from(format!("/tmp/hisn-{uid}")));
    v
}

/// Pick the root in use: the first whose parent directory exists.
pub fn pick_root(roots: &[PathBuf]) -> PathBuf {
    roots
        .iter()
        .find(|r| r.parent().is_some_and(Path::is_dir))
        .cloned()
        .unwrap_or_else(|| roots.last().cloned().expect("at least one root"))
}

/// Label for the local client: the login name, or "local" if none resolves.
pub fn local_label() -> String {
    std::env::var("USER")
        .ok()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| "local".into())
}

pub fn random_id() -> io::Result<String> {
    use std::io::Read;
    let mut b = [0u8; 6];
    File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Create (or verify) the runtime root: a real directory owned by `uid`,
/// mode 0700, not a symlink.
pub fn ensure_root(root: &Path, uid: u32) -> Result<(), SessionError> {
    match fs::DirBuilder::new().mode(0o700).create(root) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let md = fs::symlink_metadata(root)?;
    let unsafe_ = |reason: &str| SessionError::Unsafe {
        path: root.into(),
        reason: reason.into(),
    };
    if !md.file_type().is_dir() {
        return Err(unsafe_("not a real directory (symlink?)"));
    }
    if md.uid() != uid {
        return Err(unsafe_("not owned by the current user"));
    }
    if md.mode() & 0o077 != 0 {
        return Err(unsafe_("must be mode 0700"));
    }
    Ok(())
}

pub struct SessionDir {
    pub id: String,
    pub path: PathBuf,
}

impl SessionDir {
    /// `mkdir <root>/<id>` with mode 0700; fails if it already exists.
    pub fn create(root: &Path, uid: u32, id: &str) -> Result<Self, SessionError> {
        if !is_valid_session_id(id) {
            return Err(SessionError::BadId(id.into()));
        }
        ensure_root(root, uid)?;
        let path = root.join(id);
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(SessionError::Exists(id.into()));
            }
            Err(e) => return Err(e.into()),
        }
        Ok(Self {
            id: id.into(),
            path,
        })
    }

    /// Create `<root>/.tmp-<id>` (0700). The session is not visible to
    /// `find_session`/`list_sessions` until `publish` renames it to `<id>`.
    pub fn create_tmp(root: &Path, uid: u32, id: &str) -> Result<Self, SessionError> {
        if !is_valid_session_id(id) {
            return Err(SessionError::BadId(id.into()));
        }
        ensure_root(root, uid)?;
        let path = root.join(format!(".tmp-{id}"));
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(SessionError::Exists(id.into()));
            }
            Err(e) => return Err(e.into()),
        }
        Ok(Self {
            id: id.into(),
            path,
        })
    }

    /// Atomically publish a `.tmp-<id>` directory as `<id>`. Fails if the
    /// final name already exists (never replaces a live session).
    pub fn publish(self, root: &Path) -> Result<Self, SessionError> {
        let final_path = root.join(&self.id);
        if fs::symlink_metadata(&final_path).is_ok() {
            return Err(SessionError::Exists(self.id.clone()));
        }
        fs::rename(&self.path, &final_path)?;
        Ok(Self {
            id: self.id.clone(),
            path: final_path,
        })
    }

    pub fn socket_path(&self) -> PathBuf {
        self.path.join("control.sock")
    }

    pub fn audit_path(&self) -> PathBuf {
        self.path.join("grants.jsonl")
    }

    pub fn pid_path(&self) -> PathBuf {
        self.path.join("supervisor.pid")
    }

    /// Write `supervisor.pid` with the pid and starttime so stale-detection
    /// can confirm the supervisor is the same process (not a reused pid).
    pub fn write_supervisor_pid(&self, pid: i32) -> io::Result<()> {
        let starttime = sys::stat_starttime(pid)?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.pid_path())?;
        writeln!(f, "{pid} {starttime}")?;
        Ok(())
    }

    pub fn write_resolved_policy(&self, toml: &str) -> io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.path.join("policy.resolved.toml"))?;
        f.write_all(toml.as_bytes())
    }

    /// Remove the directory. Idempotent; the audit log goes with it (it is a
    /// per-session record, kept only while the session lives).
    pub fn remove(&self) {
        let _ = fs::remove_dir_all(&self.path);
    }

    /// Read the resolved policy TOML from the session dir, if present.
    /// Returns `None` if the file does not exist (e.g. a stale or 0.2.0 dir).
    pub fn read_resolved_policy(&self) -> Option<String> {
        fs::read_to_string(self.path.join("policy.resolved.toml")).ok()
    }
}

/// Resolve `--session ID` to its directory under any candidate root.
pub fn find_session(roots: &[PathBuf], id: &str) -> Result<PathBuf, SessionError> {
    if !is_valid_session_id(id) {
        return Err(SessionError::BadId(id.into()));
    }
    roots
        .iter()
        .map(|r| r.join(id))
        .find(|p| p.is_dir())
        .ok_or_else(|| SessionError::NotFound(id.into()))
}

/// Resolve a `--session` argument (an id or a name) to a session id.
///
/// An argument that is an existing id under some root resolves to itself,
/// so id-based scripts keep working. Otherwise it is looked up as a name in
/// the per-user registry (authoritative index; scan of the name files when
/// the index is missing or unparseable). Returns `NotFound` if neither.
pub fn resolve_session_arg(
    roots: &[PathBuf],
    reg_root: &Path,
    arg: &str,
) -> Result<String, SessionError> {
    if !is_valid_session_id(arg) {
        // Not a valid id (e.g. a leading '.' or too long): must be a name.
        return crate::registry::resolve_name(reg_root, roots, arg)
            .ok_or_else(|| SessionError::NotFound(arg.into()));
    }
    if roots.iter().any(|r| r.join(arg).is_dir()) {
        return Ok(arg.into());
    }
    crate::registry::resolve_name(reg_root, roots, arg)
        .filter(|id| roots.iter().any(|r| r.join(id).is_dir()))
        .ok_or_else(|| SessionError::NotFound(arg.into()))
}

/// Session ids present under any root.
pub fn list_sessions(roots: &[PathBuf]) -> Vec<(String, PathBuf)> {
    let mut v = Vec::new();
    for r in roots {
        let Ok(rd) = fs::read_dir(r) else { continue };
        for e in rd.flatten() {
            if e.path().is_dir()
                && let Some(n) = e.file_name().to_str()
                && is_valid_session_id(n)
            {
                v.push((n.to_owned(), e.path()));
            }
        }
    }
    v.sort();
    v
}

/// Append-only audit log (`O_APPEND`, 0600).
pub struct Audit {
    file: File,
}

impl Audit {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)?;
        Ok(Self { file })
    }

    /// One JSON object per line; a single `write` so lines never interleave.
    pub fn log(&self, entry: Value) -> io::Result<()> {
        let mut line = entry.to_string();
        line.push('\n');
        (&self.file).write_all(line.as_bytes())
    }

    pub fn entry(
        op: &str,
        stage: &str,
        path: Option<&str>,
        mode: Option<&str>,
        result: Option<&str>,
        peer: Option<i32>,
    ) -> Value {
        json!({
            "ts": rfc3339_now(),
            "op": op,
            "stage": stage,
            "path": path,
            "mode": mode,
            "result": result,
            "pid_peer": peer,
        })
    }
}

/// RFC 3339 UTC timestamp without a time crate (civil-from-days algorithm).
pub fn rfc3339_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    rfc3339(secs)
}

pub fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Parse `YYYY-MM-DDTHH:MM:SSZ` (the form `rfc3339_now` writes) to epoch
/// seconds. Returns `None` on any parse failure. Inverse of [`rfc3339`].
pub fn parse_rfc3339_secs(ts: &str) -> Option<i64> {
    let b = ts.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[10] != b'T' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| ts.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let (h, mi, se) = (n(11..13)?, n(14..16)?, n(17..19)?);
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + se)
}

/// Is `path` a socket we can connect to (a live supervisor)?
pub fn is_live(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path.join("control.sock")).is_ok()
}

/// 0.4.1 step 2: wait until a session's control socket accepts a connection.
/// Readiness is defined as *the socket accepts* — the same condition
/// `is_live`/`is_stale` use. Polling uses an exponential backoff that starts
/// at 1 ms and is capped at 20 ms, so a session that is already up costs one
/// ~1 ms probe and a slow-starting one is re-probed every 20 ms at worst.
/// There is deliberately no fixed 100 ms sleep: a session that becomes ready
/// in 6 ms is observed in ~7 ms, not ~100 ms.
///
/// `ENOENT` (socket not created yet) and `ECONNREFUSED` (bound but the accept
/// loop has not started) both mean "not ready yet". The probe is a
/// **nonblocking** connect, so a listener whose backlog is full (a stalled
/// accept loop) yields `EAGAIN` — "not ready" — instead of blocking the waiter
/// past its deadline. Any other connect error (`EACCES`, …) is a hard failure
/// and returns immediately.
pub fn wait_control_socket(
    socket: &Path,
    timeout: std::time::Duration,
) -> Result<(), SessionError> {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + timeout;
    let mut delay = Duration::from_millis(1);
    loop {
        match nonblocking_connect_ready(socket) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) => return Err(SessionError::Io(e)),
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(SessionError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "control socket {} not ready within {timeout:?}",
                    socket.display()
                ),
            )));
        }
        let remaining = deadline.saturating_duration_since(now);
        std::thread::sleep(delay.min(remaining));
        delay = (delay * 2).min(Duration::from_millis(20));
    }
}

/// A nonblocking `connect(2)` to a unix socket path. `Ok(true)` = connected,
/// `Ok(false)` = not ready yet (socket absent, refusing, or backlog full),
/// `Err` = a hard error that will not resolve by waiting.
fn nonblocking_connect_ready(socket: &Path) -> io::Result<bool> {
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    let bytes = socket.as_os_str().as_bytes();
    // sockaddr_un.sun_path is 108 bytes including a NUL.
    if bytes.len() >= 108 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path too long",
        ));
    }
    // SAFETY: socket() returns a fresh fd or -1; wrapped immediately.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor we own.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: zeroed sockaddr_un is a valid starting point; we fill it in.
    let mut addr: libc::sockaddr_un = unsafe { MaybeUninit::zeroed().assume_init() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (i, b) in bytes.iter().enumerate() {
        addr.sun_path[i] = *b as libc::c_char;
    }
    // SAFETY: connect() on our fd with a correctly-sized sockaddr_un.
    let r = unsafe {
        libc::connect(
            owned.as_raw_fd(),
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if r == 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        // Not ready yet: absent, refusing, or the backlog is full.
        Some(libc::ENOENT)
        | Some(libc::ECONNREFUSED)
        | Some(libc::EAGAIN)
        | Some(libc::EINPROGRESS)
        | Some(libc::EALREADY)
        | Some(libc::EINTR) => Ok(false),
        _ => Err(e),
    }
}

/// Read `supervisor.pid` as `(pid, starttime)`. `None` if missing or malformed.
pub fn read_supervisor_pid(path: &Path) -> Option<(i32, u64)> {
    let s = fs::read_to_string(path.join("supervisor.pid")).ok()?;
    let (pid_str, start_str) = s.trim().split_once(' ')?;
    let pid: i32 = pid_str.parse().ok()?;
    let start: u64 = start_str.parse().ok()?;
    (pid > 0 && start > 0).then_some((pid, start))
}

/// Is a session directory stale? `stale` = the socket refuses **and** the
/// supervisor pid is gone or has a different starttime. Socket errors other
/// than `ECONNREFUSED`/`ENOENT` mean **not stale** (a busy live session must
/// never be classified stale). A missing or malformed `supervisor.pid` means
/// **not stale** (fail safe — a 0.2.0 dir or a 0.2.1 session mid-start).
pub fn is_stale(path: &Path) -> bool {
    match socket_refuses(path) {
        true => {}
        false => return false,
    }
    let pid_file = match fs::read_to_string(path.join("supervisor.pid")) {
        Ok(s) => s,
        Err(_) => return false, // missing → not stale
    };
    let (pid_str, start_str) = match pid_file.trim().split_once(' ') {
        Some((a, b)) => (a, b),
        None => return false, // malformed → not stale
    };
    let pid: i32 = match pid_str.parse() {
        Ok(p) if p > 0 => p, // only positive pids are valid supervisor ids
        _ => return false,   // non-positive or unparseable → not stale
    };
    let recorded_start: u64 = match start_str.parse() {
        Ok(s) if s > 0 => s, // starttime must be positive
        _ => return false,
    };
    // pid not alive → stale; alive with mismatched starttime → stale.
    match sys::kill(pid, 0) {
        Ok(()) => match sys::stat_starttime(pid) {
            Ok(st) => st != recorded_start,
            Err(_) => false, // cannot read stat — alive but unknown → not stale
        },
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => true,
        Err(_) => false, // EPERM etc → alive, not stale
    }
}

/// Does the control socket refuse? Only `ECONNREFUSED`/`ENOENT` counts;
/// a timeout or backlog-full means **not stale** (live and busy).
fn socket_refuses(path: &Path) -> bool {
    match UnixStream::connect(path.join("control.sock")) {
        Ok(_) => false, // connected → live
        Err(e) => matches!(
            e.raw_os_error(),
            Some(libc::ECONNREFUSED) | Some(libc::ENOENT)
        ),
    }
}

/// Remove a session directory **safely**: only the given directory, owner-
/// checked, never following a symlink and never crossing a mount boundary.
///
/// The traversal is fd-relative: every directory is opened with
/// `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV |
/// RESOLVE_BENEATH)` relative to its parent's fd, so a symlink swapped in
/// after a check cannot redirect it, and a bind mount planted inside (same
/// device or not) makes the open fail with `EXDEV` instead of being entered.
/// A **symlink entry is unlinked, not followed and not refused**: `unlinkat`
/// never dereferences its final component, so removing the link cannot touch
/// its target. An entry not owned by `uid`, or a mount boundary, is refused
/// (`Err`), possibly after earlier entries were already removed (P24).
pub fn remove_safe(path: &Path, uid: u32) -> Result<(), String> {
    let name = path
        .file_name()
        .ok_or_else(|| "session path has no final component".to_owned())?;
    let parent = path
        .parent()
        .ok_or_else(|| "session path has no parent".to_owned())?;
    let parent_fd = File::open(parent).map_err(|e| format!("open {parent:?}: {e}"))?;
    // The session dir itself must be a real directory (not a symlink to one).
    let top = open_child_dir(parent_fd.as_raw_fd(), name)
        .map_err(|e| format!("open session dir {path:?}: {e}"))?;
    let st = rustix::fs::fstat(&top).map_err(|e| format!("fstat session dir: {e}"))?;
    if st.st_uid != uid {
        return Err(format!("session dir not owned by uid {uid}"));
    }
    remove_contents(&top, uid, 0)?;
    drop(top);
    let c = sys::cstr(Path::new(name)).map_err(|e| e.to_string())?;
    rustix::fs::unlinkat(&parent_fd, c.as_c_str(), rustix::fs::AtFlags::REMOVEDIR)
        .map_err(|e| format!("remove session dir: {e}"))
}

const REMOVE_MAX_DEPTH: usize = 64;

fn open_child_dir(dirfd: RawFd, name: &std::ffi::OsStr) -> io::Result<OwnedFd> {
    let c = sys::cstr(Path::new(name))?;
    sys::openat2(
        dirfd,
        &c,
        (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
        0,
        sys::RESOLVE_NO_SYMLINKS
            | sys::RESOLVE_NO_MAGICLINKS
            | sys::RESOLVE_NO_XDEV
            | sys::RESOLVE_BENEATH,
    )
}

fn remove_contents(dir: &OwnedFd, uid: u32, depth: usize) -> Result<(), String> {
    use rustix::fs::{AtFlags, FileType, statat, unlinkat};
    if depth > REMOVE_MAX_DEPTH {
        return Err("directory tree too deep".into());
    }
    // Collect the names first: unlinking while iterating a Dir is unspecified.
    let mut names = Vec::new();
    let rd = rustix::fs::Dir::read_from(dir).map_err(|e| format!("read_dir: {e}"))?;
    for ent in rd {
        let ent = ent.map_err(|e| format!("read entry: {e}"))?;
        let n = ent.file_name();
        if n.to_bytes() == b"." || n.to_bytes() == b".." {
            continue;
        }
        names.push(n.to_owned());
    }
    for n in names {
        let os = std::ffi::OsStr::from_bytes(n.to_bytes());
        let st = statat(dir, n.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| format!("stat {os:?}: {e}"))?;
        if st.st_uid != uid {
            return Err(format!("{os:?}: not owned by uid {uid}"));
        }
        if FileType::from_raw_mode(st.st_mode) == FileType::Directory {
            let child = open_child_dir(dir.as_raw_fd(), os)
                .map_err(|e| format!("open {os:?} (symlink or mount boundary?): {e}"))?;
            // The opened object must be the one we stat'ed (no swap in between).
            let cst = rustix::fs::fstat(&child).map_err(|e| format!("fstat {os:?}: {e}"))?;
            if cst.st_ino != st.st_ino || cst.st_dev != st.st_dev {
                return Err(format!("{os:?}: changed during removal"));
            }
            remove_contents(&child, uid, depth + 1)?;
            drop(child);
            unlinkat(dir, n.as_c_str(), AtFlags::REMOVEDIR)
                .map_err(|e| format!("remove_dir {os:?}: {e}"))?;
        } else {
            // Regular file, socket, fifo, or a symlink: unlink the entry
            // itself. unlinkat does not dereference the final component.
            unlinkat(dir, n.as_c_str(), AtFlags::empty())
                .map_err(|e| format!("unlink {os:?}: {e}"))?;
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn mode_of(p: &Path) -> io::Result<u32> {
    Ok(fs::metadata(p)?.permissions().mode() & 0o7777)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid() -> u32 {
        rustix::process::getuid().as_raw()
    }

    #[test]
    fn roots_prefer_xdg_and_include_fallback() {
        let r = runtime_roots(Some("/run/user/1000"), 1000);
        assert_eq!(
            r,
            vec![
                PathBuf::from("/run/user/1000/hisn"),
                PathBuf::from("/tmp/hisn-1000")
            ]
        );
        assert_eq!(runtime_roots(None, 7), vec![PathBuf::from("/tmp/hisn-7")]);
        assert_eq!(
            runtime_roots(Some("relative"), 7),
            vec![PathBuf::from("/tmp/hisn-7")]
        );
    }

    #[test]
    fn create_enforces_modes_and_uniqueness() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("hisn");
        let s = SessionDir::create(&root, uid(), "abc-1").unwrap();
        assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&s.path).unwrap().mode() & 0o777, 0o700);
        assert!(matches!(
            SessionDir::create(&root, uid(), "abc-1"),
            Err(SessionError::Exists(_))
        ));
        for bad in ["", "..", "a/b", "x y", &"a".repeat(65)] {
            assert!(
                matches!(
                    SessionDir::create(&root, uid(), bad),
                    Err(SessionError::BadId(_))
                ),
                "{bad:?}"
            );
        }
        s.remove();
        assert!(!s.path.exists());
        s.remove(); // idempotent
    }

    #[test]
    fn unsafe_roots_are_refused() {
        let d = tempfile::tempdir().unwrap();
        // symlink root
        let real = d.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(matches!(
            ensure_root(&link, uid()),
            Err(SessionError::Unsafe { .. })
        ));
        // wrong mode
        let loose = d.path().join("loose");
        fs::create_dir(&loose).unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            ensure_root(&loose, uid()),
            Err(SessionError::Unsafe { .. })
        ));
        // wrong owner
        assert!(matches!(
            ensure_root(&real, uid() + 1),
            Err(SessionError::Unsafe { .. })
        ));
    }

    #[test]
    fn find_and_list() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("hisn");
        SessionDir::create(&root, uid(), "b").unwrap();
        SessionDir::create(&root, uid(), "a").unwrap();
        let roots = vec![root.clone()];
        assert_eq!(find_session(&roots, "a").unwrap(), root.join("a"));
        assert!(matches!(
            find_session(&roots, "zz"),
            Err(SessionError::NotFound(_))
        ));
        assert!(matches!(
            find_session(&roots, "../x"),
            Err(SessionError::BadId(_))
        ));
        let names: Vec<_> = list_sessions(&roots).into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["a", "b"]);
        assert!(!is_live(&root.join("a")));
    }

    #[test]
    fn audit_is_append_only_jsonl_with_private_mode() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("grants.jsonl");
        let a = Audit::open(&p).unwrap();
        a.log(Audit::entry(
            "grant",
            "request",
            Some("/x"),
            Some("ro"),
            None,
            Some(5),
        ))
        .unwrap();
        a.log(Audit::entry(
            "grant",
            "result",
            Some("/x"),
            Some("ro"),
            Some("ok"),
            None,
        ))
        .unwrap();
        drop(a);
        // reopening appends, never truncates
        Audit::open(&p).unwrap().log(json!({"op":"x"})).unwrap();
        let text = fs::read_to_string(&p).unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0]["stage"], "request");
        assert_eq!(lines[1]["result"], "ok");
        assert_eq!(fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
    }

    #[test]
    fn timestamps() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_782_864_010), "2026-07-01T00:00:10Z");
        assert!(rfc3339_now().ends_with('Z'));
    }

    #[test]
    fn random_ids_are_valid_and_distinct() {
        let (a, b) = (random_id().unwrap(), random_id().unwrap());
        assert!(is_valid_session_id(&a) && a.len() == 12);
        assert_ne!(a, b);
    }

    #[test]
    fn resolved_policy_is_written_once_privately() {
        let d = tempfile::tempdir().unwrap();
        let s = SessionDir::create(&d.path().join("h"), uid(), "p").unwrap();
        s.write_resolved_policy("x = 1\n").unwrap();
        assert!(s.write_resolved_policy("y = 2\n").is_err());
        assert_eq!(
            fs::metadata(s.path.join("policy.resolved.toml"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn supervisor_pid_is_written_once_privately() {
        let d = tempfile::tempdir().unwrap();
        let s = SessionDir::create(&d.path().join("h"), uid(), "p").unwrap();
        // Use our own pid so stat_starttime succeeds.
        let my_pid = std::process::id() as i32;
        s.write_supervisor_pid(my_pid).unwrap();
        let text = fs::read_to_string(s.pid_path()).unwrap();
        assert!(text.trim().starts_with(&format!("{my_pid} ")));
        // Second write fails (create_new).
        assert!(s.write_supervisor_pid(my_pid).is_err());
        assert_eq!(fs::metadata(s.pid_path()).unwrap().mode() & 0o777, 0o600);
    }

    /// Step 1b: a `.tmp-<id>` directory is never a session. It must not be
    /// listed or found, even though its name is a valid id shape.
    #[test]
    fn tmp_publication_dir_is_invisible_until_published() {
        let root = std::env::temp_dir().join(format!("hisn-pub-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&root).unwrap().uid();
        let tmp = SessionDir::create_tmp(&root, uid, "pubid").unwrap();
        assert!(tmp.path.ends_with(".tmp-pubid"));
        // Crash injection: the tmp dir exists, nothing is published.
        assert!(list_sessions(std::slice::from_ref(&root)).is_empty());
        assert!(find_session(std::slice::from_ref(&root), "pubid").is_err());
        // Publication makes it visible under the final id.
        let done = tmp.publish(&root).unwrap();
        assert!(done.path.ends_with("pubid"));
        assert_eq!(list_sessions(std::slice::from_ref(&root)).len(), 1);
        fs::remove_dir_all(&root).unwrap();
    }

    /// Publication never replaces a session already at the final name.
    #[test]
    fn publish_refuses_existing_final_name() {
        let root = std::env::temp_dir().join(format!("hisn-pub2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&root).unwrap().uid();
        fs::create_dir(root.join("taken")).unwrap();
        let tmp = SessionDir::create_tmp(&root, uid, "taken").unwrap();
        assert!(matches!(tmp.publish(&root), Err(SessionError::Exists(_))));
        fs::remove_dir_all(&root).unwrap();
    }

    /// A leading '.' is refused as a session id (reserved for `.tmp-`).
    #[test]
    fn dot_prefixed_ids_are_refused() {
        assert!(!is_valid_session_id(".tmp-x"));
        assert!(is_valid_session_id("ab12cd"));
    }

    /// Step 1c: an id resolves to itself; a name resolves through the index;
    /// an unknown name is NotFound.
    #[test]
    fn resolve_session_arg_accepts_id_or_name() {
        let base = std::env::temp_dir().join(format!("hisn-res-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let root = base.join("r");
        let reg = base.join("reg");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&reg).unwrap();
        fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        fs::set_permissions(&reg, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&root).unwrap().uid();
        let roots = vec![root.clone()];
        // Same order as `run`: reserve the name first, then publish the dir
        // that carries it. A name already on disk would count as taken.
        {
            let _l = crate::registry::Lock::take(&reg, uid).unwrap();
            crate::registry::reserve(&reg, &roots, "mysess", "sid42").unwrap();
        }
        let sd = SessionDir::create(&root, uid, "sid42").unwrap();
        crate::registry::write_name_file(&sd.path, "mysess").unwrap();
        assert_eq!(resolve_session_arg(&roots, &reg, "sid42").unwrap(), "sid42");
        assert_eq!(
            resolve_session_arg(&roots, &reg, "mysess").unwrap(),
            "sid42"
        );
        assert!(matches!(
            resolve_session_arg(&roots, &reg, "unknown"),
            Err(SessionError::NotFound(_))
        ));
        // Index points at a dir that is gone: NotFound, not a stale hit.
        fs::remove_dir_all(&sd.path).unwrap();
        assert!(matches!(
            resolve_session_arg(&roots, &reg, "mysess"),
            Err(SessionError::NotFound(_))
        ));
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn is_stale_false_for_missing_supervisor_pid() {
        // A 0.2.0 dir without supervisor.pid is not stale (fail safe).
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("hisn");
        let s = SessionDir::create(&root, uid(), "stale1").unwrap();
        // No supervisor.pid written — socket also doesn't exist → ENOENT
        // (refuses), but missing pid → not stale.
        assert!(!is_stale(&s.path));
    }

    #[test]
    fn is_stale_false_for_malformed_supervisor_pid() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("hisn");
        let s = SessionDir::create(&root, uid(), "stale2").unwrap();
        fs::write(s.pid_path(), "not-a-number\n").unwrap();
        // Socket doesn't exist → refuses, but malformed pid → not stale.
        assert!(!is_stale(&s.path));
    }

    #[test]
    fn is_stale_true_for_dead_supervisor() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("hisn");
        let s = SessionDir::create(&root, uid(), "stale3").unwrap();
        // Fork a child that sleeps briefly, write its pid + starttime while
        // it's alive, then wait for it. The socket won't exist
        // (ECONNREFUSED) and the pid is dead (ESRCH) → stale.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            std::process::exit(0);
        }
        let starttime = sys::stat_starttime(pid).expect("child starttime while alive");
        fs::write(s.pid_path(), format!("{pid} {starttime}")).unwrap();
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
        assert!(is_stale(&s.path));
    }

    #[test]
    fn remove_safe_removes_a_session_dir() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("hisn");
        let s = SessionDir::create(&root, uid(), "rm1").unwrap();
        fs::write(s.path.join("control.sock"), b"x").unwrap();
        fs::create_dir(s.path.join("sub")).unwrap();
        fs::write(s.path.join("sub/file"), b"x").unwrap();
        remove_safe(&s.path, uid()).unwrap();
        assert!(!s.path.exists());
    }

    #[test]
    fn remove_safe_unlinks_symlinks_without_following_them() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("hisn");
        let s = SessionDir::create(&root, uid(), "rm2").unwrap();
        let target = d.path().join("outside");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("canary"), b"keep").unwrap();
        // top-level dir link, file link, dangling link, and one nested.
        std::os::unix::fs::symlink(&target, s.path.join("link")).unwrap();
        std::os::unix::fs::symlink(target.join("canary"), s.path.join("flink")).unwrap();
        std::os::unix::fs::symlink("/nonexistent-hisn", s.path.join("dangling")).unwrap();
        fs::create_dir(s.path.join("sub")).unwrap();
        std::os::unix::fs::symlink(&target, s.path.join("sub/link")).unwrap();
        remove_safe(&s.path, uid()).unwrap();
        assert!(!s.path.exists(), "stale dir must be gone");
        assert_eq!(fs::read(target.join("canary")).unwrap(), b"keep");
    }

    #[test]
    fn remove_safe_refuses_a_symlinked_session_dir() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("canary"), b"keep").unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(remove_safe(&link, uid()).is_err());
        assert!(real.join("canary").exists());
    }

    #[test]
    fn remove_safe_refuses_wrong_owner() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("hisn");
        let s = SessionDir::create(&root, uid(), "rm3").unwrap();
        // Pass wrong uid — remove_safe should refuse.
        let wrong_uid = uid() + 1;
        let result = remove_safe(&s.path, wrong_uid);
        assert!(result.is_err());
    }
}
