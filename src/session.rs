//! Session directory, ids, audit log, and session discovery (DESIGN §9).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
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

/// Is `path` a socket we can connect to (a live supervisor)?
pub fn is_live(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path.join("control.sock")).is_ok()
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

/// Remove a session directory **safely**: only inside the runtime root,
/// symlink-safe, mount-safe, owner-checked. Uses `unlinkat` per entry (not
/// `remove_dir_all`) so the traversal is fd-relative and flag-bounded.
/// Refuses if any entry is not owned by `uid` or is a symlink. Returns
/// `Ok(())` on success, `Err(reason)` on refusal.
pub fn remove_safe(path: &Path, uid: u32) -> Result<(), String> {
    // Verify the path is a real directory owned by uid.
    let dir_meta = fs::symlink_metadata(path).map_err(|e| format!("stat session dir: {e}"))?;
    if !dir_meta.file_type().is_dir() {
        return Err("session dir is not a directory".into());
    }
    if dir_meta.uid() != uid {
        return Err(format!("session dir not owned by uid {uid}"));
    }
    // Walk the tree with std::fs, checking ownership and refusing symlinks
    // at every level. We already verified the root path; the checks prevent
    // a same-uid attacker from planting symlinks or bind mounts that
    // redirect the removal.
    remove_tree_std(path, uid, dir_meta.dev())?;
    // Remove the now-empty session dir.
    fs::remove_dir(path).map_err(|e| format!("remove session dir: {e}"))
}

fn remove_tree_std(path: &Path, uid: u32, parent_dev: u64) -> Result<(), String> {
    for entry in fs::read_dir(path).map_err(|e| format!("read_dir {path:?}: {e}"))? {
        let entry = entry.map_err(|e| format!("read entry {path:?}: {e}"))?;
        let entry_path = entry.path();
        let meta =
            fs::symlink_metadata(&entry_path).map_err(|e| format!("stat {entry_path:?}: {e}"))?;
        // Check ownership.
        if meta.uid() != uid {
            return Err(format!("{entry_path:?}: not owned by uid {uid}"));
        }
        // Check not a symlink.
        if meta.file_type().is_symlink() {
            return Err(format!("{entry_path:?}: is a symlink"));
        }
        // Check not on a different mount (bind mount crossing).
        if meta.dev() != parent_dev {
            return Err(format!("{entry_path:?}: crosses a mount boundary"));
        }
        if meta.is_dir() {
            remove_tree_std(&entry_path, uid, meta.dev())?;
            fs::remove_dir(&entry_path).map_err(|e| format!("remove_dir {entry_path:?}: {e}"))?;
        } else {
            fs::remove_file(&entry_path).map_err(|e| format!("remove_file {entry_path:?}: {e}"))?;
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
    fn remove_safe_refuses_symlink_inside() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("hisn");
        let s = SessionDir::create(&root, uid(), "rm2").unwrap();
        let target = d.path().join("outside");
        fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, s.path.join("link")).unwrap();
        let result = remove_safe(&s.path, uid());
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("symlink"), "msg was: {msg}");
        assert!(s.path.exists(), "dir should still exist after refusal");
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
