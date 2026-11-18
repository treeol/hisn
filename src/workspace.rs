//! Workspaces (0.5.0, PLAN-0.5 Step 1, Part B).
//!
//! Every session belongs to a workspace. Default: derived from the session's
//! canonical working directory — a stable id from the canonical path, a
//! readable name from its last component — created on first use. `--workspace
//! NAME` overrides the name (and therefore the id).
//!
//! State lives under `$XDG_STATE_HOME/hisn/workspaces/<id>/` (dir `0700`),
//! never under a runtime root and never inside a working tree. The workspace
//! dir is hisn's own state: the mount planner never mounts the state home
//! inside a session (verified in Phase 0: the only state-home overlap check
//! is for `home.persist`, and no auto-mount references the state home), so a
//! session can never read or write the workspace state. Leak cases L82 and
//! L85 assert it.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The workspace reference stored in `session.json` (0.5.0).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceRef {
    /// Filesystem id: a 16-hex-char hash of the canonical path (default) or
    /// of the name (`--workspace`).
    pub id: String,
    /// Readable name: the last component of the canonical path, or the given
    /// `--workspace` name.
    pub name: String,
}

/// `$XDG_STATE_HOME/hisn` with the `$HOME/.local/state/hisn` fallback — the
/// same resolution `main.rs` uses for the audit archive. A relative
/// `XDG_STATE_HOME` is ignored (it would be relative to the caller's cwd,
/// i.e. inside the working tree). An empty/unset `HOME` with no
/// `XDG_STATE_HOME` falls back to a per-uid path under `/tmp` (never the
/// shared `/tmp/hisn-state-unset`, which would collide across users).
///
/// [`is_tmp_state_home`] / [`warn_if_tmp_state_home`] report that case
/// (item 6): the journal lives under a tmp dir and does not survive a
/// reboot.
/// Pure resolution of the state home from explicit inputs — the
/// production [`state_home`] reads the environment once and delegates
/// here; tests pass explicit values so they never mutate the process
/// environment (env-mutating tests race with env-reading ones when
/// `cargo test` runs in parallel).
pub fn state_home_with(xdg: Option<&str>, home: Option<&str>) -> PathBuf {
    if let Some(x) = xdg
        && !x.is_empty()
        && Path::new(x).is_absolute()
    {
        return PathBuf::from(x).join("hisn");
    }
    match home {
        Some(h) if !h.is_empty() => PathBuf::from(h).join(".local").join("state").join("hisn"),
        _ => {
            let uid = rustix::process::getuid().as_raw();
            PathBuf::from(format!("/tmp/hisn-state-unset-{uid}"))
        }
    }
}

pub fn state_home() -> PathBuf {
    state_home_with(
        std::env::var("XDG_STATE_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
}

/// Pure predicate over explicit env snapshots (item 6): true iff
/// `state_home_with` would fall back to the `/tmp` per-uid dir.
/// [`is_tmp_state_home`] reads the environment and delegates here.
pub fn is_tmp_state_home_with(xdg: Option<&str>, home: Option<&str>) -> bool {
    let xdg_ok = xdg.is_some_and(|x| !x.is_empty() && Path::new(x).is_absolute());
    if xdg_ok {
        return false;
    }
    home.is_none_or(|h| h.is_empty())
}

pub fn is_tmp_state_home() -> bool {
    is_tmp_state_home_with(
        std::env::var("XDG_STATE_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
}

/// Print one warning line when the state home is the ephemeral `/tmp`
/// fallback (item 6): the journal will not survive a reboot. Once per
/// process, not per event — a `OnceLock` guards it. Called at supervisor
/// start (and cheap to call elsewhere; the guard makes it one line).
pub fn warn_if_tmp_state_home() {
    static WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if WARNED.set(()).is_ok() && is_tmp_state_home() {
        eprintln!(
            "hisn: warning: state home is {} (XDG_STATE_HOME and HOME are unset); \
             the workspace journal will not survive a reboot",
            state_home().display()
        );
    }
}

/// Total order of workspace resolution: explicit name wins; else the default
/// workspace derived from the canonical cwd.
pub fn default_workspace(canonical_cwd: &Path, name_override: Option<&str>) -> WorkspaceRef {
    match name_override {
        Some(n) if !n.is_empty() => workspace_for_name(n),
        _ => workspace_for_path(canonical_cwd),
    }
}

/// Stable id for the default workspace: 16 hex chars of SHA-256 over the
/// canonical path (so two sessions in the same directory share a workspace,
/// and a symlinked path — already canonicalised by `Policy::resolve` —
/// cannot yield a second id).
pub fn workspace_id_for_path(canonical: &Path) -> String {
    let mut h = Sha256::new();
    h.update(b"hisn-workspace\0");
    h.update(canonical.to_string_lossy().as_bytes());
    let d = h.finalize();
    d[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Stable id for a named workspace: 16 hex chars of SHA-256 over the name.
pub fn workspace_id_for_name(name: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"hisn-workspace-name\0");
    h.update(name.as_bytes());
    let d = h.finalize();
    d[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Default workspace for a canonical working directory.
pub fn workspace_for_path(canonical: &Path) -> WorkspaceRef {
    let name = canonical
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "workspace".into());
    WorkspaceRef {
        id: workspace_id_for_path(canonical),
        name,
    }
}

/// Workspace id for a canonical cwd and an optional `--workspace` override.
pub fn workspace_id_for(canonical: PathBuf, name_override: Option<&str>) -> String {
    match name_override {
        Some(n) if !n.is_empty() => workspace_id_for_name(n),
        _ => workspace_id_for_path(&canonical),
    }
}

/// Workspace readable name for a canonical cwd and an optional override.
pub fn workspace_name_for(canonical: PathBuf, name_override: Option<&str>) -> String {
    match name_override {
        Some(n) if !n.is_empty() => n.to_owned(),
        _ => workspace_for_path(&canonical).name,
    }
}

/// Named workspace (`--workspace NAME`).
pub fn workspace_for_name(name: &str) -> WorkspaceRef {
    WorkspaceRef {
        id: workspace_id_for_name(name),
        name: name.to_owned(),
    }
}

/// A `--workspace` name: `[A-Za-z0-9._-]{1,64}`, not `.`/`..`, no leading
/// `.` (the same discipline as session ids). The name is only ever hashed,
/// never used as a path — but it must still be a strict charset so it can
/// never be mistaken for one, and so junk is refused at the CLI boundary.
pub fn is_valid_workspace_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('.')
        && s != "."
        && s != ".."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// A workspace id: exactly 16 lowercase hex chars (the shape every id this
/// build derives has). Anything else is not an id and must never be joined
/// onto a path.
pub fn is_valid_workspace_id(s: &str) -> bool {
    s.len() == 16
        && s.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Workspace dir for this user: `$XDG_STATE_HOME/hisn/workspaces/<id>/`.
///
/// Total-safe by construction: an `id` that is not a valid workspace id is
/// hashed into the id namespace instead of being joined as a path, so no
/// caller (including one reading a crafted `session.json`) can make this
/// escape the workspaces dir with `..` or an absolute path.
/// Explicit-input form of [`workspace_dir`]: the caller supplies the
/// already-resolved state home, so tests never read the (possibly
/// concurrently mutated) process environment.
pub fn workspace_dir_with(state_home: &Path, id: &str) -> PathBuf {
    let safe = if is_valid_workspace_id(id) {
        id.to_owned()
    } else {
        workspace_id_for_name(id)
    };
    state_home.join("workspaces").join(safe)
}

pub fn workspace_dir(id: &str) -> PathBuf {
    workspace_dir_with(&state_home(), id)
}

/// Create (or verify) the workspace dir, mode `0700` — the same discipline
/// as a session runtime root (`session::ensure_root`): created `0700`,
/// owner-checked, never followed through a symlink, and **refused** (not
/// silently fixed) when a component is a symlink, is owned by someone else,
/// or the leaf is group/other accessible. Every component of hisn's state
/// tree (`state_home()` down to the leaf) is checked, not just the leaf.
/// What is not checked: components above `state_home()` (the user's own XDG
/// dirs), and the mode of the parent dirs (created 0700; a pre-existing
/// group-readable `hisn/` dir is the user's choice — the 0700 leaf still
/// protects the contents).
pub fn ensure_workspace(dir: &Path) -> std::io::Result<()> {
    let home = state_home();
    // Production dirs live under the state home and are validated from it.
    // A dir outside it (tests, scratch) is validated from its immediate
    // parent — the leaf still gets the full 0700/owner/no-symlink check.
    let root = if dir.starts_with(&home) {
        home
    } else {
        dir.parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| dir.to_path_buf())
    };
    ensure_workspace_under(&root, dir)
}

/// `ensure_workspace` with an explicit state root (tests).
fn ensure_workspace_under(state_root: &Path, dir: &Path) -> std::io::Result<()> {
    let parent = dir
        .parent()
        .ok_or_else(|| std::io::Error::other("workspace has no parent"))?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .or_else(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(e)
            }
        })?;
    fs::DirBuilder::new().mode(0o700).create(dir).or_else(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            Ok(())
        } else {
            Err(e)
        }
    })?;
    // Verify every component from the state home down to the leaf.
    let uid = rustix::process::getuid().as_raw();
    let home = state_root.to_path_buf();
    let mut cur = home.clone();
    let mut parts: Vec<std::ffi::OsString> = dir
        .strip_prefix(&home)
        .map_err(|_| std::io::Error::other("workspace dir is not under the state home"))?
        .components()
        .map(|c| c.as_os_str().to_owned())
        .collect();
    // The state home itself is the first component checked.
    check_state_component(&home, uid, false)?;
    for part in parts.drain(..) {
        cur.push(part);
        let is_leaf = cur == dir;
        check_state_component(&cur, uid, is_leaf)?;
    }
    Ok(())
}

/// Is `p` a real directory (not a symlink), owned by `uid`? When `leaf`,
/// it must also be mode 0700 (no group/other bits).
fn check_state_component(p: &Path, uid: u32, leaf: bool) -> std::io::Result<()> {
    let md = fs::symlink_metadata(p)?;
    if md.file_type().is_symlink() || !md.file_type().is_dir() {
        return Err(std::io::Error::other(format!(
            "{} is not a real directory (symlink or file)",
            p.display()
        )));
    }
    if md.uid() != uid {
        return Err(std::io::Error::other(format!(
            "{} is not owned by the current user",
            p.display()
        )));
    }
    if leaf && md.mode() & 0o077 != 0 {
        return Err(std::io::Error::other(format!(
            "{} must be mode 0700 (is {:o})",
            p.display(),
            md.mode() & 0o777
        )));
    }
    Ok(())
}

/// Persistent journal lookup result. Marker names/ids are validated, not paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMarker {
    pub workspace: String,
    pub session: String,
    pub name: String,
    pub ambiguous: bool,
}

/// Write only at session start. Publication is atomic, with no per-event work.
pub fn write_session_marker(dir: &Path, id: &str, name: Option<&str>) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicU64, Ordering};
    if !crate::policy::is_valid_session_id(id)
        || name.is_some_and(|n| !crate::policy::is_valid_session_id(n))
    {
        return Err(std::io::Error::other("invalid session marker id/name"));
    }
    let uid = rustix::process::getuid().as_raw();
    let ws = create_marker_workspace(dir, uid)?;
    let sessions = crate::sys::cstr(Path::new("sessions"))?;
    rustix::fs::mkdirat(
        &ws,
        sessions.as_c_str(),
        rustix::fs::Mode::from_raw_mode(0o700),
    )
    .or_else(|e| {
        if e == rustix::io::Errno::EXIST {
            Ok(())
        } else {
            Err(e)
        }
    })?;
    let fd = open_marker_dir(ws.as_raw_fd(), Path::new("sessions"), uid, true)?;
    // Refuse unsafe existing markers rather than following or replacing them.
    let dest = crate::sys::cstr(Path::new(id))?;
    match rustix::fs::statat(&fd, dest.as_c_str(), rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st)
            if st.st_uid != uid
                || st.st_mode & libc::S_IFMT != libc::S_IFREG
                || st.st_mode & 0o777 != 0o600
                || st.st_nlink != 1 =>
        {
            return Err(std::io::Error::other("unsafe existing session marker"));
        }
        Err(e) if e != rustix::io::Errno::NOENT => return Err(e.into()),
        _ => {}
    }
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let tmp = crate::sys::cstr(Path::new(&format!(
        ".tmp-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )))?;
    let raw = crate::sys::openat2(
        fd.as_raw_fd(),
        &tmp,
        (libc::O_WRONLY
            | libc::O_CREAT
            | libc::O_EXCL
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK) as u64,
        0o600,
        crate::sys::RESOLVE_BENEATH
            | crate::sys::RESOLVE_NO_SYMLINKS
            | crate::sys::RESOLVE_NO_MAGICLINKS,
    )?;
    let mut file = fs::File::from(raw);
    let result = (|| {
        file.write_all(format!("{}\n", name.unwrap_or("")).as_bytes())?;
        rustix::fs::renameat(&fd, tmp.as_c_str(), &fd, dest.as_c_str())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = rustix::fs::unlinkat(&fd, tmp.as_c_str(), rustix::fs::AtFlags::empty());
    }
    result
}

/// Create only below a pinned, checked state root. Ancestors above that root
/// belong to the user; workspace/sessions children never follow symlinks.
fn create_marker_workspace(dir: &Path, uid: u32) -> std::io::Result<std::os::fd::OwnedFd> {
    let home = state_home();
    let root = if dir.starts_with(&home) {
        home
    } else if dir.parent().and_then(Path::file_name) == Some(std::ffi::OsStr::new("workspaces")) {
        dir.parent()
            .and_then(Path::parent)
            .ok_or_else(|| std::io::Error::other("workspace has no state root"))?
            .to_path_buf()
    } else {
        dir.parent()
            .ok_or_else(|| std::io::Error::other("workspace has no parent"))?
            .to_path_buf()
    };
    let parts: Vec<_> = dir
        .strip_prefix(&root)
        .map_err(std::io::Error::other)?
        .components()
        .collect();
    if parts.is_empty()
        || parts
            .iter()
            .any(|p| !matches!(p, std::path::Component::Normal(_)))
    {
        return Err(std::io::Error::other("invalid marker workspace path"));
    }
    let parent = root
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    // Only ancestors ABOVE hisn's state root may be symlinked.
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    let parent = open_marker_ancestor(parent)?;
    let leaf = root
        .file_name()
        .ok_or_else(|| std::io::Error::other("state root has no name"))?;
    let mut fd = create_marker_child(&parent, Path::new(leaf), uid, false)?;
    for (index, part) in parts.iter().enumerate() {
        fd = create_marker_child(
            &fd,
            Path::new(part.as_os_str()),
            uid,
            index + 1 == parts.len(),
        )?;
    }
    Ok(fd)
}

/// Pin the user's ancestors, which may be symlinked. The state root itself
/// is then opened relative to this fd with the normal no-symlink checks.
fn open_marker_ancestor(path: &Path) -> std::io::Result<std::os::fd::OwnedFd> {
    let canonical = fs::canonicalize(path)?;
    let c = crate::sys::cstr(&canonical)?;
    crate::sys::openat2(
        libc::AT_FDCWD,
        &c,
        (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            as u64,
        0,
        crate::sys::RESOLVE_NO_SYMLINKS | crate::sys::RESOLVE_NO_MAGICLINKS,
    )
}

fn open_marker_root(path: &Path, uid: u32) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::AsRawFd;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let fd = open_marker_ancestor(parent)?;
    let leaf = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("state root has no name"))?;
    open_marker_dir(fd.as_raw_fd(), Path::new(leaf), uid, false)
}

fn create_marker_child(
    parent: &std::os::fd::OwnedFd,
    name: &Path,
    uid: u32,
    private: bool,
) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::AsRawFd;
    let name_c = crate::sys::cstr(name)?;
    rustix::fs::mkdirat(
        parent,
        name_c.as_c_str(),
        rustix::fs::Mode::from_raw_mode(0o700),
    )
    .or_else(|e| {
        if e == rustix::io::Errno::EXIST {
            Ok(())
        } else {
            Err(e)
        }
    })?;
    open_marker_dir(parent.as_raw_fd(), name, uid, private)
}

fn open_marker_dir(
    parent: std::os::fd::RawFd,
    path: &Path,
    uid: u32,
    private: bool,
) -> std::io::Result<std::os::fd::OwnedFd> {
    let c = crate::sys::cstr(path)?;
    let resolve = crate::sys::RESOLVE_NO_SYMLINKS
        | crate::sys::RESOLVE_NO_MAGICLINKS
        | if path.is_absolute() {
            0
        } else {
            crate::sys::RESOLVE_BENEATH
        };
    let fd = crate::sys::openat2(
        parent,
        &c,
        (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            as u64,
        0,
        resolve,
    )?;
    let st = rustix::fs::fstat(&fd)?;
    if st.st_uid != uid || (private && st.st_mode & 0o777 != 0o700) {
        return Err(std::io::Error::other("unsafe marker directory owner/mode"));
    }
    Ok(fd)
}

fn marker_names(fd: &std::os::fd::OwnedFd) -> std::io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(fd)? {
        let entry = entry?;
        if let Ok(name) = entry.file_name().to_str() {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

pub fn find_session_marker(root: &Path, arg: &str) -> Option<SessionMarker> {
    find_session_marker_in_workspace(root, arg, None)
}

pub fn find_session_marker_in_workspace(
    root: &Path,
    arg: &str,
    workspace: Option<&str>,
) -> Option<SessionMarker> {
    find_session_marker_scoped(root, arg, rustix::process::getuid().as_raw(), workspace)
}

#[cfg(test)]
fn find_session_marker_for_uid(root: &Path, arg: &str, uid: u32) -> Option<SessionMarker> {
    find_session_marker_scoped(root, arg, uid, None)
}

fn find_session_marker_scoped(
    root: &Path,
    arg: &str,
    uid: u32,
    workspace: Option<&str>,
) -> Option<SessionMarker> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    if !crate::policy::is_valid_session_id(arg) {
        return None;
    }
    let root = open_marker_root(root, uid).ok()?;
    let workspaces = open_marker_dir(root.as_raw_fd(), Path::new("workspaces"), uid, false).ok()?;
    let mut candidates = Vec::new();
    for wid in marker_names(&workspaces).ok()? {
        if !is_valid_workspace_id(&wid) || workspace.is_some_and(|w| w != wid) {
            continue;
        }
        let Ok(ws) = open_marker_dir(workspaces.as_raw_fd(), Path::new(&wid), uid, true) else {
            continue;
        };
        let Ok(sessions) = open_marker_dir(ws.as_raw_fd(), Path::new("sessions"), uid, true) else {
            continue;
        };
        for id in marker_names(&sessions).unwrap_or_default() {
            if !crate::policy::is_valid_session_id(&id) {
                continue;
            }
            let Ok(c) = crate::sys::cstr(Path::new(&id)) else {
                continue;
            };
            let Ok(fd) = crate::sys::openat2(
                sessions.as_raw_fd(),
                &c,
                (libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) as u64,
                0,
                crate::sys::RESOLVE_BENEATH
                    | crate::sys::RESOLVE_NO_SYMLINKS
                    | crate::sys::RESOLVE_NO_MAGICLINKS,
            ) else {
                continue;
            };
            let file = fs::File::from(fd);
            let Ok(md) = file.metadata() else {
                continue;
            };
            if !md.is_file()
                || md.uid() != uid
                || md.mode() & 0o777 != 0o600
                || md.nlink() != 1
                || md.len() > 65
            {
                continue;
            }
            let mut body = String::new();
            if file.take(66).read_to_string(&mut body).is_err() {
                continue;
            }
            let Some(name) = body.strip_suffix('\n') else {
                continue;
            };
            if !name.is_empty() && !crate::policy::is_valid_session_id(name) {
                continue;
            }
            if id != arg && name != arg {
                continue;
            }
            let Ok(time) = md.modified() else {
                continue;
            };
            candidates.push((
                id == arg,
                time,
                SessionMarker {
                    workspace: wid.clone(),
                    session: id,
                    name: name.to_owned(),
                    ambiguous: false,
                },
            ));
        }
    }
    // Exact id beats a name; newest mtime wins name reuse, with deterministic ties.
    candidates.sort_by(|a, b| {
        (a.0, a.1, &a.2.session, &a.2.workspace).cmp(&(b.0, b.1, &b.2.session, &b.2.workspace))
    });
    let (is_id, _, mut chosen) = candidates.pop()?;
    chosen.ambiguous = !is_id && candidates.iter().any(|c| !c.0);
    Some(chosen)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker_tree() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir_in("target").unwrap();
        let root = d.path().join("hisn");
        (d, root)
    }

    #[test]
    fn polish2_markers_allow_symlinked_ancestors_above_state_root() {
        let d = tempfile::tempdir_in("target").unwrap();
        let base = fs::canonicalize(d.path()).unwrap();
        let real = base.join("real");
        fs::create_dir(&real).unwrap();
        let root = real.join("hisn");
        write_session_marker(
            &root.join("workspaces/0123456789abcdef"),
            "old",
            Some("chat"),
        )
        .unwrap();
        let alias = base.join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let through_alias = alias.join("hisn");
        assert_eq!(
            find_session_marker(&through_alias, "old").map(|m| m.session),
            Some("old".into()),
            "ancestors above state_home are user paths, not protected state components"
        );
        write_session_marker(
            &through_alias.join("workspaces/0123456789abcdef"),
            "new",
            None,
        )
        .unwrap();
        assert!(find_session_marker(&root, "new").is_some());
    }

    #[test]
    fn polish2_marker_refusal_does_not_create_through_state_symlinks() {
        use std::os::unix::fs::symlink;
        for root_link in [true, false] {
            let (d, root) = marker_tree();
            let outside = fs::canonicalize(d.path()).unwrap().join("outside");
            fs::create_dir(&outside).unwrap();
            if root_link {
                symlink(&outside, &root).unwrap();
            } else {
                fs::create_dir(&root).unwrap();
                symlink(&outside, root.join("workspaces")).unwrap();
            }
            let result =
                write_session_marker(&root.join("workspaces/0123456789abcdef"), "id", None);
            assert!(result.is_err(), "unsafe state tree must be refused");
            assert_eq!(
                fs::read_dir(&outside).unwrap().count(),
                0,
                "refusal must happen before creating children through a symlink"
            );
        }
    }

    #[test]
    fn polish2_ended_marker_found_by_id_and_name() {
        let (_d, root) = marker_tree();
        let ws = root.join("workspaces/0123456789abcdef");
        write_session_marker(&ws, "ended-1", Some("chat")).unwrap();
        // No live session directory or cwd-based workspace involved.
        let expected = SessionMarker {
            workspace: "0123456789abcdef".into(),
            session: "ended-1".into(),
            name: "chat".into(),
            ambiguous: false,
        };
        assert_eq!(
            find_session_marker(&root, "ended-1"),
            Some(expected.clone())
        );
        assert_eq!(find_session_marker(&root, "chat"), Some(expected));
        assert_eq!(
            fs::symlink_metadata(ws.join("sessions")).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::symlink_metadata(ws.join("sessions/ended-1"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn polish2_reused_name_chooses_newest_and_reports_id() {
        let (_d, root) = marker_tree();
        let a = root.join("workspaces/0123456789abcdef");
        let b = root.join("workspaces/fedcba9876543210");
        write_session_marker(&a, "old", Some("chat")).unwrap();
        write_session_marker(&b, "new", Some("chat")).unwrap();
        for (dir, id, secs) in [(&a, "old", 1), (&b, "new", 2)] {
            fs::File::open(dir.join("sessions").join(id))
                .unwrap()
                .set_times(
                    fs::FileTimes::new()
                        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)),
                )
                .unwrap();
        }
        let m = find_session_marker(&root, "chat").unwrap();
        assert_eq!(m.session, "new");
        assert!(m.ambiguous, "caller must report chosen id");
    }

    #[test]
    fn polish2_unsafe_markers_are_ignored() {
        let (_d, root) = marker_tree();
        let ws = root.join("workspaces/0123456789abcdef");
        write_session_marker(&ws, "real", Some("chat")).unwrap();
        std::os::unix::fs::symlink("real", ws.join("sessions/link")).unwrap();
        assert!(find_session_marker(&root, "link").is_none());
        let owner = fs::metadata(ws.join("sessions/real")).unwrap().uid();
        assert!(find_session_marker_for_uid(&root, "real", owner.wrapping_add(1)).is_none());
    }

    // State-home resolution is tested via the explicit `*_with`
    // forms; no test in this module mutates XDG_STATE_HOME/HOME, so
    // env-reading tests here cannot race with env-mutating ones.

    #[test]
    fn workspace_id_is_stable_for_the_same_path() {
        let a = workspace_for_path(Path::new("/work/proj"));
        let b = workspace_for_path(Path::new("/work/proj"));
        assert_eq!(a, b);
        assert_eq!(a.name, "proj");
        assert_eq!(a.id.len(), 16);
        assert!(a.id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn workspace_id_differs_for_different_paths() {
        let a = workspace_for_path(Path::new("/work/proj"));
        let b = workspace_for_path(Path::new("/work/other"));
        let c = workspace_for_name("proj");
        // A named workspace is a different workspace from the path one (the
        // id namespace is salted per kind).
        assert_ne!(a.id, b.id);
        assert_ne!(a.id, c.id);
        assert_eq!(c.name, "proj");
        assert_eq!(c.id, workspace_for_name("proj").id);
    }

    #[test]
    fn workspace_dir_is_under_the_state_home_workspaces() {
        // A valid id passes through unchanged. Explicit state home —
        // never the process environment (which parallel env-mutating
        // tests can temporarily empty, sending `state_home()` to the
        // /tmp fallback that does not end in `hisn/workspaces/`).
        let home = state_home_with(Some("/real/state"), Some("/home/u"));
        let d = workspace_dir_with(&home, "0123456789abcdef");
        assert!(d.ends_with("hisn/workspaces/0123456789abcdef"), "got {d:?}");
    }

    #[test]
    fn default_prefers_the_override() {
        let w = default_workspace(Path::new("/work/proj"), Some("team"));
        assert_eq!(w, workspace_for_name("team"));
        let w = default_workspace(Path::new("/work/proj"), None);
        assert_eq!(w, workspace_for_path(Path::new("/work/proj")));
        let w = default_workspace(Path::new("/work/proj"), Some(""));
        assert_eq!(w, workspace_for_path(Path::new("/work/proj")));
    }

    #[test]
    fn tmp_state_home_is_detected_only_when_both_env_vars_fail() {
        // Item 6: the /tmp fallback happens only when XDG_STATE_HOME is
        // missing/empty/relative AND HOME is missing/empty. Tested as a
        // pure predicate over explicit snapshots — no process-env
        // mutation, so no race with other tests.
        // Both present and good: not tmp.
        assert!(!is_tmp_state_home_with(
            Some("/real/state"),
            Some("/home/u")
        ));
        // XDG good, HOME missing: not tmp.
        assert!(!is_tmp_state_home_with(Some("/real/state"), None));
        // XDG missing, HOME good: not tmp.
        assert!(!is_tmp_state_home_with(None, Some("/home/u")));
        // Both missing: tmp.
        assert!(is_tmp_state_home_with(None, None));
        // XDG relative, HOME empty: tmp.
        assert!(is_tmp_state_home_with(Some("rel/state"), Some("")));
        // XDG empty, HOME empty: tmp.
        assert!(is_tmp_state_home_with(Some(""), Some("")));
    }

    #[test]
    fn same_folder_name_in_different_trees_never_collides() {
        // Item 4: the id is derived from the canonical path, so two
        // projects with the same folder name in different trees have
        // different workspaces.
        let a = workspace_for_path(Path::new("/work/team/proj"));
        let b = workspace_for_path(Path::new("/home/user/Coding/proj"));
        assert_eq!(a.name, b.name);
        assert_ne!(a.id, b.id);
        let home = state_home_with(Some("/real/state"), Some("/home/u"));
        assert_ne!(
            workspace_dir_with(&home, &a.id),
            workspace_dir_with(&home, &b.id)
        );
    }

    #[test]
    fn workspace_dir_never_escapes_for_a_crafted_id() {
        // Item 4: workspace_dir is total-safe — anything that is not a
        // 16-hex id is hashed into the namespace, never joined as a path.
        // Explicit state home (no process-env read; see
        // `workspace_dir_is_under_the_state_home_workspaces`).
        let home = state_home_with(Some("/real/state"), Some("/home/u"));
        for crafted in [
            "../../etc",
            "/etc/passwd",
            "..",
            ".",
            "a/b",
            "x".repeat(64).as_str(),
            "",
        ] {
            let d = workspace_dir_with(&home, crafted);
            assert!(
                d.ends_with("hisn/workspaces")
                    || d.parent().is_some_and(|p| p.ends_with("workspaces")),
                "{crafted:?} escaped: {d:?}"
            );
            // The joined component is always a 16-hex id.
            let last = d.file_name().unwrap().to_string_lossy();
            assert!(is_valid_workspace_id(&last), "{crafted:?} -> {d:?}");
        }
        // Valid ids pass through unchanged.
        let d = workspace_dir_with(&home, "0123456789abcdef");
        assert!(d.ends_with("hisn/workspaces/0123456789abcdef"), "got {d:?}");
    }

    #[test]
    fn workspace_name_charset() {
        for good in ["team", "proj-1", "a_b.c", "x"] {
            assert!(is_valid_workspace_name(good), "{good:?}");
        }
        for bad in [
            "",
            "../x",
            "..",
            ".",
            ".hidden",
            "a/b",
            "/abs",
            "a\\b",
            "sp ace",
            "x".repeat(65).as_str(),
        ] {
            assert!(!is_valid_workspace_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn ensure_workspace_refuses_symlink_parent_leaf_and_foreign_leaf() {
        use std::os::unix::fs::PermissionsExt;
        // Happy path: created 0700 under a temp state root.
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("hisn");
        let dir = root.join("workspaces").join("0123456789abcdef");
        ensure_workspace_under(&root, &dir).unwrap();
        let md = fs::symlink_metadata(&dir).unwrap();
        assert_eq!(md.mode() & 0o777, 0o700);
        assert!(md.file_type().is_dir());

        // Foreign-owned leaf: refused. (Cannot chown in the sandbox, so
        // check the component directly with a uid that is not the owner.)
        let d2 = tempfile::tempdir().unwrap();
        let root2 = d2.path().join("hisn");
        let dir2 = root2.join("workspaces").join("0123456789abcdef");
        fs::create_dir_all(&dir2).unwrap();
        let owner = fs::symlink_metadata(&dir2).unwrap().uid();
        assert_ne!(owner, 65534, "test setup: dir must not be owned by 65534");
        assert!(
            check_state_component(&dir2, 65534, true).is_err(),
            "foreign-owned dir must be refused"
        );

        // Symlinked parent in the state tree: refused.
        let d3 = tempfile::tempdir().unwrap();
        let real = d3.path().join("real");
        fs::create_dir_all(&real).unwrap();
        let root3 = d3.path().join("hisn");
        std::os::unix::fs::symlink(&real, &root3).unwrap();
        let dir3 = root3.join("workspaces").join("0123456789abcdef");
        assert!(
            ensure_workspace_under(&root3, &dir3).is_err(),
            "symlinked state-home must be refused"
        );

        // Symlinked leaf: refused.
        let d4 = tempfile::tempdir().unwrap();
        let root4 = d4.path().join("hisn");
        let target = d4.path().join("elsewhere");
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(root4.join("workspaces")).unwrap();
        let dir4 = root4.join("workspaces").join("0123456789abcdef");
        std::os::unix::fs::symlink(&target, &dir4).unwrap();
        assert!(
            ensure_workspace_under(&root4, &dir4).is_err(),
            "symlinked workspace dir must be refused"
        );

        // Group-readable leaf (0755): refused (mirrors session::ensure_root).
        let d5 = tempfile::tempdir().unwrap();
        let root5 = d5.path().join("hisn");
        let dir5 = root5.join("workspaces").join("0123456789abcdef");
        fs::create_dir_all(&dir5).unwrap();
        fs::set_permissions(&dir5, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            ensure_workspace_under(&root5, &dir5).is_err(),
            "0755 workspace dir must be refused"
        );
    }
}
