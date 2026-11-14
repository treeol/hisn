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
pub fn state_home() -> PathBuf {
    if let Ok(x) = std::env::var("XDG_STATE_HOME")
        && !x.is_empty()
        && Path::new(&x).is_absolute()
    {
        return PathBuf::from(x).join("hisn");
    }
    match std::env::var("HOME") {
        Ok(h) if !h.is_empty() => PathBuf::from(h).join(".local").join("state").join("hisn"),
        _ => {
            let uid = rustix::process::getuid().as_raw();
            PathBuf::from(format!("/tmp/hisn-state-unset-{uid}"))
        }
    }
}

/// Whether `state_home()` falls back to the per-uid directory under
/// `/tmp` — i.e. `XDG_STATE_HOME` is missing, empty or relative **and**
/// `HOME` is missing or empty (item 6).
pub fn is_tmp_state_home() -> bool {
    let xdg_ok = std::env::var("XDG_STATE_HOME")
        .map(|x| !x.is_empty() && Path::new(&x).is_absolute())
        .unwrap_or(false);
    if xdg_ok {
        return false;
    }
    std::env::var("HOME").map(|h| h.is_empty()).unwrap_or(true)
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
pub fn workspace_dir(id: &str) -> PathBuf {
    let safe = if is_valid_workspace_id(id) {
        id.to_owned()
    } else {
        workspace_id_for_name(id)
    };
    state_home().join("workspaces").join(safe)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialises the env-mutating tests in this module.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

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
        // A valid id passes through unchanged.
        let d = workspace_dir("0123456789abcdef");
        assert!(d.ends_with("hisn/workspaces/0123456789abcdef"));
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
        // pure predicate over explicit env snapshots (the real env is
        // restored immediately).
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let save_xdg = std::env::var("XDG_STATE_HOME").ok();
        let save_home = std::env::var("HOME").ok();
        // SAFETY: guarded by ENV_LOCK for the whole restore window.
        unsafe {
            let set = |xdg: Option<&str>, home: Option<&str>| {
                match xdg {
                    Some(v) => std::env::set_var("XDG_STATE_HOME", v),
                    None => std::env::remove_var("XDG_STATE_HOME"),
                }
                match home {
                    Some(v) => std::env::set_var("HOME", v),
                    None => std::env::remove_var("HOME"),
                }
            };
            // Both present and good: not tmp.
            set(Some("/real/state"), Some("/home/u"));
            assert!(!is_tmp_state_home());
            // XDG good, HOME missing: not tmp.
            set(Some("/real/state"), None);
            assert!(!is_tmp_state_home());
            // XDG missing, HOME good: not tmp.
            set(None, Some("/home/u"));
            assert!(!is_tmp_state_home());
            // Both missing: tmp.
            set(None, None);
            assert!(is_tmp_state_home());
            // XDG relative, HOME empty: tmp.
            set(Some("rel/state"), Some(""));
            assert!(is_tmp_state_home());
            // XDG empty, HOME empty: tmp.
            set(Some(""), Some(""));
            assert!(is_tmp_state_home());
            // Restore.
            match save_xdg {
                Some(v) => std::env::set_var("XDG_STATE_HOME", v),
                None => std::env::remove_var("XDG_STATE_HOME"),
            }
            match save_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn same_folder_name_in_different_trees_never_collides() {
        // Item 4: the id is derived from the canonical path, so two
        // projects with the same folder name in different trees have
        // different workspaces.
        let a = workspace_for_path(Path::new("/work/team/proj"));
        let b = workspace_for_path(Path::new("/home/valon/Coding/proj"));
        assert_eq!(a.name, b.name);
        assert_ne!(a.id, b.id);
        assert_ne!(workspace_dir(&a.id), workspace_dir(&b.id));
    }

    #[test]
    fn workspace_dir_never_escapes_for_a_crafted_id() {
        // Item 4: workspace_dir is total-safe — anything that is not a
        // 16-hex id is hashed into the namespace, never joined as a path.
        for crafted in [
            "../../etc",
            "/etc/passwd",
            "..",
            ".",
            "a/b",
            "x".repeat(64).as_str(),
            "",
        ] {
            let d = workspace_dir(crafted);
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
        let d = workspace_dir("0123456789abcdef");
        assert!(d.ends_with("hisn/workspaces/0123456789abcdef"));
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
