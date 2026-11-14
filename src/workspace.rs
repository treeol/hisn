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
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
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
/// same resolution `main.rs` uses for the audit archive. An empty/unset
/// `HOME` with no `XDG_STATE_HOME` is forbidden (it would otherwise yield a
/// relative `.local/state/hisn` inside the working tree).
pub fn state_home() -> PathBuf {
    if let Ok(x) = std::env::var("XDG_STATE_HOME")
        && !x.is_empty()
    {
        return PathBuf::from(x).join("hisn");
    }
    match std::env::var("HOME") {
        Ok(h) if !h.is_empty() => PathBuf::from(h).join(".local").join("state").join("hisn"),
        _ => PathBuf::from("/tmp/hisn-state-unset"),
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

/// Workspace dir for this user: `$XDG_STATE_HOME/hisn/workspaces/<id>/`.
pub fn workspace_dir(id: &str) -> PathBuf {
    state_home().join("workspaces").join(id)
}

/// Create (or verify) the workspace dir, mode `0700`, not a symlink — the
/// same discipline as a session runtime root (`session::ensure_root`). The
/// parent `workspaces/` dir is created `0700` too. Recursive (the workspace
/// dir is three levels under the state home).
pub fn ensure_workspace(dir: &Path) -> std::io::Result<()> {
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
    let md = fs::symlink_metadata(dir)?;
    if !md.file_type().is_dir() {
        return Err(std::io::Error::other(
            "workspace dir is not a real directory (symlink?)",
        ));
    }
    let mut p = md.permissions();
    p.set_mode(0o700);
    let _ = fs::set_permissions(dir, p);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let d = workspace_dir("abc123");
        assert!(d.ends_with("hisn/workspaces/abc123"));
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
}
