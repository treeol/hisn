//! Rootfs store (0.3.2): manages rootfs images under
//! `$XDG_DATA_HOME/hisn/rootfs/<name>/`.
//!
//! A rootfs is a directory tree that replaces the host toolchain dirs
//! (`/usr`, `/bin`, …) inside the sandbox. The store resolves a name to a
//! path; the import tool populates the store from a tar archive.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// The rootfs manifest (`manifest.json` inside each store entry).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub name: String,
    pub source: String,
    pub source_digest: Option<String>,
    pub import_timestamp: String,
    pub hisn_version: String,
    pub sha256: Option<String>,
    pub files: u64,
    pub skipped: u64,
    pub size_bytes: u64,
}

/// The store root: `$XDG_DATA_HOME/hisn/rootfs/` (default
/// `~/.local/share/hisn/rootfs/`).
pub fn store_root() -> Result<PathBuf> {
    let xdg = std::env::var("XDG_DATA_HOME").ok();
    let base = match xdg {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => {
            let home = std::env::var("HOME").context("HOME is not set")?;
            PathBuf::from(home).join(".local").join("share")
        }
    };
    Ok(base.join("hisn").join("rootfs"))
}

/// Refuse a rootfs whose layout would make the host path walk escape it.
///
/// `<rootfs>/etc` is enumerated with `read_dir` on the host and each entry is
/// bound from `<rootfs>/etc/<name>`; if `etc` were a symlink (absolute, or
/// dangling) the host would resolve it outside the tree. It must therefore be
/// a real directory. Toolchain dirs that are symlinks (`bin -> usr/bin`) are
/// only ever recreated as symlinks, never followed, and stay allowed.
pub fn check_layout(root: &std::path::Path) -> std::result::Result<(), String> {
    let etc = root.join("etc");
    match std::fs::symlink_metadata(&etc) {
        Ok(m) if m.file_type().is_symlink() => {
            let t = std::fs::read_link(&etc)
                .map(|t| t.display().to_string())
                .unwrap_or_default();
            let dangling = if etc.exists() { "" } else { " (dangling)" };
            Err(format!(
                "{} is a symlink -> {t}{dangling}; the rootfs /etc must be a real directory",
                etc.display()
            ))
        }
        _ => Ok(()),
    }
}

/// Validate a rootfs store name: `^[A-Za-z0-9._-]{1,64}$`, not `.` or `..`.
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Resolve a store name to its path: `$XDG_DATA_HOME/hisn/rootfs/<name>/`.
/// Does NOT check existence; the caller should `fs::canonicalize` or stat.
pub fn resolve_name(name: &str) -> Result<PathBuf> {
    if !is_valid_name(name) {
        bail!("invalid rootfs name {name:?}");
    }
    let root = store_root()?;
    Ok(root.join(name))
}

/// List the names present in the store (directories with a `manifest.json`).
pub fn list() -> Result<Vec<String>> {
    let root = store_root()?;
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for e in fs::read_dir(&root)? {
        let e = e?;
        if !e.file_type()?.is_dir() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if !is_valid_name(&name) {
            continue;
        }
        let manifest = e.path().join("manifest.json");
        if manifest.is_file() {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// Get the path of a named rootfs, or None if not present.
pub fn path_of(name: &str) -> Result<Option<PathBuf>> {
    if !is_valid_name(name) {
        bail!("invalid rootfs name {name:?}");
    }
    let p = resolve_name(name)?;
    if p.join("manifest.json").is_file() {
        Ok(Some(p))
    } else {
        Ok(None)
    }
}

/// Remove a named rootfs from the store.
pub fn remove(name: &str) -> Result<()> {
    if !is_valid_name(name) {
        bail!("invalid rootfs name {name:?}");
    }
    let p = resolve_name(name)?;
    if !p.exists() {
        bail!("rootfs {name:?} does not exist");
    }
    fs::remove_dir_all(&p).with_context(|| format!("removing rootfs {name}"))?;
    Ok(())
}

/// Read the manifest of a named rootfs.
pub fn manifest(name: &str) -> Result<Manifest> {
    if !is_valid_name(name) {
        bail!("invalid rootfs name {name:?}");
    }
    let p = resolve_name(name)?;
    let manifest_path = p.join("manifest.json");
    let text = fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading manifest for {name}"))?;
    serde_json::from_str(&text).with_context(|| format!("parsing manifest for {name}"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn check_layout_refuses_symlinked_etc() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir(r.join("etc")).unwrap();
        assert!(check_layout(r).is_ok());
        std::fs::remove_dir(r.join("etc")).unwrap();
        std::os::unix::fs::symlink("nonexistent", r.join("etc")).unwrap();
        let e = check_layout(r).unwrap_err();
        assert!(e.contains("/etc") && e.contains("dangling"), "{e}");
        std::fs::remove_file(r.join("etc")).unwrap();
        std::os::unix::fs::symlink("/home", r.join("etc")).unwrap();
        assert!(check_layout(r).unwrap_err().contains("symlink -> /home"));
    }

    use super::*;

    #[test]
    fn name_validation() {
        assert!(is_valid_name("go-dev"));
        assert!(is_valid_name("a.b_c-d9"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name(".."));
        assert!(!is_valid_name("."));
        assert!(!is_valid_name("a/b"));
        assert!(!is_valid_name(&"a".repeat(65)));
    }

    #[test]
    fn resolve_name_rejects_invalid() {
        assert!(resolve_name("../escape").is_err());
        assert!(resolve_name("a/b").is_err());
    }
}
