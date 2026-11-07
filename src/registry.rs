//! Per-user session name registry (0.4.0, step 1a).
//!
//! A session may carry a human name (`hisn run --name`). Names are unique per
//! user across every candidate runtime root. The authoritative mapping
//! name -> id lives in `names.json` inside the `/tmp/hisn-$UID` root, always,
//! regardless of which root the session itself is in. `names.lock` in the same
//! root serialises writers. Both go through `session::ensure_root`, so the
//! owner, symlink and mode checks apply.
//!
//! The index is a cache of truth that lives in the session directories: each
//! session's `name` file is the source for its name. If the index is missing
//! or unparseable, lookups fall back to scanning every candidate root's
//! `name` files, and `repair` rewrites the index from that scan.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::policy::is_valid_session_id;
use crate::rootfs_store::is_valid_name;
use crate::session::{SessionError, ensure_root};

pub const INDEX_FILE: &str = "names.json";
pub const LOCK_FILE: &str = "names.lock";
pub const NAME_FILE: &str = "name";

/// The fixed home of the registry: the `/tmp/hisn-$UID` root, for every user
/// regardless of `XDG_RUNTIME_DIR`.
pub fn registry_root(uid: u32) -> PathBuf {
    PathBuf::from(format!("/tmp/hisn-{uid}"))
}

#[derive(Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Index {
    /// Name -> session id.
    pub names: BTreeMap<String, String>,
}

/// Exclusive lock on `names.lock`, released on drop.
pub struct Lock {
    _file: File,
}

impl Lock {
    /// Take the registry lock. Blocks until available.
    pub fn take(reg_root: &Path, uid: u32) -> Result<Self, SessionError> {
        ensure_root(reg_root, uid)?;
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(reg_root.join(LOCK_FILE))?;
        // SAFETY: flock on a valid, owned fd; no memory is touched.
        let rc = unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&f), libc::LOCK_EX) };
        if rc != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self { _file: f })
    }
}

/// Read the index. A missing or unparseable file yields `None`, which tells
/// the caller to fall back to a scan.
pub fn read_index(reg_root: &Path) -> Option<Index> {
    let text = fs::read_to_string(reg_root.join(INDEX_FILE)).ok()?;
    serde_json::from_str(&text).ok()
}

/// Atomically replace the index: write a temp file, fsync, rename.
pub fn write_index(reg_root: &Path, idx: &Index) -> io::Result<()> {
    let tmp = reg_root.join(format!(".{INDEX_FILE}.tmp"));
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    let body = serde_json::to_string(idx).map_err(io::Error::other)?;
    f.write_all(body.as_bytes())?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, reg_root.join(INDEX_FILE))
}

/// Read a session's `name` file, if it has one and it is valid.
pub fn name_of(session_dir: &Path) -> Option<String> {
    let md = fs::symlink_metadata(session_dir.join(NAME_FILE)).ok()?;
    if !md.file_type().is_file() {
        return None;
    }
    let s = fs::read_to_string(session_dir.join(NAME_FILE)).ok()?;
    let s = s.trim_end_matches('\n').to_owned();
    is_valid_name(&s).then_some(s)
}

/// Scan every candidate root for session directories that carry a name.
/// Returns `(name, id)` pairs. Used only as the fallback path.
pub fn scan_names(roots: &[PathBuf]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for r in roots {
        let Ok(rd) = fs::read_dir(r) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let Some(id) = e.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !p.is_dir() || !is_valid_session_id(&id) {
                continue;
            }
            if let Some(name) = name_of(&p) {
                out.push((name, id));
            }
        }
    }
    out.sort();
    out
}

/// Resolve a name to a session id. The index is authoritative; if it is
/// missing or unparseable, fall back to a scan. The index is not rewritten
/// here; `repair` does that.
pub fn resolve_name(reg_root: &Path, roots: &[PathBuf], name: &str) -> Option<String> {
    match read_index(reg_root) {
        Some(idx) => idx.names.get(name).cloned(),
        None => scan_names(roots)
            .into_iter()
            .find(|(n, _)| n == name)
            .map(|(_, id)| id),
    }
}

/// Rebuild the index from the session directories. Caller holds the lock.
/// Returns the number of names recorded.
pub fn repair(reg_root: &Path, roots: &[PathBuf]) -> io::Result<usize> {
    let mut idx = Index::default();
    for (name, id) in scan_names(roots) {
        idx.names.entry(name).or_insert(id);
    }
    let n = idx.names.len();
    write_index(reg_root, &idx)?;
    Ok(n)
}

/// Reserve a name for a new session `id`. Caller holds the lock.
/// Refuses names that are invalid, that are already in use by a live
/// session in any root, or that equal another session's id.
pub fn reserve(
    reg_root: &Path,
    roots: &[PathBuf],
    name: &str,
    id: &str,
) -> Result<(), RegistryError> {
    if !is_valid_name(name) {
        return Err(RegistryError::BadName(name.into()));
    }
    if name == id {
        return Err(RegistryError::NameIsId(name.into()));
    }
    // A name may not equal an existing session id in any root.
    for r in roots {
        if r.join(name).exists() {
            return Err(RegistryError::NameIsId(name.into()));
        }
    }
    let mut idx = read_index(reg_root).unwrap_or_else(|| {
        // Index missing or broken: rebuild from disk before deciding.
        let mut i = Index::default();
        for (n, i2) in scan_names(roots) {
            i.names.entry(n).or_insert(i2);
        }
        i
    });
    if idx.names.contains_key(name) {
        return Err(RegistryError::Taken(name.into()));
    }
    idx.names.insert(name.into(), id.into());
    write_index(reg_root, &idx)?;
    Ok(())
}

/// Drop a name from the index. Caller holds the lock. Missing names are ok.
pub fn release(reg_root: &Path, name: &str) -> io::Result<()> {
    let Some(mut idx) = read_index(reg_root) else {
        return Ok(());
    };
    if idx.names.remove(name).is_some() {
        write_index(reg_root, &idx)?;
    }
    Ok(())
}

/// Write `name` into a session directory, mode 0600.
pub fn write_name_file(session_dir: &Path, name: &str) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(session_dir.join(NAME_FILE))?;
    writeln!(f, "{name}")
}

/// Owner uid of a path, for checks that do not go through `ensure_root`.
pub fn owner_of(p: &Path) -> io::Result<u32> {
    Ok(fs::symlink_metadata(p)?.uid())
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("invalid session name {0:?}: use letters, digits, '.', '_' or '-' (no leading '.')")]
    BadName(String),
    #[error("name {0:?} is already in use")]
    Taken(String),
    #[error("name {0:?} collides with a session id")]
    NameIsId(String),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(label: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "hisn-reg-{label}-{}-{}",
            std::process::id(),
            crate::session::random_id().unwrap()
        ));
        fs::create_dir_all(&d).unwrap();
        fs::set_permissions(&d, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        d
    }

    fn uid() -> u32 {
        fs::metadata(std::env::temp_dir()).unwrap().uid()
    }

    fn mk_session(root: &Path, id: &str, name: Option<&str>) {
        let d = root.join(id);
        fs::create_dir_all(&d).unwrap();
        if let Some(n) = name {
            write_name_file(&d, n).unwrap();
        }
    }

    #[test]
    fn reserve_then_resolve_uses_index() {
        let reg = tmp("reg");
        let r1 = tmp("r1");
        let roots = vec![r1.clone()];
        let _ = uid();
        {
            let _l = Lock::take(&reg, uid()).unwrap();
            reserve(&reg, &roots, "alpha", "abc123").unwrap();
        }
        assert_eq!(
            resolve_name(&reg, &roots, "alpha").as_deref(),
            Some("abc123")
        );
    }

    #[test]
    fn duplicate_name_is_refused() {
        let reg = tmp("reg");
        let roots = vec![tmp("r1")];
        let _l = Lock::take(&reg, uid()).unwrap();
        reserve(&reg, &roots, "alpha", "id1").unwrap();
        assert!(matches!(
            reserve(&reg, &roots, "alpha", "id2"),
            Err(RegistryError::Taken(_))
        ));
    }

    #[test]
    fn invalid_and_id_colliding_names_are_refused() {
        let reg = tmp("reg");
        let r1 = tmp("r1");
        let roots = vec![r1.clone()];
        let _l = Lock::take(&reg, uid()).unwrap();
        assert!(matches!(
            reserve(&reg, &roots, ".hidden", "id1"),
            Err(RegistryError::BadName(_))
        ));
        mk_session(&r1, "existingid", None);
        assert!(matches!(
            reserve(&reg, &roots, "existingid", "id2"),
            Err(RegistryError::NameIsId(_))
        ));
        assert!(matches!(
            reserve(&reg, &roots, "same", "same"),
            Err(RegistryError::NameIsId(_))
        ));
    }

    #[test]
    fn index_missing_falls_back_to_scan() {
        let reg = tmp("reg");
        let r1 = tmp("r1");
        mk_session(&r1, "id9", Some("beta"));
        let roots = vec![r1];
        assert!(read_index(&reg).is_none());
        assert_eq!(resolve_name(&reg, &roots, "beta").as_deref(), Some("id9"));
    }

    #[test]
    fn index_unparseable_falls_back_to_scan() {
        let reg = tmp("reg");
        let r1 = tmp("r1");
        mk_session(&r1, "id7", Some("gamma"));
        fs::write(reg.join(INDEX_FILE), "{not json").unwrap();
        let roots = vec![r1];
        assert!(read_index(&reg).is_none());
        assert_eq!(resolve_name(&reg, &roots, "gamma").as_deref(), Some("id7"));
    }

    #[test]
    fn repair_rebuilds_index_from_scan() {
        let reg = tmp("reg");
        let r1 = tmp("r1");
        mk_session(&r1, "id1", Some("one"));
        mk_session(&r1, "id2", None);
        let roots = vec![r1];
        let n = repair(&reg, &roots).unwrap();
        assert_eq!(n, 1);
        let idx = read_index(&reg).unwrap();
        assert_eq!(idx.names.get("one").map(String::as_str), Some("id1"));
    }

    #[test]
    fn release_drops_name() {
        let reg = tmp("reg");
        let roots = vec![tmp("r1")];
        let _l = Lock::take(&reg, uid()).unwrap();
        reserve(&reg, &roots, "gone", "idx").unwrap();
        release(&reg, "gone").unwrap();
        assert!(!read_index(&reg).unwrap().names.contains_key("gone"));
    }

    /// Two runtime roots (two XDG_RUNTIME_DIR values) must share one index,
    /// so a name cannot be taken twice by sessions in different roots.
    #[test]
    fn names_race_across_roots() {
        let reg = tmp("reg");
        let xdg_a = tmp("xdgA");
        let xdg_b = tmp("xdgB");
        let roots_a = runtime_roots_for(&xdg_a);
        let roots_b = runtime_roots_for(&xdg_b);
        {
            let _l = Lock::take(&reg, uid()).unwrap();
            reserve(&reg, &roots_a, "shared", "ida").unwrap();
        }
        // The second root sees the same index, so the same name is refused.
        let _l = Lock::take(&reg, uid()).unwrap();
        assert!(matches!(
            reserve(&reg, &roots_b, "shared", "idb"),
            Err(RegistryError::Taken(_))
        ));
        assert_eq!(
            resolve_name(&reg, &roots_b, "shared").as_deref(),
            Some("ida")
        );
    }

    fn runtime_roots_for(xdg: &Path) -> Vec<PathBuf> {
        vec![xdg.join("hisn")]
    }

    /// Crash injection between reservation and session publication: a name
    /// reserved in the index with no session directory must not block a
    /// repair, and repair must drop it.
    #[test]
    fn crash_after_reserve_is_repaired_by_scan() {
        let reg = tmp("reg");
        let r1 = tmp("r1");
        let roots = vec![r1.clone()];
        {
            let _l = Lock::take(&reg, uid()).unwrap();
            reserve(&reg, &roots, "orphan", "neverpublished").unwrap();
        }
        // Simulated crash: no session dir was published.
        let _l = Lock::take(&reg, uid()).unwrap();
        let n = repair(&reg, &roots).unwrap();
        assert_eq!(n, 0);
        assert!(!read_index(&reg).unwrap().names.contains_key("orphan"));
    }
}
