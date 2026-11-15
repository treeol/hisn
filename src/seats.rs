//! Seats with credentials and roles (0.5.1, ADR 0021): the workspace seat
//! store.
//!
//! A **seat** is a named client identity for one workspace: a name, a role
//! (`owner`, `member` or `observer`), a creation time, an optional expiry,
//! an optional revocation, and a credential. The credential is a random
//! 256-bit token shown exactly once at creation; only its SHA-256 hash is
//! stored (hex, under a `hash_algo` tag), and comparison is in constant
//! time.
//!
//! **The boundary, stated plainly (ADR 0021):** under one Unix user a seat
//! is attribution and a guard against mistakes, not a security boundary.
//! Any process of that user can omit the credential (and be the owner) or
//! read this file. Real separation comes with separate Unix users.
//!
//! The store is `seats.json` in the workspace state directory (dir 0700 via
//! [`crate::workspace`], file 0600), never inside a session's view. Writes
//! are read-modify-write under a `seats.lock` flock, published atomically
//! (tmp + rename), so concurrent writers do not lose updates. A truncated
//! or corrupt store **fails closed for credentials** — no seat verifies —
//! and **never for the owner without a credential** (a client that sends no
//! credential does not read this file at all).

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::workspace;

pub const STORE_FILE: &str = "seats.json";
pub const LOCK_FILE: &str = "seats.lock";
const HASH_ALGO: &str = "sha256";
const STORE_V: u32 = 1;
/// Token length in bytes (256 bits, decision D).
pub const TOKEN_BYTES: usize = 32;

/// The roles (decision E), smallest useful set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Member,
    Observer,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Member => "member",
            Role::Observer => "observer",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "owner" => Some(Role::Owner),
            "member" => Some(Role::Member),
            "observer" => Some(Role::Observer),
            _ => None,
        }
    }
}

/// One seat, without its credential (the hash of the credential is in the
/// store, never the credential itself).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seat {
    pub name: String,
    pub role: Role,
    pub created: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default)]
    pub revoked: bool,
    pub hash: String,
}

/// The on-disk store.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoreFile {
    v: u32,
    hash_algo: String,
    seats: Vec<Seat>,
}

/// The verified identity of one presented credential: `<name>` acting with
/// `<role>`. Carried in the client record as the seat name and role; the
/// credential itself never is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatIdentity {
    pub name: String,
    pub role: Role,
}

/// What a credential check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeatVerdict {
    /// The credential matched a live, unexpired seat.
    Found(SeatIdentity),
    /// The credential matched a seat that was revoked.
    Revoked,
    /// The credential matched a seat past its expiry.
    Expired,
    /// No seat in the store has this credential's hash.
    Unknown,
}

fn store_path(dir: &Path) -> PathBuf {
    dir.join(STORE_FILE)
}

fn lock_path(dir: &Path) -> PathBuf {
    dir.join(LOCK_FILE)
}

/// Hash a credential for storage/comparison: SHA-256, hex.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Constant-time equality over equal-length inputs (a hash is always 64
/// hex chars; the length itself is not secret).
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// A fresh 256-bit credential, hex (64 chars). Reads `/dev/urandom`.
pub fn new_token() -> std::io::Result<String> {
    let mut buf = [0u8; TOKEN_BYTES];
    fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(hex(&buf))
}

/// A seat name: the session-name charset, and never a name a client label
/// could already mean (`local`, `hisn-internal`, or `<login>@<ip>`).
pub fn valid_name(name: &str) -> bool {
    crate::policy::is_valid_session_id(name)
        && !matches!(name, "local" | "hisn-internal")
        && !name.contains('@')
}

/// The `(mtime, len)` stamp of the store file, for cheap change detection.
/// `None` when the file does not exist or cannot be stat'ed.
pub fn store_stamp(dir: &Path) -> Option<(std::time::SystemTime, u64)> {
    let md = fs::metadata(store_path(dir)).ok()?;
    Some((md.modified().ok()?, md.len()))
}

/// Read and parse the store. `None` when the file is absent (an empty
/// store, not an error); `Err` when it is present but unreadable or
/// corrupt. Callers that verify credentials treat `Err` as an empty set
/// (fail closed); callers that manage seats surface it.
pub fn load(dir: &Path) -> Result<Option<Vec<Seat>>, String> {
    let path = store_path(dir);
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    if bytes.is_empty() {
        return Err(format!("{}: empty file", path.display()));
    }
    let store: StoreFile = serde_json::from_slice(&bytes)
        .map_err(|e| format!("{}: corrupt store ({e})", path.display()))?;
    if store.v != STORE_V || store.hash_algo != HASH_ALGO {
        return Err(format!(
            "{}: unsupported store version (v={}, hash_algo={})",
            path.display(),
            store.v,
            store.hash_algo
        ));
    }
    Ok(Some(store.seats))
}

/// Every seat in the store, sorted by name. Empty when the store is
/// absent **or corrupt** (fail closed for credentials).
pub fn seats(dir: &Path) -> Vec<Seat> {
    load(dir).unwrap_or(None).unwrap_or_default()
}

/// Verify a presented credential against the store.
pub fn verify(dir: &Path, token: &str) -> SeatVerdict {
    let want = hash_token(token);
    let now = crate::session::rfc3339_now();
    for seat in seats(dir) {
        if constant_time_eq(&seat.hash, &want) {
            if seat.revoked {
                return SeatVerdict::Revoked;
            }
            if let Some(exp) = &seat.expires
                && now.as_str() >= exp.as_str()
            {
                return SeatVerdict::Expired;
            }
            return SeatVerdict::Found(SeatIdentity {
                name: seat.name,
                role: seat.role,
            });
        }
    }
    SeatVerdict::Unknown
}

/// A read-modify-write under the store flock. The closure mutates the seat
/// list; publication is atomic (tmp + rename). A corrupt store makes the
/// write fail rather than overwrite (fail closed).
fn with_lock<F>(dir: &Path, f: F) -> Result<Vec<Seat>, String>
where
    F: FnOnce(&mut Vec<Seat>) -> Result<(), String>,
{
    workspace::ensure_workspace(dir).map_err(|e| format!("{}", e))?;
    let lock = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(lock_path(dir))
        .map_err(|e| format!("{}: {e}", lock_path(dir).display()))?;
    {
        use std::os::fd::AsRawFd;
        // SAFETY: `lock` is a file we opened and hold for the guard's life.
        unsafe {
            if libc::flock(lock.as_raw_fd(), libc::LOCK_EX) != 0 {
                return Err(format!(
                    "locking {}: {}",
                    lock_path(dir).display(),
                    std::io::Error::last_os_error()
                ));
            }
        }
    }
    let mut cur = load(dir)?.unwrap_or_default();
    f(&mut cur)?;
    let store = StoreFile {
        v: STORE_V,
        hash_algo: HASH_ALGO.to_string(),
        seats: cur.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&store).map_err(|e| e.to_string())?;
    let tmp = dir.join(format!(".seats.json.tmp-{}", std::process::id()));
    {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
    }
    fs::rename(&tmp, store_path(dir)).map_err(|e| format!("{}: {e}", store_path(dir).display()))?;
    Ok(cur)
}

/// Create a seat: returns the credential, shown once and never stored.
/// Fails when the name is taken (a revoked name must be revoked-then-added:
/// `add` over a revoked name creates a fresh seat with a fresh token).
pub fn add(dir: &Path, name: &str, role: Role, expires: Option<String>) -> Result<String, String> {
    if !valid_name(name) {
        return Err(format!(
            "invalid seat name {name:?}: letters, digits, '.', '_' or '-', no leading '.', not 'local' or 'hisn-internal'"
        ));
    }
    let token = new_token().map_err(|e| format!("generating a credential: {e}"))?;
    let hash = hash_token(&token);
    with_lock(dir, |cur| {
        if cur.iter().any(|s| s.name == name && !s.revoked) {
            return Err(format!("seat {name} already exists"));
        }
        cur.retain(|s| s.name != name);
        cur.push(Seat {
            name: name.to_string(),
            role,
            created: crate::session::rfc3339_now(),
            expires,
            revoked: false,
            hash: hash.clone(),
        });
        cur.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(())
    })?;
    Ok(token)
}

/// Change a seat's role. Fails for an unknown or revoked seat.
pub fn set_role(dir: &Path, name: &str, role: Role) -> Result<(), String> {
    with_lock(dir, |cur| {
        let seat = cur
            .iter_mut()
            .find(|s| s.name == name && !s.revoked)
            .ok_or_else(|| format!("no live seat {name}"))?;
        seat.role = role;
        Ok(())
    })
    .map(|_| ())
}

/// Revoke a seat. The record stays (with its creation time), so the journal
/// can distinguish a revoked seat's history from a re-created one.
pub fn revoke(dir: &Path, name: &str) -> Result<(), String> {
    with_lock(dir, |cur| {
        let seat = cur
            .iter_mut()
            .find(|s| s.name == name && !s.revoked)
            .ok_or_else(|| format!("no live seat {name}"))?;
        seat.revoked = true;
        Ok(())
    })
    .map(|_| ())
}

/// The public view of the store for `ls --json` and `seat ls`: name, role,
/// creation time, expiry, revocation. Never a hash, never a credential.
#[derive(Debug, Clone, Serialize)]
pub struct SeatView {
    pub name: String,
    pub role: String,
    pub created: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    pub revoked: bool,
}

pub fn views(dir: &Path) -> Vec<SeatView> {
    seats(dir)
        .into_iter()
        .map(|s| SeatView {
            name: s.name,
            role: s.role.as_str().to_string(),
            created: s.created,
            expires: s.expires,
            revoked: s.revoked,
        })
        .collect()
}

/// The set of seats a supervisor last read, with the stamp it read them at.
/// Reloads only when the stamp changes; a stat failure clears the set
/// (fails closed for credentials).
#[derive(Debug, Default)]
pub struct SeatCache {
    seats: BTreeMap<String, Seat>,
    stamp: Option<(std::time::SystemTime, u64)>,
}

impl SeatCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// The current seat set, reloaded from `dir` only when the store's stamp
    /// changed since the last read. Returns `true` when the set changed.
    pub fn refresh(&mut self, dir: &Path) -> bool {
        let stamp = store_stamp(dir);
        if stamp != self.stamp {
            self.stamp = stamp;
            self.seats = seats(dir)
                .into_iter()
                .map(|s| (s.name.clone(), s))
                .collect();
            true
        } else {
            false
        }
    }

    pub fn as_slice(&self) -> Vec<Seat> {
        self.seats.values().cloned().collect()
    }

    pub fn get(&self, name: &str) -> Option<&Seat> {
        self.seats.get(name)
    }

    pub fn values(&self) -> impl Iterator<Item = &Seat> {
        self.seats.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn ws() -> (tempfile::TempDir, PathBuf) {
        let d = dir();
        let p = d.path().join("ws");
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        (d, p)
    }

    #[test]
    fn role_round_trip() {
        for (s, r) in [
            ("owner", Role::Owner),
            ("member", Role::Member),
            ("observer", Role::Observer),
        ] {
            assert_eq!(Role::parse(s), Some(r));
            assert_eq!(r.as_str(), s);
        }
        assert_eq!(Role::parse("admin"), None);
    }

    #[test]
    fn hash_is_stable_and_constant_time_eq_behaves() {
        let h = hash_token("a credential");
        assert_eq!(h.len(), 64);
        assert_eq!(h, hash_token("a credential"));
        assert_ne!(h, hash_token("another credential"));
        assert!(constant_time_eq(&h, &h));
        assert!(!constant_time_eq(&h, &hash_token("another credential")));
        assert!(!constant_time_eq("short", "shorter"));
    }

    #[test]
    fn name_rules() {
        assert!(valid_name("agent-1"));
        assert!(valid_name("a.b_c"));
        assert!(!valid_name(""));
        assert!(!valid_name(".hidden"));
        assert!(!valid_name("local"));
        assert!(!valid_name("hisn-internal"));
        assert!(!valid_name("a/b"));
    }

    #[test]
    fn add_verify_set_role_revoke() {
        let (_t, d) = ws();
        let token = add(&d, "bob", Role::Member, None).unwrap();
        assert_eq!(token.len(), 64);
        assert_eq!(
            verify(&d, &token),
            SeatVerdict::Found(SeatIdentity {
                name: "bob".into(),
                role: Role::Member
            })
        );
        // The credential is not in the file.
        let text = fs::read_to_string(store_path(&d)).unwrap();
        assert!(
            !text.contains(&token),
            "the store must not hold the credential"
        );
        assert!(text.contains(&hash_token(&token)));
        // An unknown token is refused, never owner.
        assert_eq!(verify(&d, &"0".repeat(64)), SeatVerdict::Unknown);
        // A duplicate live name is refused.
        assert!(add(&d, "bob", Role::Observer, None).is_err());
        // set-role takes effect.
        set_role(&d, "bob", Role::Owner).unwrap();
        assert_eq!(
            verify(&d, &token),
            SeatVerdict::Found(SeatIdentity {
                name: "bob".into(),
                role: Role::Owner
            })
        );
        // Revocation refuses the same token.
        revoke(&d, "bob").unwrap();
        assert_eq!(verify(&d, &token), SeatVerdict::Revoked);
        // A revoked name can be re-added as a fresh seat with a fresh token.
        let token2 = add(&d, "bob", Role::Observer, None).unwrap();
        assert_ne!(token, token2);
        assert_eq!(verify(&d, &token2).found_role(), Some(Role::Observer));
        assert_eq!(verify(&d, &token), SeatVerdict::Unknown);
    }

    impl SeatVerdict {
        fn found_role(&self) -> Option<Role> {
            match self {
                SeatVerdict::Found(id) => Some(id.role),
                _ => None,
            }
        }
    }

    #[test]
    fn expired_is_refused() {
        let (_t, d) = ws();
        // An expiry in the past: refused even though the token is right.
        let token = add(&d, "old", Role::Member, Some("2000-01-01T00:00:00Z".into())).unwrap();
        assert_eq!(verify(&d, &token), SeatVerdict::Expired);
        // An expiry far in the future: accepted.
        let token = add(
            &d,
            "fresh",
            Role::Member,
            Some("2999-01-01T00:00:00Z".into()),
        )
        .unwrap();
        assert!(matches!(verify(&d, &token), SeatVerdict::Found(_)));
    }

    #[test]
    fn corrupt_store_fails_closed() {
        let (_t, d) = ws();
        // Truncated / corrupt / empty stores verify nothing.
        for bytes in [&b"{"[..], b"not json", b"", b"[]"] {
            fs::write(store_path(&d), bytes).unwrap();
            assert_eq!(verify(&d, &"0".repeat(64)), SeatVerdict::Unknown);
            assert!(views(&d).is_empty());
        }
        // A store written by a newer schema version also fails closed.
        fs::write(
            store_path(&d),
            r#"{"v":99,"hash_algo":"sha256","seats":[]}"#,
        )
        .unwrap();
        assert_eq!(verify(&d, &"0".repeat(64)), SeatVerdict::Unknown);
    }

    #[test]
    fn mode_is_0600_and_views_carry_no_hash() {
        use std::os::unix::fs::PermissionsExt;
        let (_t, d) = ws();
        let token = add(&d, "bob", Role::Member, None).unwrap();
        let md = fs::metadata(store_path(&d)).unwrap();
        assert_eq!(md.permissions().mode() & 0o777, 0o600);
        let raw = fs::read_to_string(store_path(&d)).unwrap();
        assert!(!raw.contains(&token));
        for v in views(&d) {
            let s = serde_json::to_string(&v).unwrap();
            assert!(!s.contains("hash"), "{s}");
            assert!(!s.contains(&token));
        }
    }

    #[test]
    fn concurrent_writers_do_not_lose_updates() {
        let (_t, d) = ws();
        let p = d.clone();
        std::thread::scope(|scope| {
            for i in 0..8 {
                let p = p.clone();
                scope.spawn(move || {
                    add(&p, &format!("seat-{i}"), Role::Member, None).unwrap();
                });
            }
        });
        assert_eq!(seats(&d).len(), 8);
    }

    #[test]
    fn cache_reloads_only_on_stamp_change() {
        let (_t, d) = ws();
        let mut cache = SeatCache::new();
        cache.refresh(&d);
        assert!(cache.as_slice().is_empty());
        let token = add(&d, "bob", Role::Member, None).unwrap();
        cache.refresh(&d);
        assert_eq!(cache.as_slice().len(), 1);
        let _ = token;
    }
}
