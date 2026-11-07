//! `session.json` (`hisn-session/v1`): the per-session metadata record.
//!
//! Written once, at creation, inside the `.tmp-<id>` directory before it is
//! published. Its `state` is the lifecycle field (0.4.0 step 1, decision #6):
//!
//! - `creating`: the `.tmp-<id>` directory, before publication;
//! - `running`:  published, supervisor alive;
//! - `stopping`: a stop was requested and the sandbox is being torn down;
//! - `stopped`:  orderly end (explicit stop or idle expiry); dir kept;
//! - `crashed`:  reported by `ls`, never written: dir present, supervisor
//!   dead, state not `stopped` (what `session::is_stale` detects).
//!
//! `members` (append-only, 0.4.0 step 3) and `lease` (step 5) are optional so
//! old `session.json` files load unchanged when the fields are absent.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "hisn-session/v1";
pub const FILE: &str = "session.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Creating,
    Running,
    Stopping,
    Stopped,
    Crashed,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Creating => "creating",
            State::Running => "running",
            State::Stopping => "stopping",
            State::Stopped => "stopped",
            State::Crashed => "crashed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Owner {
    pub uid: u32,
    pub label: String,
    pub client_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Created {
    pub ts: String,
    pub by: String,
}

/// A client that has attached or exec'd into the session. Append-only in
/// `session.json`; `last_seen` is updated at most once per 60 s (step 3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Member {
    pub uid: u32,
    pub label: String,
    pub first_seen: String,
    pub last_seen: String,
}

/// Lease state for idle expiry (step 5). Absent on sessions created before
/// the lease field existed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Lease {
    pub idle_timeout_s: Option<u64>,
    pub last_activity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionMeta {
    pub schema: String,
    pub id: String,
    pub name: Option<String>,
    pub owner: Owner,
    pub created: Created,
    pub cwd: String,
    pub rootfs: Option<String>,
    pub network: String,
    pub state: State,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<Member>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<Lease>,
    /// Session env snapshot: keys declared at `run --env K=V` (0.4.0 step 4).
    /// Values matching `looks_secret` are stored as `"<redacted>"` on disk;
    /// the real values are held in supervisor memory.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env_declared: std::collections::BTreeMap<String, String>,
}

impl SessionMeta {
    pub fn new(id: &str, name: Option<&str>, owner: Owner, cwd: &str, network: &str) -> Self {
        Self {
            schema: SCHEMA.into(),
            id: id.into(),
            name: name.map(str::to_owned),
            created: Created {
                ts: crate::session::rfc3339_now(),
                by: owner.label.clone(),
            },
            owner,
            cwd: cwd.into(),
            rootfs: None,
            network: network.into(),
            state: State::Creating,
            members: Vec::new(),
            lease: None,
            env_declared: std::collections::BTreeMap::new(),
        }
    }

    /// Write `session.json` into `dir` (mode 0600), fsync'd.
    pub fn write_to(&self, dir: &Path) -> std::io::Result<()> {
        let body = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join(FILE))?;
        f.write_all(body.as_bytes())?;
        f.sync_all()
    }
}

/// Read `session.json` from a session dir. `None` if missing or unparseable.
pub fn read(dir: &Path) -> Option<SessionMeta> {
    let text = fs::read_to_string(dir.join(FILE)).ok()?;
    serde_json::from_str(&text).ok()
}

/// Rewrite the `state` field atomically (write temp, fsync, rename).
pub fn set_state(dir: &Path, state: State) -> std::io::Result<()> {
    let mut m = read(dir).ok_or_else(|| std::io::Error::other("session.json missing"))?;
    m.state = state;
    rewrite(dir, &m)
}

/// Record a client in the members list. Append if unseen; otherwise update
/// `last_seen` and `label`. The caller is responsible for the 60 s rate
/// limit — this function always writes if called.
pub fn record_member(dir: &Path, uid: u32, label: &str, now: &str) -> std::io::Result<()> {
    let mut m = read(dir).ok_or_else(|| std::io::Error::other("session.json missing"))?;
    if let Some(mem) = m.members.iter_mut().find(|mem| mem.uid == uid) {
        mem.last_seen = now.to_owned();
        if mem.label != label {
            mem.label = label.to_owned();
        }
    } else {
        m.members.push(Member {
            uid,
            label: label.to_owned(),
            first_seen: now.to_owned(),
            last_seen: now.to_owned(),
        });
    }
    rewrite(dir, &m)
}

/// Update `last_activity` in the lease (0.4.0 step 5).
pub fn touch_lease(dir: &Path, now: &str) -> std::io::Result<()> {
    let mut m = read(dir).ok_or_else(|| std::io::Error::other("session.json missing"))?;
    if let Some(lease) = m.lease.as_mut() {
        lease.last_activity = Some(now.to_owned());
    }
    rewrite(dir, &m)
}

/// Atomically rewrite `session.json` (write temp, fsync, rename).
fn rewrite(dir: &Path, m: &SessionMeta) -> std::io::Result<()> {
    let tmp = dir.join(".session.json.tmp");
    let _ = fs::remove_file(&tmp);
    let body = serde_json::to_string_pretty(m).map_err(std::io::Error::other)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(body.as_bytes())?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, dir.join(FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> Owner {
        Owner {
            uid: 1000,
            label: "local".into(),
            client_id: "c1".into(),
        }
    }

    #[test]
    fn roundtrip_and_state_change() {
        let d = std::env::temp_dir().join(format!("hisn-meta-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let m = SessionMeta::new("abc", Some("nm"), owner(), "/w", "host");
        m.write_to(&d).unwrap();
        assert_eq!(read(&d).unwrap().state, State::Creating);
        set_state(&d, State::Running).unwrap();
        let back = read(&d).unwrap();
        assert_eq!(back.state, State::Running);
        assert_eq!(back.schema, SCHEMA);
        assert_eq!(back.name.as_deref(), Some("nm"));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn state_names_are_the_documented_set() {
        assert_eq!(State::Creating.as_str(), "creating");
        assert_eq!(State::Crashed.as_str(), "crashed");
    }

    #[test]
    fn record_member_appends_and_updates() {
        let d = std::env::temp_dir().join(format!("hisn-member-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let m = SessionMeta::new("abc", Some("nm"), owner(), "/w", "host");
        m.write_to(&d).unwrap();
        // No members initially.
        assert!(read(&d).unwrap().members.is_empty());
        // First client: appended.
        record_member(&d, 1000, "local", "2026-11-07T12:00:00Z").unwrap();
        let m1 = read(&d).unwrap();
        assert_eq!(m1.members.len(), 1);
        assert_eq!(m1.members[0].uid, 1000);
        assert_eq!(m1.members[0].label, "local");
        assert_eq!(m1.members[0].first_seen, "2026-11-07T12:00:00Z");
        // Same uid: updated, not appended.
        record_member(&d, 1000, "local", "2026-11-07T12:01:00Z").unwrap();
        let m2 = read(&d).unwrap();
        assert_eq!(m2.members.len(), 1);
        assert_eq!(m2.members[0].last_seen, "2026-11-07T12:01:00Z");
        // Different uid: appended.
        record_member(&d, 1001, "uid:1001", "2026-11-07T12:02:00Z").unwrap();
        let m3 = read(&d).unwrap();
        assert_eq!(m3.members.len(), 2);
        assert_eq!(m3.members[1].uid, 1001);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn old_json_without_members_loads() {
        let d = std::env::temp_dir().join(format!("hisn-old-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        // Write a session.json without members or lease (as 0.3 wrote it).
        let old = r#"{"schema":"hisn-session/v1","id":"abc","name":"nm","owner":{"uid":1000,"label":"local","client_id":"c1"},"created":{"ts":"2026-11-07T12:00:00Z","by":"local"},"cwd":"/w","rootfs":null,"network":"host","state":"running"}"#;
        fs::write(d.join(FILE), old).unwrap();
        let m = read(&d).unwrap();
        assert_eq!(m.members, Vec::new());
        assert_eq!(m.lease, None);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn lease_roundtrip_and_touch() {
        let d = std::env::temp_dir().join(format!("hisn-lease-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let mut m = SessionMeta::new("abc", Some("nm"), owner(), "/w", "host");
        m.lease = Some(Lease {
            idle_timeout_s: Some(300),
            last_activity: Some("2026-11-07T12:00:00Z".into()),
        });
        m.write_to(&d).unwrap();
        let back = read(&d).unwrap();
        assert_eq!(back.lease.as_ref().unwrap().idle_timeout_s, Some(300));
        // touch_lease updates last_activity.
        touch_lease(&d, "2026-11-07T12:01:00Z").unwrap();
        let m2 = read(&d).unwrap();
        assert_eq!(
            m2.lease.as_ref().unwrap().last_activity.as_deref(),
            Some("2026-11-07T12:01:00Z")
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn env_declared_roundtrip() {
        let d = std::env::temp_dir().join(format!("hisn-env-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let mut m = SessionMeta::new("abc", None, owner(), "/w", "none");
        m.env_declared.insert("GOFLAGS".into(), "-mod=mod".into());
        m.env_declared
            .insert("SECRET_TOKEN".into(), "<redacted>".into());
        m.write_to(&d).unwrap();
        let back = read(&d).unwrap();
        assert_eq!(back.env_declared.len(), 2);
        assert_eq!(back.env_declared["GOFLAGS"], "-mod=mod");
        assert_eq!(back.env_declared["SECRET_TOKEN"], "<redacted>");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn touch_lease_noop_without_lease() {
        // F5: touch_lease on a session without a lease field is a no-op
        // (the lease is None, so last_activity is not set).
        let d = std::env::temp_dir().join(format!("hisn-noop-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let m = SessionMeta::new("abc", None, owner(), "/w", "none");
        m.write_to(&d).unwrap();
        // touch_lease on a session without a lease sets last_activity if
        // the lease exists; here lease is None, so it stays None.
        touch_lease(&d, "2026-11-07T12:00:00Z").unwrap();
        let back = read(&d).unwrap();
        assert_eq!(
            back.lease, None,
            "lease must stay None without idle_timeout"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn session_json_writes_are_serialised() {
        // F5: the rewrite function uses a fixed .session.json.tmp name with
        // create_new(true). Two concurrent calls would race on the tmp name.
        // The caller (Shared) holds session_json_lock; this test just
        // verifies record_member and touch_lease can both be called
        // sequentially without error.
        let d = std::env::temp_dir().join(format!("hisn-serial-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let mut m = SessionMeta::new("abc", None, owner(), "/w", "none");
        m.lease = Some(Lease {
            idle_timeout_s: Some(300),
            last_activity: Some("2026-11-07T12:00:00Z".into()),
        });
        m.write_to(&d).unwrap();
        record_member(&d, 1000, "local", "2026-11-07T12:00:00Z").unwrap();
        touch_lease(&d, "2026-11-07T12:00:05Z").unwrap();
        let back = read(&d).unwrap();
        assert_eq!(back.members.len(), 1);
        assert_eq!(
            back.lease.as_ref().unwrap().last_activity.as_deref(),
            Some("2026-11-07T12:00:05Z")
        );
        fs::remove_dir_all(&d).unwrap();
    }
}
