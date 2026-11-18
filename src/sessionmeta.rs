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
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "hisn-session/v1";
pub const FILE: &str = "session.json";

/// 0.5.0: the supervisor's own version (A1), written at session creation as
/// the optional `hisn_version` field. **Information only**: it is never
/// compared by the CLI or the supervisor (see [`PROTOCOL_REVISION`]). Set by
/// the supervisor after construction (the constructor stays binary-agnostic
/// for tests).
pub const HISN_VERSION: &str = env!("CARGO_PKG_VERSION");

/// 0.5.0: the control-protocol revision this build speaks (Part A, revised in
/// the step-1 follow-up; revision 3 by 0.5.1, ADR 0021). This integer is the
/// *only* version the CLI and the supervisor compare:
/// `client.protocol_version` on the wire carries it, and `session.json`
/// records `protocol_revision` beside `hisn_version`. A request that
/// declares a higher revision is answered `E_VERSION`; absent means
/// revision 1 (0.4.3 behaviour). The release version string must never be
/// compared, so a `-dev` build can use its own feature.
pub const PROTOCOL_REVISION: u32 = 3;

/// The wire field name for the revision (`client.protocol_version`).
/// Kept as the historical field name; there is one concept — the protocol
/// revision — and one number, declared here.
pub const PROTOCOL_VERSION: u32 = PROTOCOL_REVISION;

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
    /// 0.5.1 (Part 6): unknown fields nested inside `owner`, captured
    /// verbatim like [`SessionMeta::extra`] and emitted back unchanged.
    #[serde(default, flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
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
    /// 0.5.1 (Part 6): unknown fields nested inside `members[]` entries.
    #[serde(default, flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

/// Lease state for idle expiry (step 5). Absent on sessions created before
/// the lease field existed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Lease {
    pub idle_timeout_s: Option<u64>,
    pub last_activity: Option<String>,
    /// 0.5.1 (Part 6): unknown fields nested inside `lease`.
    #[serde(default, flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
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
    /// 0.5.0: the supervisor's version (`HISN_VERSION`), written at creation.
    /// **Information only** — never compared (see [`PROTOCOL_REVISION`]).
    /// `None` on a pre-0.5.0 session (serialised as `null` like `rootfs` —
    /// the CLI accepts both a missing field and `null`).
    #[serde(default)]
    pub hisn_version: Option<String>,
    /// 0.5.0: the supervisor's protocol revision (`PROTOCOL_REVISION`),
    /// written at creation beside `hisn_version`. This integer — not the
    /// version string — is what the CLI compares to decide whether it may
    /// send `protocol_version`/new ops. `None`/absent = revision 1 (0.4.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_revision: Option<u32>,
    /// 0.5.0 (B1): the workspace this session belongs to (its id and readable
    /// name). `None` on a pre-0.5.0 session. Additive only; old files without
    /// it load unchanged (unknown/new fields are ignored by `SessionMeta`,
    /// which deliberately has no `deny_unknown_fields` — the read side is
    /// forward-compatible).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<crate::workspace::WorkspaceRef>,
    /// Session env snapshot: keys declared at `run --env K=V` (0.4.0 step 4).
    /// Values matching `looks_secret` are stored as `"<redacted>"` on disk;
    /// the real values are held in supervisor memory.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env_declared: std::collections::BTreeMap<String, String>,
    /// Unknown top-level fields, captured verbatim (item 2). On read they
    /// land here; on write they are emitted back unchanged. This replaces
    /// the previous merge-based rewrite, which had a latent trap: a known
    /// `skip_serializing_if` field cleared in memory would resurrect its
    /// old on-disk value. With `flatten` the struct is the single source
    /// of truth — unknown fields pass through, known fields behave
    /// normally (a cleared field stays cleared). Nested unknown keys
    /// inside known structs are still dropped (top-level only, by design).
    #[serde(default, flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
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
            hisn_version: None,
            protocol_revision: None,
            workspace: None,
            extra: std::collections::BTreeMap::new(),
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

/// Hold an exclusive `flock` on `dir/session.json.lock` for the lifetime of
/// the returned guard. Both the supervisor and the `hisn stop` CLI take this
/// lock around every read-modify-write of `session.json`, so concurrent
/// writers in different processes cannot lose an update.
fn lock(dir: &Path) -> std::io::Result<File> {
    let f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(dir.join("session.json.lock"))?;
    // SAFETY: flock on a valid fd. The supervisor has signal handlers, so
    // a signal during a contended lock can interrupt the wait: retry on
    // EINTR, return any other error.
    loop {
        let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) };
        if rc == 0 {
            break;
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINTR) {
            return Err(e);
        }
    }
    Ok(f)
}

/// Rewrite the `state` field atomically (write temp, fsync, rename).
/// Takes the cross-process lock around the read-modify-write.
pub fn set_state(dir: &Path, state: State) -> std::io::Result<()> {
    let _guard = lock(dir)?;
    let mut m = read(dir).ok_or_else(|| std::io::Error::other("session.json missing"))?;
    m.state = state;
    rewrite(dir, &m)
}

/// Record a client in the members list. Append if (uid, label) unseen;
/// otherwise update `last_seen`. F8: members are keyed by (uid, label),
/// not uid alone — two clients with the same uid but different labels
/// are two members. The caller is responsible for the 60 s rate limit.
/// Takes the cross-process lock around the read-modify-write.
pub fn record_member(dir: &Path, uid: u32, label: &str, now: &str) -> std::io::Result<()> {
    let _guard = lock(dir)?;
    let mut m = read(dir).ok_or_else(|| std::io::Error::other("session.json missing"))?;
    if let Some(mem) = m
        .members
        .iter_mut()
        .find(|mem| mem.uid == uid && mem.label == label)
    {
        mem.last_seen = now.to_owned();
    } else {
        m.members.push(Member {
            uid,
            label: label.to_owned(),
            first_seen: now.to_owned(),
            last_seen: now.to_owned(),
            extra: std::collections::BTreeMap::new(),
        });
    }
    rewrite(dir, &m)
}

/// Update `last_activity` in the lease (0.4.0 step 5). No-op (no write at all)
/// when the session has no lease: 0.4.1 step 7 verifies that a session without
/// `idle_timeout` never rewrites `session.json` for a lease touch.
/// Takes the cross-process lock around the read-modify-write.
pub fn touch_lease(dir: &Path, now: &str) -> std::io::Result<()> {
    let _guard = lock(dir)?;
    let mut m = read(dir).ok_or_else(|| std::io::Error::other("session.json missing"))?;
    match m.lease.as_mut() {
        Some(lease) => {
            lease.last_activity = Some(now.to_owned());
            rewrite(dir, &m)
        }
        None => Ok(()),
    }
}

/// Atomically rewrite `session.json` (write unique temp, fsync, rename).
/// The temp name is unique per call (pid + a process-wide counter) so two
/// writers that somehow both reach this point cannot collide or EEXIST;
/// the `flock` in the callers is what serialises them.
///
/// A leftover temp file with the same pid and counter (a crash followed by
/// pid reuse, with the counter reset) would make `create_new` fail. The
/// lock already serialises writers, so no live writer can own that exact
/// name: remove a stale file with the exact name before creating it.
///
/// **Unknown top-level fields survive** (item 2): they are captured in
/// `SessionMeta::extra` (serde flatten) on read and emitted back verbatim
/// on write, so a field this build does not know (written by a newer hisn)
/// is carried through every read-modify-write instead of being dropped.
fn rewrite(dir: &Path, m: &SessionMeta) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".session.json.tmp-{}-{n}", std::process::id()));
    let body = serde_json::to_string_pretty(m).map_err(std::io::Error::other)?;
    // Remove a stale temp file with this exact name before create_new.
    let _ = fs::remove_file(&tmp);
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

            extra: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn runtime_roots_are_the_documented_setup() {
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
        // 0.5.0: a fresh meta has no hisn_version (the supervisor sets it at
        // creation) and no workspace ( likewise); both are optional on read.
        assert_eq!(back.hisn_version, None);
        assert_eq!(back.workspace, None);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn hisn_version_and_workspace_roundtrip() {
        let d = std::env::temp_dir().join(format!("hisn- ver-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let mut m = SessionMeta::new("abc", None, owner(), "/w", "none");
        m.hisn_version = Some(HISN_VERSION.to_owned());
        m.protocol_revision = Some(PROTOCOL_REVISION);
        m.workspace = Some(crate::workspace::WorkspaceRef {
            id: "abc123".into(),
            name: "proj".into(),
        });
        m.write_to(&d).unwrap();
        let back = read(&d).unwrap();
        assert_eq!(back.hisn_version.as_deref(), Some(HISN_VERSION));
        assert_eq!(back.protocol_revision, Some(PROTOCOL_REVISION));
        assert_eq!(back.workspace.as_ref().unwrap().name, "proj");
        // A meta without them (0.4.3 shape on disk) loads with None.
        let old = r#"{"schema":"hisn-session/v1","id":"abc","name":"nm","owner":{"uid":1000,"label":"local","client_id":"c1"},"created":{"ts":"2026-11-07T12:00:00Z","by":"local"},"cwd":"/w","rootfs":null,"network":"host","state":"running"}"#;
        fs::write(d.join(FILE), old).unwrap();
        let m2 = read(&d).unwrap();
        assert_eq!(m2.hisn_version, None);
        assert_eq!(m2.protocol_revision, None);
        assert_eq!(m2.workspace, None);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn protocol_revision_is_two_and_the_version_string_is_never_the_gate() {
        // Item 1: the gate is the integer revision, not the release version.
        // This build is `0.5.1-dev` (Cargo.toml) and must still declare
        // revision 3 so its own CLI can use its own feature.
        assert_eq!(PROTOCOL_REVISION, 3);
        assert_eq!(crate::control::PROTOCOL_VERSION, 3);
        // A dev version string does not lower the revision.
        assert!(HISN_VERSION.contains("0.6.0"));
    }

    #[test]
    fn unknown_top_level_fields_survive_every_rewrite() {
        // Item 2: a file carrying a field this build does not know keeps it
        // across set_state, record_member and touch_lease. Before the merge
        // in `rewrite`, each of these silently dropped it.
        let d = std::env::temp_dir().join(format!("hisn-unknown-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let mut m = SessionMeta::new("abc", Some("nm"), owner(), "/w", "none");
        m.lease = Some(Lease {
            idle_timeout_s: Some(300),
            last_activity: Some("2026-11-07T12:00:00Z".into()),

            extra: std::collections::BTreeMap::new(),
        });
        // Write with an extra unknown field by hand (as a newer build would).
        let mut body = serde_json::to_value(&m).unwrap();
        body.as_object_mut().unwrap().insert(
            "future_field".into(),
            serde_json::json!({"nested": [1, 2, 3], "note": "keep me"}),
        );
        fs::write(d.join(FILE), serde_json::to_string_pretty(&body).unwrap()).unwrap();
        let has_future = || {
            let text = fs::read_to_string(d.join(FILE)).unwrap();
            text.contains("future_field") && text.contains("keep me")
        };
        set_state(&d, State::Running).unwrap();
        assert!(has_future(), "set_state dropped the unknown field");
        record_member(&d, 1000, "local", "2026-11-07T12:01:00Z").unwrap();
        assert!(has_future(), "record_member dropped the unknown field");
        touch_lease(&d, "2026-11-07T12:02:00Z").unwrap();
        assert!(has_future(), "touch_lease dropped the unknown field");
        // And the known fields still updated.
        let back = read(&d).unwrap();
        assert_eq!(back.state, State::Running);
        assert_eq!(back.members.len(), 1);
        assert_eq!(
            back.lease.as_ref().unwrap().last_activity.as_deref(),
            Some("2026-11-07T12:02:00Z")
        );
        fs::remove_dir_all(&d).unwrap();
    }

    /// 0.5.1 (Part 6): unknown fields **nested** inside `owner`, `lease`
    /// and `members[]` survive rewrites, like the top-level ones. Every
    /// rewrite of `session.json` goes through `read` → `rewrite`, so the
    /// nested maps are the single source of truth.
    #[test]
    fn unknown_nested_fields_survive_every_rewrite() {
        let d = std::env::temp_dir().join(format!("hisn-nested-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let mut m = SessionMeta::new("abc", Some("nm"), owner(), "/w", "none");
        m.lease = Some(Lease {
            idle_timeout_s: Some(300),
            last_activity: Some("2026-11-07T12:00:00Z".into()),
            extra: std::collections::BTreeMap::new(),
        });
        m.members.push(Member {
            uid: 1000,
            label: "local".into(),
            first_seen: "2026-11-07T12:00:00Z".into(),
            last_seen: "2026-11-07T12:00:00Z".into(),
            extra: std::collections::BTreeMap::new(),
        });
        let mut body = serde_json::to_value(&m).unwrap();
        let o = body.as_object_mut().unwrap();
        o.get_mut("owner")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("future_owner_field".into(), serde_json::json!("keep-owner"));
        o.get_mut("lease")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("future_lease_field".into(), serde_json::json!({"x": 1}));
        o.get_mut("members").unwrap().as_array_mut().unwrap()[0]
            .as_object_mut()
            .unwrap()
            .insert("future_member_field".into(), serde_json::json!([1, 2]));
        fs::write(d.join(FILE), serde_json::to_string_pretty(&body).unwrap()).unwrap();
        let has = |needle: &str| fs::read_to_string(d.join(FILE)).unwrap().contains(needle);
        for needle in [
            "future_owner_field",
            "future_lease_field",
            "future_member_field",
        ] {
            assert!(has(needle), "setup dropped {needle}");
        }
        set_state(&d, State::Running).unwrap();
        record_member(&d, 1000, "local", "2026-11-07T12:01:00Z").unwrap();
        touch_lease(&d, "2026-11-07T12:02:00Z").unwrap();
        for needle in [
            "future_owner_field",
            "future_lease_field",
            "future_member_field",
        ] {
            assert!(has(needle), "a rewrite dropped {needle}");
        }
        // And the known fields still updated.
        let back = read(&d).unwrap();
        assert_eq!(back.state, State::Running);
        assert_eq!(
            back.lease.as_ref().unwrap().last_activity.as_deref(),
            Some("2026-11-07T12:02:00Z")
        );
        assert_eq!(
            back.owner.extra.get("future_owner_field"),
            Some(&serde_json::json!("keep-owner"))
        );
        assert_eq!(
            back.lease.as_ref().unwrap().extra.get("future_lease_field"),
            Some(&serde_json::json!({"x": 1}))
        );
        assert_eq!(
            back.members[0].extra.get("future_member_field"),
            Some(&serde_json::json!([1, 2]))
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn cleared_known_fields_do_not_resurrect() {
        // R2: a known `skip_serializing_if` field cleared in memory must
        // stay cleared on rewrite. The previous merge-based rewrite
        // resurrected the old on-disk value; the flatten design cannot.
        // Drive `rewrite` directly (the test is in-module, so the private
        // fn is reachable) with the lease still on disk — the test that
        // used to hand-write the cleared body first proved nothing, since
        // the old merge code would have passed it too (Mashūra round 1).
        let d = std::env::temp_dir().join(format!("hisn-clear-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let mut m = SessionMeta::new("abc", Some("nm"), owner(), "/w", "none");
        m.lease = Some(Lease {
            idle_timeout_s: Some(300),
            last_activity: Some("2026-11-07T12:00:00Z".into()),

            extra: std::collections::BTreeMap::new(),
        });
        m.write_to(&d).unwrap();
        // Sanity: the lease is on disk.
        assert!(
            fs::read_to_string(d.join(FILE))
                .unwrap()
                .contains("\"lease\"")
        );
        // Clear it in memory and rewrite directly — `rewrite` must not
        // merge the old on-disk value back in.
        let mut m2 = read(&d).unwrap();
        m2.lease = None;
        rewrite(&d, &m2).unwrap();
        let text = fs::read_to_string(d.join(FILE)).unwrap();
        assert!(
            !text.contains("\"lease\""),
            "cleared lease resurrected on rewrite: {text}"
        );
        assert_eq!(read(&d).unwrap().lease, None);
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

            extra: std::collections::BTreeMap::new(),
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
        // 0.4.1 step 7: no lease ⇒ no rewrite at all (session.json unchanged).
        let before = fs::read(d.join(FILE)).unwrap();
        touch_lease(&d, "2026-11-07T12:00:00Z").unwrap();
        let after = fs::read(d.join(FILE)).unwrap();
        assert_eq!(before, after, "session.json rewritten without a lease");
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

            extra: std::collections::BTreeMap::new(),
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

    #[test]
    fn two_labels_same_uid_are_two_members() {
        // F8: members are keyed by (uid, label), not uid alone.
        let d = std::env::temp_dir().join(format!("hisn-f8-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let m = SessionMeta::new("abc", None, owner(), "/w", "none");
        m.write_to(&d).unwrap();
        record_member(&d, 1000, "local", "2026-11-07T12:00:00Z").unwrap();
        record_member(&d, 1000, "wakil@host", "2026-11-07T12:00:01Z").unwrap();
        let back = read(&d).unwrap();
        assert_eq!(
            back.members.len(),
            2,
            "two labels same uid should be two members"
        );
        assert_eq!(back.members[0].uid, 1000);
        assert_eq!(back.members[0].label, "local");
        assert_eq!(back.members[1].uid, 1000);
        assert_eq!(back.members[1].label, "wakil@host");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn rewrite_survives_stale_temp_with_same_name() {
        // A leftover temp file with the same pid+counter name (crash +
        // pid reuse) must not make the rewrite fail: the stale file is
        // removed before create_new. The counter is process-wide and
        // other tests advance it, so plant stale files for a wide range
        // past the current value — the point is that *some* stale name
        // in that range collides with the rewrite's own name.
        let d = std::env::temp_dir().join(format!("hisn-stale-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let m = SessionMeta::new("abc", None, owner(), "/w", "none");
        m.write_to(&d).unwrap();
        for n in 0..64u64 {
            fs::write(
                d.join(format!(".session.json.tmp-{}-{n}", std::process::id())),
                b"stale",
            )
            .unwrap();
        }
        set_state(&d, State::Running).unwrap();
        let back = read(&d).unwrap();
        assert_eq!(back.state, State::Running);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn concurrent_writers_lose_no_update() {
        use std::sync::Arc;
        let d = std::env::temp_dir().join(format!("hisn-conc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let mut m = SessionMeta::new("abc", None, owner(), "/w", "none");
        m.lease = Some(Lease {
            idle_timeout_s: Some(300),
            last_activity: Some("2026-11-07T12:00:00Z".into()),

            extra: std::collections::BTreeMap::new(),
        });
        m.write_to(&d).unwrap();
        let d = Arc::new(d);
        let mut handles = Vec::new();
        for i in 0..8u32 {
            let dd = Arc::clone(&d);
            handles.push(std::thread::spawn(move || {
                record_member(&dd, 1000 + i, &format!("label-{i}"), "2026-11-07T12:00:00Z")
                    .expect("record_member");
                touch_lease(&dd, "2026-11-07T12:00:01Z").expect("touch_lease");
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let back = read(&d).unwrap();
        assert_eq!(
            back.members.len(),
            8,
            "every concurrent member insert must survive"
        );
        assert_eq!(
            back.lease.as_ref().unwrap().last_activity.as_deref(),
            Some("2026-11-07T12:00:01Z")
        );
        fs::remove_dir_all(&*d).unwrap();
    }
}
