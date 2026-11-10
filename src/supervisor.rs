//! The supervisor: owns one session (DESIGN §2, §9, §10, §11).
//!
//! **Needs user namespaces; cannot run in the Wakil build sandbox.** Pure
//! pieces (R5 decision, holder logic, request routing helpers) are unit
//! tested; the rest is covered by the host leak tests.
//!
//! Sequence (single-threaded until the control thread starts):
//! 1. checks, policy resolution, R1b alias scan, session dir;
//! 2. `unshare(NEWUSER|NEWNS)` → userns S (own copy of the mount tree);
//! 3. `clone(NEWUSER|NEWNS|NEWPID|NEWIPC|NEWUTS[|NEWNET])` → init;
//! 4. open `/proc/<init>/ns/{user,pid,mnt}`, send GO, wait for READY;
//! 5. fork the persistent grant helper (still single-threaded);
//! 6. start the control thread, apply initial grants, send START;
//! 7. relay stdio / pty, wait for init, clean up (ns fds first).

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::alias;
use crate::authz;
use crate::cli::{RunArgs, parse_grant_spec};
use crate::control::{self, ConnId, Handler, Mode, Request, err, ok};
use crate::env as senv;
use crate::exec::{self, ExecClient, ExecContext, ExecRules, NsFds};
use crate::grant::{self, Grant, GrantTable, HelperClient, Holder, HolderKind, Rules};
use crate::init::{self, InitConfig, MSG_ERROR, MSG_GO, MSG_READY, MSG_START};
use crate::landlock;
use crate::mounts::{self, HostFacts};
use crate::policy::{Network, Overrides, Policy, ResolvedPolicy, is_valid_session_id};
use crate::profile::{self, Profile as ProfileDoc};
use crate::services::{self, ServiceHandle};
use crate::session::{self, Audit, SessionDir};
use crate::sessionmeta;
use crate::{seccomp, sig, sys};

// ---------------------------------------------------------------- R5 decision

/// Why a control-socket peer was refused (never shown to the peer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refuse {
    WrongUid { peer: u32, ours: u32 },
    InSandboxPidns,
    Unknown(String),
}

/// R5 (DESIGN §9): decide from facts, failing closed on anything missing.
///
/// Membership of the sandbox pid namespace is decided by `peer_in_tree` (the
/// peer descends from the sandbox init, via world-readable `status` files).
/// `peer_pidns`/`sandbox_pidns` (`/proc/<pid>/ns/pid` inodes) are an extra
/// positive check when readable. The supervisor lives in a child user
/// namespace, so for a host peer the ns link is *expectedly* unreadable
/// (`cap_ptrace_access_check`); that alone is not a refusal, but an
/// undecidable `peer_in_tree` is.
pub fn authorize_peer(
    peer_uid: u32,
    our_uid: u32,
    peer_pidns: io::Result<u64>,
    sandbox_pidns: u64,
    peer_in_tree: io::Result<bool>,
    peer_alive: bool,
) -> Result<(), Refuse> {
    if peer_uid != our_uid {
        return Err(Refuse::WrongUid {
            peer: peer_uid,
            ours: our_uid,
        });
    }
    if !peer_alive {
        return Err(Refuse::Unknown("peer process already gone".into()));
    }
    if matches!(peer_pidns, Ok(ino) if ino == sandbox_pidns) {
        return Err(Refuse::InSandboxPidns);
    }
    match peer_in_tree {
        Ok(true) => Err(Refuse::InSandboxPidns),
        Ok(false) => Ok(()),
        Err(e) => Err(Refuse::Unknown(format!(
            "cannot establish peer ancestry: {e}"
        ))),
    }
}

/// Aggregate the scan results of one revoke into the response fields.
pub fn holders_json(holders: &BTreeSet<Holder>) -> Value {
    Value::Array(
        holders
            .iter()
            .map(|h| json!({ "pid": h.pid, "kind": h.kind.as_str() }))
            .collect(),
    )
}

/// Check the `expose` path for a forward (R1, R2, R3). The expose path must
/// not be `/`, `/proc`, `/sys`, `/dev`, or inside the runtime root; and must
/// not overlap a mask or static mount (same rules as a grant target).
fn check_forbidden_expose(path: &Path, runtime_roots: &[PathBuf]) -> Result<()> {
    use crate::policy::check_forbidden;
    check_forbidden(path, runtime_roots).map_err(|e| anyhow!("expose: {e}"))?;
    Ok(())
}

// ------------------------------------------------------------------- state

struct Held {
    mount_root: OwnedFd,
}

pub struct Shared {
    uid: u32,
    init_pid: i32,
    sandbox_pidns: u64,
    resolved_toml: String,
    /// Risk labels for this session (DESIGN §16), for `inspect --json`.
    risk: Vec<profile::RiskEntry>,
    rules: Rules,
    table: Mutex<GrantTable>,
    held: Mutex<std::collections::BTreeMap<PathBuf, Held>>,
    helper: Mutex<HelperClient>,
    audit: Audit,
    /// Serialises grant/revoke so audit order = execution order.
    op_lock: Mutex<()>,
    // ---- exec (DESIGN §14)
    exec: ExecClient,
    exec_rules: ExecRules,
    /// Spawns hold it shared until the program is inside init's tree; a hard
    /// revoke takes it exclusively before sweeping (DESIGN §14.6, D22).
    spawn_gate: RwLock<()>,
    /// One table for every live exec, keyed by `exec_id` (0.4.3: folded
    /// from the former `live`/`execs`/`exec_info`/`used_pids`/
    /// `recycled_pids` maps, whose five collections duplicated the same
    /// registration). Lock order, documented: `lease_lock` (via `admit`)
    /// then this table's lock; the table is the only lock taken for exec
    /// bookkeeping, so there is no cross-map ordering to get wrong.
    exec_table: Mutex<ExecTable>,
    /// Monotonic exec_id counter (never reused within a session).
    next_exec_id: std::sync::atomic::AtomicU64,
    /// Monotonic request sequence number, supervisor-assigned (0.4.0 step 3).
    seq: std::sync::atomic::AtomicU64,
    /// 0.4.1 R2: the live control connections (the client count and the
    /// `clients[]` records). The idle timer treats a non-empty registry as
    /// activity. Keyed by [`ConnId`]; see [`ConnRegistry`].
    conns: Mutex<ConnRegistry>,
    /// In-sandbox services (DESIGN §19): name → state for `ls --json`.
    services: Mutex<std::collections::BTreeMap<String, ServiceState>>,
    /// The session directory on the host (for `session.json` member writes).
    session_dir: std::path::PathBuf,
    /// F5: serialises all `session.json` rewrites (record_member, touch_lease).
    session_json_lock: Mutex<()>,
    /// F5: the idle timeout for this session (None = never, no lease writes).
    idle_timeout_s: Option<u64>,
    /// F8: last `last_seen` timestamp per (uid, label) pair, for the 60 s
    /// rate limit. Keyed by "{uid}:{label}".
    members_lock: Mutex<std::collections::BTreeMap<String, String>>,
    /// F8: last `last_activity` timestamp for the lease (10 s rate limit).
    lease_lock: Mutex<()>,
    /// F8: the last touch timestamp (for the 10 s lease rate limit).
    lease_last_touch: Mutex<Option<String>>,
    /// F2 fix: in-memory last activity seconds (updated on every authorized
    /// request, not rate-limited). The idle timer reads this instead of
    /// the persisted lease value, which is throttled to 10 s writes.
    last_activity_secs: std::sync::atomic::AtomicI64,
}

/// 0.4.1 R2: the live control connections. The client count and the per-
/// connection records are one map, so the count cannot drift from the records:
/// `connected()` is the map's length. Keyed by [`ConnId`] (never reused), so a
/// disconnect removes exactly the record its connect added.
#[derive(Default)]
struct ConnRegistry {
    clients: std::collections::BTreeMap<ConnId, ClientInfo>,
}

impl ConnRegistry {
    /// A connection sent its first request line: it is a client from now on.
    /// Returns `false` (and changes nothing) if it was already registered.
    fn connect(&mut self, id: ConnId, info: ClientInfo) -> bool {
        if self.clients.contains_key(&id) {
            return false;
        }
        self.clients.insert(id, info);
        true
    }

    /// The connection closed. Returns `true` if it was registered (exactly
    /// one disconnect per connect; a second is a no-op).
    fn disconnect(&mut self, id: ConnId) -> bool {
        self.clients.remove(&id).is_some()
    }

    /// Refine a registered connection's record with its request's identity.
    fn update(&mut self, id: ConnId, label: &str, label_source: &str, uid: u32, pid: Option<i32>) {
        if let Some(ci) = self.clients.get_mut(&id) {
            ci.uid = uid;
            ci.pid = pid;
            ci.label = label.to_owned();
            ci.label_source = label_source.to_owned();
        }
    }

    /// Number of connected clients.
    fn connected(&self) -> usize {
        self.clients.len()
    }
}

/// 0.4.1 step 3: a live control connection's client record, for `ls --json`
/// `clients[]`.
#[derive(Clone)]
struct ClientInfo {
    uid: u32,
    pid: Option<i32>,
    label: String,
    label_source: String,
    connected_since: String,
}

/// 0.4.1 step 3: a live exec, for `ls --json` `execs[]`.
#[derive(Clone)]
struct ExecInfo {
    pid: i32,
    argv0: String,
    tty: bool,
    attach: bool,
}

/// One live exec, held in [`ExecTable`]: the `ls --json` info, the pid, and
/// the two dup'd status-fd handles (one for `signal` by `exec_id`, one for
/// `signal` by pid — the same dup the old `execs`/`live` pair made). The
/// handles are `None` when a status dup failed at registration (EMFILE):
/// the exec is still listed, but not signal-able (the old `if let Ok(dup)`
/// skip, without a panic).
struct ExecEntry {
    info: ExecInfo,
    status_by_id: Option<OwnedFd>,
    status_by_pid: Option<OwnedFd>,
}

/// All live execs of a session, keyed by `exec_id`, plus the pid-reuse
/// history (0.4.3: one table; before, five collections tracked the same
/// exec and could disagree).
///
/// Pid-recycling semantics are unchanged: a pid ever used is remembered
/// (`used_pids`); a pid handed to a later exec is `recycled` and `signal`
/// by that pid is rejected. Entries are removed when the exec finishes;
/// the used/recycled history is not.
#[derive(Default)]
struct ExecTable {
    live: std::collections::BTreeMap<u64, ExecEntry>,
    used_pids: std::collections::BTreeSet<i32>,
    recycled_pids: std::collections::BTreeSet<i32>,
}

impl ExecTable {
    fn insert_info(&mut self, exec_id: u64, info: ExecInfo) {
        let pid = info.pid;
        if self.used_pids.contains(&pid) {
            self.recycled_pids.insert(pid);
        }
        self.used_pids.insert(pid);
        self.live.insert(
            exec_id,
            ExecEntry {
                info,
                status_by_id: None,
                status_by_pid: None,
            },
        );
    }

    fn set_status(&mut self, exec_id: u64, by_id: OwnedFd, by_pid: OwnedFd) {
        if let Some(e) = self.live.get_mut(&exec_id) {
            e.status_by_id = Some(by_id);
            e.status_by_pid = Some(by_pid);
        }
    }

    fn remove(&mut self, exec_id: u64) {
        self.live.remove(&exec_id);
    }

    fn is_empty(&self) -> bool {
        self.live.is_empty()
    }

    fn by_id(&self, exec_id: u64) -> Option<&OwnedFd> {
        self.live
            .get(&exec_id)
            .and_then(|e| e.status_by_id.as_ref())
    }

    /// Signal-by-pid lookup: `None` if the pid is recycled (reject with the
    /// recycled error) or not live. Returns the status handle.
    fn by_pid(&self, pid: i32) -> Option<&OwnedFd> {
        if self.recycled_pids.contains(&pid) {
            return None;
        }
        self.live
            .values()
            .find(|e| e.info.pid == pid)
            .and_then(|e| e.status_by_pid.as_ref())
    }

    fn is_recycled(&self, pid: i32) -> bool {
        self.recycled_pids.contains(&pid)
    }

    fn infos(&self) -> impl Iterator<Item = (u64, &ExecInfo)> {
        self.live.iter().map(|(id, e)| (*id, &e.info))
    }
}

/// The state of an in-sandbox service for `ls --json` (DESIGN §19).
pub struct ServiceState {
    pub name: String,
    pub pid: i32,
    pub socket: Option<String>,
    pub state: &'static str, // "starting" | "ready" | "exited"
    pub exit: Option<i32>,
    /// The status socket to the service's monitor `W`, used to detect exit.
    pub status: OwnedFd,
}

impl Shared {
    /// The exec helper client (used by `services` to spawn in-sandbox
    /// services).
    pub fn exec(&self) -> &ExecClient {
        &self.exec
    }

    /// The spawn gate (used by `services`).
    pub fn spawn_gate(&self) -> &RwLock<()> {
        &self.spawn_gate
    }

    /// The in-sandbox service states (used by `services`).
    pub fn services(&self) -> &Mutex<std::collections::BTreeMap<String, ServiceState>> {
        &self.services
    }

    /// Next request sequence number (supervisor-assigned, never reused).
    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Client label for a request whose client did not send one (0.4.0):
    /// `local` for the owner's own uid, `uid:<n>` otherwise. The SSH-derived
    /// `<login>@<ip>` label and `--client` arrive with the attach/SSH step.
    fn client_label(&self, uid: u32) -> String {
        if uid == self.uid {
            "local".into()
        } else {
            format!("uid:{uid}")
        }
    }

    /// Record a request's client in the `session.json` members list
    /// (F8: keyed by (uid, label), 60 s rate limit, serialised through
    /// `session_json_lock`).
    fn record_member(&self, client: &authz::ClientRecord) {
        let now = crate::session::rfc3339_now();
        let key = format!("{}:{}", client.uid, client.label);
        let should_write = {
            let ml = self.members_lock.lock().expect("members lock");
            match ml.get(&key) {
                None => true,
                Some(stored) => {
                    let stored_secs = crate::session::parse_rfc3339_secs(stored).unwrap_or(0);
                    let now_secs = crate::session::parse_rfc3339_secs(&now).unwrap_or(0);
                    now_secs - stored_secs >= 60
                }
            }
        };
        if !should_write {
            return;
        }
        let _lock = self.session_json_lock.lock().expect("session_json lock");
        let _ =
            crate::sessionmeta::record_member(&self.session_dir, client.uid, &client.label, &now);
        let mut ml = self.members_lock.lock().expect("members lock");
        ml.insert(key, now);
    }

    /// 0.4.0 F2: last activity time in epoch seconds (for the idle timer).
    /// F2 fix: reads the in-memory atomic (updated on every request) rather
    /// than the persisted lease value (throttled to 10 s writes).
    pub fn last_activity_secs(&self) -> i64 {
        self.last_activity_secs
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// 0.4.0 F2 fix: are there any connected control clients? A connection is
    /// a client from its first complete request line until it closes (a bare
    /// connect is never a client; see `serve_conn`).
    pub fn has_connected_clients(&self) -> bool {
        self.conns.lock().expect("conns").connected() > 0
    }

    /// 0.4.0 F2 fix: are there any running execs? (Any entry in the exec
    /// table, regardless of state — a finished exec is removed immediately.)
    pub fn has_running_execs(&self) -> bool {
        !self.exec_table.lock().expect("exec_table").is_empty()
    }

    /// 0.4.1 step 7: the idle predicate input, read under `lease_lock` so an
    /// admission (a new client or exec) cannot interleave between the reads and
    /// the stop decision. `admit()` takes the same lock, so a request admitted
    /// during the check is seen by it.
    pub fn idle_snapshot(&self) -> (bool, bool, i64) {
        let _g = self.lease_lock.lock().expect("lease lock");
        (
            self.conns.lock().expect("conns").connected() > 0,
            !self.exec_table.lock().expect("exec_table").is_empty(),
            self.last_activity_secs
                .load(std::sync::atomic::Ordering::SeqCst),
        )
    }

    /// 0.4.1 step 7: admission marker. A client connect or an exec registration
    /// takes `lease_lock`, so it is serialised against an in-progress idle
    /// check: an exec admitted during the check cannot be stopped under it.
    /// Returns the closure's value.
    fn admit<T>(&self, f: impl FnOnce() -> T) -> T {
        let _g = self.lease_lock.lock().expect("lease lock");
        f()
    }

    /// F2 fix: a control client connected: its first complete request line
    /// arrived (not at accept). 0.4.1 step 3: records the connection so
    /// `ls --json` can list live clients. The record is refined when that
    /// request is handled (`handle` calls `update_client` with the real label).
    pub fn connect_client(&self, conn: ConnId) {
        let now = crate::session::rfc3339_now();
        self.admit(|| {
            self.conns.lock().expect("conns").connect(
                conn,
                ClientInfo {
                    uid: self.uid,
                    pid: None,
                    label: "connected".into(),
                    label_source: "none".into(),
                    connected_since: now,
                },
            );
        });
    }

    /// 0.4.1 step 3: refine a connected client's record with the request-built
    /// `ClientRecord` (the label/label_source only arrive with a request line).
    fn update_client(&self, conn: ConnId, client: &authz::ClientRecord) {
        self.conns.lock().expect("conns").update(
            conn,
            &client.label,
            &client.label_source,
            client.uid,
            client.pid,
        );
    }

    /// F2 fix: a control client disconnected (serve_conn thread exited).
    /// The disconnect is the client's last activity: idle time counts from
    /// here, not from its (possibly much earlier) request.
    pub fn disconnect_client(&self, conn: ConnId) {
        // The removal and the activity bump happen under `lease_lock`, the same
        // lock `idle_snapshot` holds while it reads the count and the activity.
        // Without it the idle check could see zero clients and the old
        // timestamp in the gap between the two steps. Lock order matches
        // admission: lease_lock, then conns. A disconnect without a registered
        // connect is a no-op (never a negative count, no activity bump).
        let _g = self.lease_lock.lock().expect("lease lock");
        let removed = self.conns.lock().expect("conns").disconnect(conn);
        if removed && self.idle_timeout_s.is_some() {
            let now = crate::lifecycle::Clock::now_secs(&crate::lifecycle::SystemClock);
            self.last_activity_secs
                .fetch_max(now, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Update `last_activity` in `session.json` (0.4.0 step 5, F5), rate-limited
    /// to once per 10 s. No-op when `idle_timeout` is unset. All session.json
    /// rewrites go through `session_json_lock`.
    fn touch_lease(&self) {
        if self.idle_timeout_s.is_none() {
            return;
        }
        let now = crate::session::rfc3339_now();
        let now_secs = crate::session::parse_rfc3339_secs(&now).unwrap_or(0);
        // F2 fix: update the in-memory clock on every request (not rate-limited).
        self.last_activity_secs
            .fetch_max(now_secs, std::sync::atomic::Ordering::SeqCst);
        let should_write = {
            let _ll = self.lease_lock.lock().expect("lease lock");
            let stored = self.lease_last_touch.lock().expect("lease ts");
            match &*stored {
                None => true,
                Some(s) => {
                    let stored_secs = crate::session::parse_rfc3339_secs(s).unwrap_or(0);
                    now_secs - stored_secs >= 10
                }
            }
        };
        if !should_write {
            return;
        }
        let _json_lock = self.session_json_lock.lock().expect("session_json lock");
        let _ = crate::sessionmeta::touch_lease(&self.session_dir, &now);
        *self.lease_last_touch.lock().expect("lease ts") = Some(now);
    }

    /// Audit a line that carries the client record and the authz decision.
    #[allow(clippy::too_many_arguments)]
    fn log_client(
        &self,
        op: &str,
        stage: &str,
        path: Option<&str>,
        mode: Option<&str>,
        result: Option<&str>,
        client: &authz::ClientRecord,
        allowed: bool,
    ) {
        let mut entry = Audit::entry(op, stage, path, mode, result, client.pid);
        if let Some(o) = entry.as_object_mut() {
            o.insert(
                "client".into(),
                json!({
                    "uid": client.uid,
                    "label": client.label,
                    "label_source": client.label_source,
                    "req_id": client.req_id,
                }),
            );
            o.insert("seq".into(), json!(client.seq));
            o.insert("authz".into(), json!({ "allow": allowed }));
        }
        let _ = self.audit.log(entry);
    }

    fn log(
        &self,
        op: &str,
        stage: &str,
        path: Option<&str>,
        mode: Option<&str>,
        result: Option<&str>,
        peer: Option<i32>,
    ) {
        let _ = self
            .audit
            .log(Audit::entry(op, stage, path, mode, result, peer));
    }

    fn do_grant(
        &self,
        _auth: &authz::Authorized,
        client: &authz::ClientRecord,
        path: &str,
        mode: Mode,
        recursive: bool,
    ) -> Value {
        let _g = self.op_lock.lock().expect("op lock");
        self.log_client(
            "grant",
            "request",
            Some(path),
            Some(mode.as_str()),
            None,
            client,
            true,
        );
        let resp = (|| -> std::result::Result<Value, (String, String)> {
            let p = grant::parse_abs(path).map_err(|r| (r.code.to_owned(), r.message))?;
            let (src, canon) = grant::open_source(&p).map_err(|e| match e.raw_os_error() {
                Some(libc::ENOENT) => {
                    (control::E_NOT_FOUND.into(), format!("{path}: no such path"))
                }
                Some(libc::ELOOP | libc::EXDEV) => (
                    control::E_PATH_FORBIDDEN.into(),
                    format!("{path}: symlinks and escapes are not followed"),
                ),
                _ => (control::E_INTERNAL.into(), format!("{path}: {e}")),
            })?;
            if canon != p {
                return Err((
                    control::E_PATH_FORBIDDEN.into(),
                    format!("{path}: not canonical (resolves to {})", canon.display()),
                ));
            }
            {
                let table = self.table.lock().expect("table");
                grant::check_grant(&self.rules, &table, &canon, mode, recursive)
                    .map_err(|r| (r.code.to_owned(), r.message))?;
            }
            // R1b on the grant source as well (alias of the runtime dir).
            if let Ok(mi) = fs::read_to_string("/proc/self/mountinfo") {
                match alias::check_tree(&mi, &canon, recursive, &self.rules.runtime_roots) {
                    Ok(None) => {}
                    Ok(Some(a)) => {
                        return Err((
                            control::E_PATH_FORBIDDEN.into(),
                            format!("aliases the runtime directory: {a:?}"),
                        ));
                    }
                    Err(e) => return Err((control::E_INTERNAL.into(), e)),
                }
            } else {
                return Err((control::E_INTERNAL.into(), "cannot read mountinfo".into()));
            }
            let tree = grant::prepare_tree(&src, mode, recursive)
                .map_err(|e| (control::E_INTERNAL.into(), format!("open_tree: {e}")))?;
            let (mount_root, id) = self
                .helper
                .lock()
                .expect("helper")
                .grant(&canon, &tree)
                .map_err(|e| (control::E_INTERNAL.into(), format!("attach: {e}")))?;
            self.table.lock().expect("table").insert(Grant {
                path: canon.clone(),
                mode,
                recursive,
                mount_id: id,
                ts: session::rfc3339_now(),
            });
            self.held
                .lock()
                .expect("held")
                .insert(canon.clone(), Held { mount_root });
            Ok(ok(
                json!({ "mount_id": id, "path": canon, "mode": mode.as_str() }),
            ))
        })();
        match resp {
            Ok(v) => {
                self.log_client(
                    "grant",
                    "result",
                    Some(path),
                    Some(mode.as_str()),
                    Some("ok"),
                    client,
                    true,
                );
                v
            }
            Err((code, msg)) => {
                self.log_client(
                    "grant",
                    "result",
                    Some(path),
                    Some(mode.as_str()),
                    Some(&code),
                    client,
                    true,
                );
                err(&code, msg)
            }
        }
    }

    fn do_revoke(
        &self,
        _auth: &authz::Authorized,
        client: &authz::ClientRecord,
        path: &str,
        hard: bool,
        kill_holders: bool,
    ) -> Value {
        let _g = self.op_lock.lock().expect("op lock");
        let _ = client;
        self.log_client("revoke", "request", Some(path), None, None, client, true);
        let resp = (|| -> std::result::Result<Value, (String, String)> {
            let p = grant::parse_abs(path).map_err(|r| (r.code.to_owned(), r.message))?;
            let mount_id = {
                let t = self.table.lock().expect("table");
                grant::require_granted(&t, &p)
                    .map_err(|r| (r.code.to_owned(), r.message))?
                    .mount_id
            };
            // Keep the handle and the table entry until the detach succeeded, so a
            // failed detach can be retried instead of orphaning the grant.
            let detach = {
                let held = self.held.lock().expect("held");
                let h = held.get(&p).ok_or_else(|| {
                    (
                        control::E_INTERNAL.to_owned(),
                        "grant has no mount handle".to_owned(),
                    )
                })?;
                self.helper
                    .lock()
                    .expect("helper")
                    .revoke(&p, &h.mount_root)
            };
            detach.map_err(|e| (control::E_INTERNAL.into(), format!("detach: {e}")))?;
            self.table.lock().expect("table").remove(&p);
            // Dropping the handle releases our reference to the detached mount.
            drop(self.held.lock().expect("held").remove(&p));

            if hard {
                // No spawn may be half-way between "sent to the helper" and
                // "inside init's tree" while we sweep (D22). Poisoning cannot
                // matter: the guarded value is `()`.
                let _gate = self.spawn_gate.write().unwrap_or_else(|e| e.into_inner());
                self.kill_all_except_init()
                    .map_err(|e| (control::E_INTERNAL.into(), e))?;
                return Ok(ok(json!({ "guarantee": "hard", "holders": [] })));
            }
            let mut holders = self.scan_holders(mount_id);
            if kill_holders && !holders.is_empty() {
                for h in &holders {
                    if h.kind != HolderKind::Unknown {
                        let _ = sys::kill(h.pid, libc::SIGKILL);
                    }
                }
                thread::sleep(std::time::Duration::from_millis(50));
                holders = self.scan_holders(mount_id);
            }
            // Never claims more than "lookup": queued SCM_RIGHTS fds are unscannable.
            Ok(ok(
                json!({ "guarantee": "lookup", "holders": holders_json(&holders) }),
            ))
        })();
        match resp {
            Ok(v) => {
                self.log_client(
                    "revoke",
                    "result",
                    Some(path),
                    None,
                    Some("ok"),
                    client,
                    true,
                );
                v
            }
            Err((code, msg)) => {
                self.log_client(
                    "revoke",
                    "result",
                    Some(path),
                    None,
                    Some(&code),
                    client,
                    true,
                );
                err(&code, msg)
            }
        }
    }

    /// Forward a host socket inside the sandbox at `expose` (DESIGN §17).
    /// Uses the grant helper to `open_tree` the socket inode and `move_mount`
    /// it at `expose` with `MOUNT_ATTR_RDONLY`. The forward is tracked in
    /// the grant table like a ro grant.
    fn do_forward(&self, socket: &str, expose: &str, name: &str) -> Result<()> {
        self.do_forward_inner(socket, expose, name, false)
    }

    /// `internal`: the source is hisn's own ssh-agent proxy socket, which by
    /// construction lives in the session directory (inside the runtime root).
    /// Only the R1b alias check is skipped, and only after the caller-supplied
    /// path was verified to be exactly that socket (a socket inode, below).
    fn do_forward_inner(
        &self,
        socket: &str,
        expose: &str,
        name: &str,
        internal: bool,
    ) -> Result<()> {
        let _g = self.op_lock.lock().expect("op lock");
        self.log("forward", "start", Some(socket), None, None, None);
        // Canonicalize the socket path: /var/run is a symlink to /run on
        // systemd hosts, and open_source uses RESOLVE_NO_SYMLINKS, so we
        // must resolve the path first. The canonical path is what we
        // validate against (R1–R4); the original string is only for display.
        let canon_path = fs::canonicalize(socket)
            .with_context(|| format!("canonicalizing socket {}", socket))?;
        let p = grant::parse_abs(canon_path.to_str().unwrap_or(socket))
            .map_err(|r| anyhow!("{}: {}", r.code, r.message))?;
        let (src, canon) = grant::open_source(&p).map_err(|e| anyhow!("open source: {e}"))?;
        // canon should now match p (both are symlink-free); if not, the
        // path was further resolved by the kernel and we use the canonical form.
        // Verify the source is a socket inode.
        let meta = fs::symlink_metadata(&canon).map_err(|e| anyhow!("stat: {e}"))?;
        let file_type = meta.file_type();
        if !file_type.is_socket() {
            bail!(
                "E_NOT_SOCKET: {} is not a socket (is {})",
                socket,
                if file_type.is_dir() {
                    "dir"
                } else if file_type.is_file() {
                    "file"
                } else {
                    "other"
                }
            );
        }
        // R1b on the source (skipped only for hisn's own proxy socket).
        if internal {
            // the source must be exactly <session dir>/ssh-agent.sock
            if canon.file_name().and_then(|n| n.to_str()) != Some("ssh-agent.sock") {
                bail!(
                    "internal forward source {} is not the proxy socket",
                    canon.display()
                );
            }
        } else if let Ok(mi) = fs::read_to_string("/proc/self/mountinfo") {
            match alias::check_tree(&mi, &canon, false, &self.rules.runtime_roots) {
                Ok(None) => {}
                Ok(Some(a)) => bail!("{socket} aliases the runtime directory: {a:?}"),
                Err(e) => bail!("R1b: {e}"),
            }
        } else {
            bail!("cannot read mountinfo");
        }
        // Validate the expose path (R1, R2, R3).
        let expose_p =
            grant::parse_abs(expose).map_err(|r| anyhow!("expose: {} : {}", r.code, r.message))?;
        check_forbidden_expose(&expose_p, &self.rules.runtime_roots)?;
        // Prepare the tree: open_tree(OPEN_TREE_CLONE) + mount_setattr(RDONLY).
        let tree =
            grant::prepare_tree(&src, Mode::Ro, false).map_err(|e| anyhow!("prepare_tree: {e}"))?;
        // Send to the grant helper to attach at `expose`.
        let (mount_root, id) = self
            .helper
            .lock()
            .expect("helper")
            .forward(&expose_p, &tree)
            .map_err(|e| anyhow!("attach: {e}"))?;
        // Track in the grant table.
        self.table.lock().expect("table").insert(Grant {
            path: expose_p.clone(),
            mode: Mode::Ro,
            recursive: false,
            mount_id: id,
            ts: session::rfc3339_now(),
        });
        self.held
            .lock()
            .expect("held")
            .insert(expose_p.clone(), Held { mount_root });
        self.log("forward", "result", Some(socket), None, Some("ok"), None);
        tracing::info!("forward: {} -> {} (mount_id={id})", name, expose);
        Ok(())
    }

    /// PIDs (in the supervisor's view) of every process in the sandbox pid
    /// namespace: the sandbox init and all its descendants (orphans reparent
    /// to init, so nothing in the namespace is outside this tree).
    ///
    /// Not done by comparing `/proc/<pid>/ns/pid`: the supervisor lives in a
    /// child user namespace and may not read that link for host processes of
    /// the same user. Fail closed: any unreadable `status` (other than a
    /// process that just exited) makes the enumeration an error, so an
    /// incomplete list is never mistaken for an empty one.
    fn sandbox_pids(&self) -> io::Result<Vec<i32>> {
        sys::descendants_of(self.init_pid)
    }

    /// Hard revoke: kill everything but init, repeat until none are left.
    fn kill_all_except_init(&self) -> std::result::Result<(), String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let pids: Vec<i32> = self
                .sandbox_pids()
                .map_err(|e| format!("cannot enumerate sandbox processes: {e}"))?
                .into_iter()
                .filter(|p| *p != self.init_pid)
                .collect();
            if pids.is_empty() {
                return Ok(());
            }
            if std::time::Instant::now() > deadline {
                let _ = sys::kill(self.init_pid, libc::SIGKILL);
                return Err("hard revoke timed out; session killed".into());
            }
            for p in pids {
                let _ = sys::kill(p, libc::SIGKILL);
            }
            thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// Soft-revoke scan: who still holds the mount (cwd, root, fds, mappings)?
    /// Anything unreadable is reported as `unknown`, never as clean.
    fn scan_holders(&self, mount_id: u64) -> BTreeSet<Holder> {
        let mut out = BTreeSet::new();
        let pids = match self.sandbox_pids() {
            Ok(p) => p,
            Err(_) => {
                out.insert(Holder {
                    pid: 0,
                    kind: HolderKind::Unknown,
                });
                return out;
            }
        };
        for pid in pids.into_iter().filter(|p| *p != self.init_pid) {
            let unknown = |out: &mut BTreeSet<Holder>| {
                out.insert(Holder {
                    pid,
                    kind: HolderKind::Unknown,
                });
            };
            for (link, kind) in [("cwd", HolderKind::Cwd), ("root", HolderKind::Cwd)] {
                match sys::mnt_id(
                    libc::AT_FDCWD,
                    &sys::cstr_str(&format!("/proc/{pid}/{link}")).expect("no NUL"),
                    0,
                ) {
                    Ok(id) if id == mount_id => {
                        out.insert(Holder { pid, kind });
                    }
                    Ok(_) => {}
                    Err(_) => unknown(&mut out),
                }
            }
            match fs::read_dir(format!("/proc/{pid}/fdinfo")) {
                Ok(rd) => {
                    for fd in rd.flatten() {
                        match fs::read_to_string(fd.path()) {
                            Ok(body) => {
                                match grant::fdinfo_mount_id(&body) {
                                    Some(id) if id == mount_id => {
                                        out.insert(Holder {
                                            pid,
                                            kind: HolderKind::Fd,
                                        });
                                    }
                                    Some(_) => {}
                                    // unparsable: never counted as clean
                                    None => unknown(&mut out),
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::NotFound => {} // fd closed meanwhile
                            Err(_) => unknown(&mut out),
                        }
                    }
                }
                Err(_) => unknown(&mut out),
            }
            // Mappings: /proc/<pid>/map_files/* resolve to the mapped files; a
            // statx of each yields its mount id.
            match fs::read_dir(format!("/proc/{pid}/map_files")) {
                Ok(rd) => {
                    for m in rd.flatten() {
                        let Ok(c) = sys::cstr(&m.path()) else {
                            unknown(&mut out);
                            continue;
                        };
                        match sys::mnt_id(libc::AT_FDCWD, &c, 0) {
                            Ok(id) if id == mount_id => {
                                out.insert(Holder {
                                    pid,
                                    kind: HolderKind::Map,
                                });
                            }
                            Ok(_) => {}
                            Err(e) if e.kind() == io::ErrorKind::NotFound => {} // unmapped meanwhile
                            Err(_) => unknown(&mut out),
                        }
                    }
                }
                Err(_) => unknown(&mut out),
            }
        }
        out
    }

    /// `exec`: validate, spawn through the helper, stream the exit status
    /// (DESIGN §14). Writes `{"ok":true,"pid":N}` to `conn` itself and returns
    /// the final `{"exit":…}` line (or an error response).
    fn do_exec(
        &self,
        _auth: &authz::Authorized,
        client: &authz::ClientRecord,
        req: ExecRequest,
        stdio: Vec<OwnedFd>,
        conn: &UnixStream,
    ) -> Value {
        let argv0 = req.argv.first().cloned().unwrap_or_default();
        let op = if req.attach { "attach" } else { "exec" };
        self.log_client(op, "request", Some(&argv0), None, None, client, true);
        let fail = |code: &str, msg: String| {
            self.log_client(op, "result", Some(&argv0), None, Some(code), client, true);
            err(code, msg)
        };
        let spec = match exec::validate(
            req.argv,
            req.cwd,
            req.env,
            req.tty,
            stdio.len(),
            &self.exec_rules,
        ) {
            Ok(s) => s,
            Err(e) => return fail(control::E_BAD_REQUEST, e.to_string()),
        };
        let spawned = {
            let _gate = self.spawn_gate.read().unwrap_or_else(|e| e.into_inner());
            self.exec.spawn(&spec, stdio, exec::SPAWN_TIMEOUT)
        };
        let sp = match spawned {
            Ok(sp) => sp,
            Err(exec::SpawnError::Exec { message, .. }) => {
                return fail(control::E_EXEC, message);
            }
            Err(exec::SpawnError::Internal(m)) => return fail(control::E_INTERNAL, m),
        };
        // Register for `signal` before the client learns the pid.
        let exec_id = self
            .next_exec_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // Register for `signal` before the client learns the pid. One
        // admission inserts one table entry (info + both status dups +
        // pid-recycling); the idle check therefore sees the exec atomically.
        // No panic path: if a status dup fails (EMFILE), the exec is still
        // listed in `ls --json` (info inserted unconditionally, as the old
        // `exec_info` insert was) but is not signal-able — exactly the old
        // `if let Ok(dup)` skip for the `execs` map, never a panic inside
        // the `admit`/`lease_lock` closure (a panic there would poison the
        // lock for every later admit and idle check).
        // 0.4.1 step 7: registration is admission — it takes the lease lock
        // so an idle check in flight cannot miss this exec and stop the
        // session.
        self.admit(|| {
            let by_pid = sys::dup_cloexec_min(sp.status.as_raw_fd(), 3).ok();
            let by_id = sys::dup_cloexec_min(sp.status.as_raw_fd(), 3).ok();
            let mut table = self.exec_table.lock().expect("exec_table");
            // The info is always recorded (the old `exec_info` insert was
            // unconditional); the signal handles are only present when
            // both dups succeeded. Insertion marks the pid used even when
            // a dup failed (the old `used_pids` marking was unconditional
            // too, conditioned on the first dup — the table keeps the
            // unconditional marking, the safer direction for pid reuse).
            table.insert_info(
                exec_id,
                ExecInfo {
                    pid: sp.pid,
                    argv0: argv0.clone(),
                    tty: req.tty,
                    attach: req.attach,
                },
            );
            if let (Some(by_pid), Some(by_id)) = (by_pid, by_id) {
                table.set_status(exec_id, by_id, by_pid);
            }
        });
        let mut w = conn;
        let started = writeln!(
            w,
            "{}",
            ok(json!({ "pid": sp.pid, "exec_id": format!("e-{exec_id}") }))
        );
        let outcome = if started.is_ok() {
            exec::drive(&sp.status, sp.pending, conn.as_raw_fd(), exec::CANCEL_GRACE)
        } else {
            // Client already gone: cancel through the normal path.
            exec::drive_from(&sp.status, sp.pending, -1, std::time::Duration::ZERO, true)
        };
        self.exec_table.lock().expect("exec_table").remove(exec_id);
        let (res, line) = match outcome {
            exec::Outcome::Exited(exec::Exit::Code(c)) => ("ok", json!({ "exit": { "code": c } })),
            exec::Outcome::Exited(exec::Exit::Signal(n)) => (
                "ok",
                json!({ "exit": { "signal": control::signal_name(n) } }),
            ),
            exec::Outcome::Lost => ("lost", json!({ "exit": { "lost": true } })),
        };
        self.log_client(
            "exec",
            "result",
            Some(&argv0),
            None,
            Some(res),
            client,
            true,
        );
        line
    }

    /// `signal`: deliver to a live exec'd program of *this* session only.
    /// Accepts `exec_id` (preferred) or `pid` (deprecated for 0.2 clients).
    fn do_signal(
        &self,
        _auth: &authz::Authorized,
        client: &authz::ClientRecord,
        exec_id: Option<String>,
        pid: Option<i32>,
        signal: &str,
    ) -> Value {
        self.log_client("signal", "request", None, None, Some(signal), client, true);
        let Some(sig) = control::parse_signal(signal) else {
            return err(control::E_BAD_REQUEST, format!("unknown signal {signal:?}"));
        };
        // Prefer exec_id; fall back to pid for 0.2 clients.
        if let Some(eid) = exec_id {
            let eid_num = eid.strip_prefix("e-").and_then(|n| n.parse::<u64>().ok());
            let Some(eid_num) = eid_num else {
                return err(control::E_BAD_REQUEST, format!("invalid exec_id {eid:?}"));
            };
            let table = self.exec_table.lock().expect("exec_table");
            let Some(h) = table.by_id(eid_num) else {
                return err(
                    control::E_NOT_FOUND,
                    format!("no running exec with exec_id {eid}"),
                );
            };
            return match sys::send_all(h.as_raw_fd(), exec::format_kill(sig).as_bytes()) {
                Ok(()) => ok(json!({})),
                Err(e) => err(control::E_INTERNAL, e.to_string()),
            };
        }
        // Deprecated pid path: reject if the pid has been recycled.
        let Some(pid) = pid else {
            return err(
                control::E_BAD_REQUEST,
                "signal requires exec_id or pid".to_owned(),
            );
        };
        let table = self.exec_table.lock().expect("exec_table");
        if table.is_recycled(pid) {
            return err(
                control::E_NOT_FOUND,
                format!("pid {pid} has been recycled; use exec_id"),
            );
        }
        let Some(h) = table.by_pid(pid) else {
            return err(
                control::E_NOT_FOUND,
                format!("no running exec with pid {pid}"),
            );
        };
        match sys::send_all(h.as_raw_fd(), exec::format_kill(sig).as_bytes()) {
            Ok(()) => ok(json!({})),
            Err(e) => err(control::E_INTERNAL, e.to_string()),
        }
    }

    /// 0.4.1 step 3: the live per-session view for `ls --json`: currently
    /// connected clients and live execs (including attaches). Never blocks; a
    /// client with no requests yet is still listed (label "connected").
    fn session_info(&self, _auth: &authz::Authorized) -> Value {
        let clients: Vec<Value> = self
            .conns
            .lock()
            .expect("conns")
            .clients
            .values()
            .map(|c| {
                json!({
                    "uid": c.uid,
                    "pid": c.pid,
                    "label": c.label,
                    "label_source": c.label_source,
                    "connected_since": c.connected_since,
                })
            })
            .collect();
        let execs: Vec<Value> = self
            .exec_table
            .lock()
            .expect("exec_table")
            .infos()
            .map(|(id, e)| {
                json!({
                    "exec_id": format!("e-{id}"),
                    "pid": e.pid,
                    "argv0": e.argv0,
                    "tty": e.tty,
                    "attach": e.attach,
                })
            })
            .collect();
        // `"starting"`: a service whose readiness has not passed yet is
        // reported as starting. `start_in_sandbox_service` inserts the
        // state as "starting"; only the readiness pass (in
        // `start_in_sandbox_services` via `wait_service_readiness`) and
        // the exit detect below flip it. Before this change every service
        // was inserted as "ready" and `"starting"` never appeared.
        let services: Vec<Value> = self
            .services
            .lock()
            .expect("services")
            .values()
            .map(|s| {
                json!({
                    "name": s.name,
                    "pid": s.pid,
                    "socket": s.socket,
                    "state": s.state,
                    "exit": s.exit,
                })
            })
            .collect();
        ok(json!({ "clients": clients, "execs": execs, "services": services }))
    }

    fn inspect(&self, _auth: &authz::Authorized) -> Value {
        let services = {
            let mut svcs = self.services.lock().expect("services");
            // Update service states: check if each service is still alive
            // (P26). A service whose status socket is closed or whose pid
            // is gone has exited.
            for s in svcs.values_mut() {
                let alive = s.status.as_raw_fd();
                let mut pollfds = [libc::pollfd {
                    fd: alive,
                    events: libc::POLLIN,
                    revents: 0,
                }];
                // SAFETY: poll on our own fd, non-blocking.
                let r = unsafe { libc::poll(&mut pollfds[0], 1, 0) };
                if r > 0 && (pollfds[0].revents & (libc::POLLHUP | libc::POLLERR)) != 0 {
                    // The monitor is gone. The exit status itself is not
                    // recoverable from the status socket (Part 2.3 evidence
                    // note): the pid is in the sandbox pid namespace, so
                    // the supervisor cannot waitpid it; only the monitor
                    // `W` reaps it, and the status stream carries the pid
                    // but no exit code on this path without new plumbing
                    // across threads. `exit` therefore stays None for
                    // in-sandbox services (as before); the state flip is
                    // the truthful part.
                    s.state = "exited";
                }
            }
            svcs.values()
                .map(|s| {
                    json!({
                        "name": s.name,
                        "pid": s.pid,
                        "socket": s.socket,
                        "state": s.state,
                        "exit": s.exit,
                    })
                })
                .collect::<Vec<_>>()
        };
        let policy_redacted = redact_env_set(&self.resolved_toml);
        match fs::read_to_string(format!("/proc/{}/mountinfo", self.init_pid)) {
            Ok(mi) => ok(json!({
                "schema": "hisn-inspect/v1",
                "mountinfo": mi,
                "policy": policy_redacted,
                "risk": self.risk.iter().map(|e| json!({
                    "capability": e.capability,
                    "label": e.label.kebab(),
                })).collect::<Vec<_>>(),
                "services": services,
                // The supervisor's own descriptor count: the leak suite (L19)
                // cannot read /proc/<supervisor>/fd (non-dumpable after the
                // userns change), so the supervisor reports it itself.
                "supervisor_fds": open_fd_count().ok(),
            })),
            Err(e) => err(
                control::E_INTERNAL,
                format!("cannot read sandbox mountinfo: {e}"),
            ),
        }
    }
}

/// The fields of an `exec` request, as they arrive from the control socket.
struct ExecRequest {
    argv: Vec<String>,
    cwd: Option<String>,
    env: std::collections::BTreeMap<String, String>,
    tty: bool,
    /// 0.4.0 step 2: when true, this is an attach (interactive shell).
    attach: bool,
}

struct Ctl {
    sh: Arc<Shared>,
}

impl Handler for Ctl {
    fn authorize(&self, peer: &UnixStream) -> std::result::Result<(), String> {
        let fd = peer.as_raw_fd();
        let (pid, uid) = sys::peer_cred(fd).map_err(|e| e.to_string())?;
        // Prefer a pidfd (immune to pid reuse); fall back to the credential pid.
        let alive = match sys::peer_pidfd(fd) {
            Ok(pfd) => sys::pidfd_alive(pfd.as_raw_fd()),
            Err(_) => true,
        };
        let decision = authorize_peer(
            uid,
            self.sh.uid,
            sys::ns_inode(pid, "pid"),
            self.sh.sandbox_pidns,
            sys::is_descendant_of(pid, self.sh.init_pid),
            alive,
        )
        .map_err(|r| format!("{r:?}"));
        if let Err(reason) = &decision {
            // The peer is never told why (POLICY-SPEC §7), but the operator
            // must be able to see it: audit log + the supervisor's stderr.
            self.sh
                .log("auth", "refused", None, None, Some(reason), Some(pid));
            eprintln!("hisn: control: refused peer pid {pid} uid {uid}: {reason}");
        }
        decision
    }

    fn connect(&self, conn: ConnId) {
        self.sh.connect_client(conn);
    }

    /// 0.4.1 R2: a request counts its connection only if it is admitted: an
    /// observer never is, and a mutation the owner-uid decision refuses does
    /// not register. The decision is the same `authz::authorize` `handle` runs.
    fn admit(&self, req: &Request, peer: &UnixStream, _conn: ConnId) -> bool {
        if req.is_observer() {
            return false;
        }
        // The same peer identity `handle` reads (SO_PEERCRED), then the same
        // decision. A refused request does not register.
        let (_, peer_uid) = match sys::peer_cred(peer.as_raw_fd()) {
            Ok((p, u)) => (Some(p), u),
            Err(_) => (None, u32::MAX),
        };
        let client = authz::ClientRecord {
            uid: peer_uid,
            pid: None,
            label: String::new(),
            label_source: "none".to_string(),
            req_id: None,
            seq: 0,
            principal: None,
        };
        let session = authz::SessionAuth {
            owner_uid: self.sh.uid,
        };
        authz::authorize(&client, &session, req).is_ok()
    }

    fn disconnect(&self, conn: ConnId) {
        self.sh.disconnect_client(conn);
    }

    fn handle(&self, req: Request, fds: Vec<OwnedFd>, peer: &UnixStream, conn: ConnId) -> Value {
        let (peer_pid, peer_uid) = match sys::peer_cred(peer.as_raw_fd()) {
            Ok((p, u)) => (Some(p), u),
            Err(_) => (None, u32::MAX),
        };
        // The single transport entry (0.4.0 step 3, F1): build the client
        // record from SO_PEERCRED (uid, pid — never from the request) plus
        // the client-supplied label/label_source/req_id, and authorize
        // BEFORE any effect.
        let seq = self.sh.next_seq();
        let (label, label_source, req_id) = req
            .client_field()
            .map(|c| {
                (
                    c.label
                        .clone()
                        .unwrap_or_else(|| self.sh.client_label(peer_uid)),
                    c.label_source.clone().unwrap_or_else(|| "none".to_string()),
                    c.req_id.clone(),
                )
            })
            .unwrap_or_else(|| (self.sh.client_label(peer_uid), "none".to_string(), None));
        let client = authz::ClientRecord {
            uid: peer_uid,
            pid: peer_pid,
            label,
            label_source,
            req_id,
            seq,
            principal: None,
        };
        let session = authz::SessionAuth {
            owner_uid: self.sh.uid,
        };
        let auth = match authz::authorize(&client, &session, &req) {
            Ok(a) => a,
            Err(refusal) => {
                self.sh.log_client(
                    refusal.op.name(),
                    "refused",
                    None,
                    None,
                    Some(&refusal.reason),
                    &client,
                    false,
                );
                return err(control::E_UNAUTHORIZED, refusal.reason);
            }
        };
        // 0.4.1 R2: an observer request (sessioninfo, inspect, list) creates no
        // member, touches no lease, and refines no client record. Only the
        // authorized mutations that count as clients do those writes.
        if !req.is_observer() {
            self.sh.record_member(&client);
            self.sh.touch_lease();
            self.sh.update_client(conn, &client);
        }
        match req {
            Request::Exec {
                argv,
                cwd,
                env,
                tty,
                attach,
                client: _,
            } => {
                if attach {
                    // 0.4.0 step 2: an attach is an exec with the session's
                    // shell ($SHELL from the env snapshot, else /bin/sh) in
                    // the session cwd. The base env is the session snapshot.
                    let shell = if argv.is_empty() {
                        self.sh
                            .exec_rules
                            .base_env
                            .get("SHELL")
                            .cloned()
                            .unwrap_or_else(|| "/bin/sh".into())
                    } else {
                        argv[0].clone()
                    };
                    let attach_argv = if argv.is_empty() {
                        vec![shell.clone(), "-l".into()]
                    } else {
                        argv
                    };
                    let attach_cwd = cwd.or_else(|| Some(self.sh.exec_rules.default_cwd.clone()));
                    return self.sh.do_exec(
                        &auth,
                        &client,
                        ExecRequest {
                            argv: attach_argv,
                            cwd: attach_cwd,
                            env,
                            tty: true,
                            attach: true,
                        },
                        fds,
                        peer,
                    );
                }
                self.sh.do_exec(
                    &auth,
                    &client,
                    ExecRequest {
                        argv,
                        cwd,
                        env,
                        tty,
                        attach: false,
                    },
                    fds,
                    peer,
                )
            }
            Request::Signal {
                exec_id,
                pid,
                signal,
                client: _,
            } => self.sh.do_signal(&auth, &client, exec_id, pid, &signal),
            Request::Grant {
                path,
                mode,
                recursive,
                client: _,
            } => self.sh.do_grant(&auth, &client, &path, mode, recursive),
            Request::Revoke {
                path,
                hard,
                kill_holders,
                client: _,
            } => self.sh.do_revoke(&auth, &client, &path, hard, kill_holders),
            Request::List { client: _ } => {
                let _ = &auth;
                let t = self.sh.table.lock().expect("table");
                let grants: Vec<Value> = t
                    .list()
                    .iter()
                    .map(|g| json!({ "path": g.path, "mode": g.mode.as_str(), "recursive": g.recursive, "mount_id": g.mount_id, "ts": g.ts }))
                    .collect();
                ok(json!({ "grants": grants }))
            }
            Request::Inspect { client: _ } => self.sh.inspect(&auth),
            Request::SessionInfo { client: _ } => self.sh.session_info(&auth),
            Request::Kill { signal, client: _ } => {
                self.sh
                    .log_client("kill", "request", None, None, Some(&signal), &client, true);
                match control::parse_signal(&signal) {
                    None => err(control::E_BAD_REQUEST, format!("unknown signal {signal:?}")),
                    Some(s) => match sys::kill(self.sh.init_pid, s) {
                        Ok(()) => ok(json!({})),
                        Err(e) => err(control::E_INTERNAL, e.to_string()),
                    },
                }
            }
        }
    }
}

// --------------------------------------------------------------------- run

/// Longest user name accepted for the sandbox stubs (`useradd` limit).
const MAX_USERNAME: usize = 32;

/// Fallback when the host user cannot be named.
const FALLBACK_USERNAME: &str = "user";

/// May `n` be written into the generated `/etc/passwd` and `/etc/group`
/// and exported as `USER`/`LOGNAME`? Conservative on purpose: no `:`,
/// newline, whitespace or `/`, so a hostile NSS entry cannot add a line or a
/// field to the stubs.
fn valid_username(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= MAX_USERNAME
        && !n.starts_with('-')
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Turn a user-database lookup into the sandbox user name. The second value
/// is why the fallback was used (logged at `-v`). Pure: unit-tested.
fn pick_username(lookup: io::Result<Option<String>>) -> (String, Option<String>) {
    let why = match lookup {
        Ok(Some(n)) if valid_username(&n) => return (n, None),
        Ok(Some(n)) => format!(
            "host user name is not usable in /etc/passwd ({} bytes, unsupported characters or length)",
            n.len()
        ),
        Ok(None) => "no passwd entry for the host uid".to_owned(),
        Err(e) => format!("getpwuid_r failed: {e}"),
    };
    (FALLBACK_USERNAME.to_owned(), Some(why))
}

/// Host uid, gid and the user name shown inside the sandbox. The name comes
/// from the user database (`getpwuid_r` on the effective uid), never from
/// `$USER`: a scrubbed launch environment (Wakil, `env -i`) has none.
fn getids(verbose: u8) -> (u32, u32, String) {
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    let euid = rustix::process::geteuid().as_raw();
    let (name, why) = pick_username(sys::passwd_name(euid));
    if verbose > 0 {
        match why {
            Some(w) => eprintln!("hisn: username: using {name:?}: {w}"),
            None => eprintln!("hisn: username: {name:?} (getpwuid_r uid {euid})"),
        }
    }
    (uid, gid, name)
}

/// Resolve policy + flags into the resolved policy, grant list, runtime roots,
/// and the 0.3 surface (services, forwards, host_services, ssh) from the profile.
///
/// The profile document is loaded once here; the risk labels are computed
/// from that same document and carried in [`Prepared::risk_entries`], so a
/// detached start cannot compute them from a second, racy load.
pub struct Prepared {
    pub policy: ResolvedPolicy,
    pub grants: Vec<(String, Mode)>,
    pub roots: Vec<PathBuf>,
    /// Risk labels computed from the loaded profile document (or the CLI
    /// synthesis when no profile is given).
    pub risk_entries: Vec<profile::RiskEntry>,
    /// 0.3 surface: in-sandbox services from the profile.
    pub services: Vec<profile::Service>,
    /// 0.3 surface: forwards from the profile.
    pub forwards: Vec<profile::Forward>,
    /// 0.3 surface: host_services from the profile.
    pub host_services: Vec<profile::HostService>,
    /// 0.3.2: SSH agent config from the profile.
    pub ssh: Option<profile::SshConfig>,
    /// 0.4.1 step 3: the rootfs as the user gave it (a store name or a path),
    /// for `ls`. `None` when the session uses the host toolchain.
    pub rootfs_display: Option<String>,
}

pub fn prepare(args: &RunArgs, uid: u32) -> Result<Prepared> {
    let roots = session::runtime_roots(std::env::var("XDG_RUNTIME_DIR").ok().as_deref(), uid);
    let cwd_base = std::env::current_dir().context("current dir")?;
    let (pol, base, profile_doc) = match (&args.policy, &args.profile) {
        (Some(f), None) => {
            let p = Policy::load(f).with_context(|| f.display().to_string())?;
            let b = f
                .parent()
                .filter(|b| !b.as_os_str().is_empty())
                .map(Path::to_path_buf)
                .unwrap_or(cwd_base.clone());
            (p, b, None)
        }
        (None, Some(spec)) => {
            let (path, source) = profile::resolve_profile_path(spec)?;
            let prof = ProfileDoc::load(&path)?;
            let b = path
                .parent()
                .filter(|b| !b.as_os_str().is_empty())
                .map(Path::to_path_buf)
                .unwrap_or(cwd_base.clone());
            // Trust check: a profile under the session cwd or a rw grant
            // cannot satisfy risk_ack (E_PROFILE_UNTRUSTED). The session cwd
            // is not known yet (it is resolved from the inner policy), so the
            // check runs after resolution, in `run`. Here we just load it.
            let _ = source; // trust check deferred to run()
            let pol = prof.policy.clone();
            (pol, b, Some(prof))
        }
        (None, None) => (Policy::default(), cwd_base.clone(), None),
        // (Some, Some) is rejected by check_command() before we get here.
        _ => unreachable!("--profile and --policy are mutually exclusive (check_command)"),
    };
    // Compute risk from the same document, then destructure the owned
    // profile: overrides/rootfs display need `home`/`net`/`rootfs`; the 0.3
    // surface and ssh move out. No field is cloned (before, `prepare`
    // cloned the whole profile and then four of its fields).
    let risk_entries = match &profile_doc {
        Some(prof) => profile::compute_risks(prof),
        None => compute_risk_from_cli(args)?,
    };
    let (home, rootfs, net) = match &profile_doc {
        Some(prof) => (prof.home.clone(), prof.rootfs.clone(), prof.net.clone()),
        None => (None, None, None),
    };
    let (services, forwards, host_services, ssh) = match profile_doc {
        Some(ProfileDoc {
            services,
            forwards,
            host_services,
            ssh,
            ..
        }) => (services, forwards, host_services, ssh),
        None => (Vec::new(), Vec::new(), Vec::new(), None),
    };
    let mut ov = Overrides {
        cwd: args.cwd.as_ref().map(|c| {
            if c.is_absolute() {
                c.clone()
            } else {
                cwd_base.join(c)
            }
        }),
        network: args.network.map(|n| match n {
            crate::cli::NetworkArg::None => Network::None,
            crate::cli::NetworkArg::Host => Network::Host,
        }),
        home_persist: args
            .home_persist
            .clone()
            .or_else(|| home.as_ref()?.persist.clone()),
        // 0.3.3: `[net] nameservers` from the profile (no CLI flag).
        nameservers: net.as_ref().and_then(|n| n.nameservers.clone()),
        rootfs_path: match &args.rootfs_path {
            Some(p) => Some(p.to_string_lossy().into_owned()),
            // Strict: a profile naming a rootfs that cannot be resolved is an
            // error, never a silent fall-back to the host toolchain.
            None => rootfs.as_ref().map(profile::rootfs_spec).transpose()?,
        },
    };
    // The profile-contributed overrides (home/rootfs/nameservers) are the
    // same construction `profile validate` uses, via `Profile::overrides`
    // on the document; here the CLI fields win, so the fields are set
    // directly (identical values, one construction site in `profile.rs`).
    let _ = &mut ov;
    let policy = pol.resolve(&base, &ov, &roots)?;
    // 0.4.1 step 3: the display form of the rootfs — the store name when the
    // profile named one, else the path as given.
    let rootfs_display = match &args.rootfs_path {
        Some(p) => Some(p.to_string_lossy().into_owned()),
        None => rootfs
            .as_ref()
            .and_then(|r| r.name.clone().or_else(|| r.path.clone())),
    };
    let grants = args
        .grants
        .iter()
        .map(|g| parse_grant_spec(g).map_err(|e| anyhow!(e)))
        .collect::<Result<Vec<_>>>()?;
    Ok(Prepared {
        policy,
        grants,
        roots,
        risk_entries,
        services,
        forwards,
        host_services,
        ssh,
        rootfs_display,
    })
}

/// Risk entries when no profile document was loaded: build the synthetic
/// profile from the CLI overrides so the RISK line is still printed
/// (the same synthesis `compute_risk_entries` used before).
fn compute_risk_from_cli(args: &RunArgs) -> Result<Vec<profile::RiskEntry>> {
    if args.home_persist.is_some() || args.rootfs_path.is_some() {
        let synth = ProfileDoc {
            version: profile::PROFILE_VERSION.to_string(),
            policy: Policy::default(),
            home: args.home_persist.as_ref().map(|p| profile::HomeConfig {
                persist: Some(p.clone()),
            }),
            rootfs: args.rootfs_path.as_ref().map(|p| profile::RootfsConfig {
                name: None,
                path: Some(p.to_string_lossy().into_owned()),
            }),
            net: None,
            ssh: None,
            services: Vec::new(),
            forwards: Vec::new(),
            host_services: Vec::new(),
            docker: None,
        };
        Ok(profile::compute_risks(&synth))
    } else {
        Ok(Vec::new())
    }
}

fn mountinfo_check(policy: &ResolvedPolicy, roots: &[PathBuf]) -> Result<()> {
    let mi = fs::read_to_string("/proc/self/mountinfo")
        .context("reading mountinfo (R1b fails closed)")?;
    let mut trees: Vec<(PathBuf, bool)> = vec![(policy.cwd.clone(), true)];
    // 0.3.3: a `src:dst` bind is a host tree (`src`) mounted in the session;
    // the R1b alias check is about host paths, so it checks `src`.
    trees.extend(policy.ro_binds.iter().map(|b| (b.src.clone(), true)));
    trees.extend(policy.rw.iter().map(|p| (p.clone(), false)));
    for d in mounts::TOOLCHAIN_DIRS.iter().chain(&[mounts::NIX_DIR]) {
        if Path::new(d).is_dir() {
            trees.push((PathBuf::from(d), true));
        }
    }
    for (t, rec) in trees {
        match alias::check_tree(&mi, &t, rec, roots).map_err(|e| anyhow!("R1b: {e}"))? {
            None => {}
            Some(a) => bail!(
                "R1b: {} aliases the hisn runtime directory: {a:?}",
                t.display()
            ),
        }
    }
    Ok(())
}

fn static_rules(plan: &[mounts::MountOp], policy: &ResolvedPolicy, roots: &[PathBuf]) -> Rules {
    let mut rules = Rules {
        runtime_roots: roots.to_vec(),
        grantable_rw: policy.grantable_rw.clone(),
        ..Default::default()
    };
    for op in plan.iter().filter(|o| mounts::is_mount(&o.kind)) {
        rules.static_mounts.push(op.target.clone());
        if matches!(op.kind, mounts::MountKind::BindRo { .. }) {
            rules.static_ro.push(op.target.clone());
        }
    }
    // /etc is a sealed tmpfs: nothing may be granted writable under it either.
    rules.static_ro.push("/etc".into());
    rules.masks = plan
        .iter()
        .filter(|o| {
            matches!(
                o.kind,
                mounts::MountKind::MaskFile | mounts::MountKind::MaskDir
            )
        })
        .map(|o| o.target.clone())
        .collect();
    rules
}

/// 0.4.1 step 7: `hisn inspect` must not echo a secret-shaped `env.set` value.
/// Parses the resolved-policy TOML and replaces each `env.set` value whose key
/// looks secret (per `env::looks_secret`) with `<redacted>`, then re-serializes.
/// Parsing (not a line rewrite) means a value cannot leak through a multiline
/// TOML string escape. Pure; unit-tested. If the TOML does not parse, the
/// original is returned unchanged (inspect would fail to read it anyway).
pub fn redact_env_set(toml: &str) -> String {
    let mut v: toml::Value = match toml::from_str(toml) {
        Ok(v) => v,
        Err(_) => return toml.to_owned(),
    };
    if let Some(set) = v
        .get_mut("env")
        .and_then(|e| e.get_mut("set"))
        .and_then(|s| s.as_table_mut())
    {
        for (k, val) in set.iter_mut() {
            if crate::env::looks_secret(k) {
                *val = toml::Value::String("<redacted>".into());
            }
        }
    }
    toml::to_string_pretty(&v).unwrap_or_else(|_| toml.to_owned())
}

/// Number of descriptors this process has open (includes the one used to
/// count them, which is constant between calls).
pub fn open_fd_count() -> io::Result<usize> {
    Ok(fs::read_dir("/proc/self/fd")?.count())
}

/// Exit status of `hisn run` when the session fails to start (before "ready"):
/// a refused profile, a missing risk_ack, a home/persist refusal, a service
/// readiness timeout. The suite and the docs both name 125 (`EXIT_INTERNAL`).
/// A started session passes its command's own status through instead.
pub const EXIT_START_FAILED: i32 = 125;

/// Exit code of `hisn run`.
pub fn run(args: RunArgs, allow_host_abstract: bool, verbose: u8) -> Result<i32> {
    // 0.4.1 step 4: `hisn run --detach` returns as soon as the session is
    // ready. The parent forks a supervisor child (setsid, stdio to
    // <session-dir>/supervisor.log 0600), waits for the control socket to
    // accept (step 2's event wait), prints "<id> <name|-> ready" and exits 0.
    // Without --detach the process becomes the supervisor and blocks until the
    // session ends, exactly as before.
    if args.detach {
        return run_detached(args, allow_host_abstract, verbose);
    }
    run_supervisor(args, allow_host_abstract, verbose)
}

/// Print RISK lines to stderr (one per widening capability), unless
/// `--quiet-risk`. Also prints "RISK: none" at -v when there are none.
fn print_risk_lines(risk_entries: &[profile::RiskEntry], verbose: u8) {
    let lines = profile::format_risk_lines(risk_entries);
    for line in &lines {
        eprintln!("{line}");
    }
    if lines.is_empty() && verbose > 0 {
        eprintln!("RISK: none");
    }
}

/// Fork a supervisor for a `--detach` session, wait for readiness, print the
/// ready line, and return without waiting for the session to end.
fn run_detached(args: RunArgs, allow_host_abstract: bool, verbose: u8) -> Result<i32> {
    // Load and resolve the profile once, before fork, so the child inherits
    // the resolved state (single profile load per process, 0.4.3): the
    // child's `prepare` reuses this prepared state instead of re-reading
    // the file. RISK lines are printed in the parent before forking: the
    // child's stderr is /dev/null (closed by close_all_except + reopen)
    // until redirect_stdio_to_log replaces it with supervisor.log, so RISK
    // lines printed in the child would never reach the parent's caller.
    // (non-detached prints them in run_supervisor_inner as before.)
    let (uid, _gid, _username) = getids(verbose);
    let prepared = prepare(&args, uid)?;
    if !args.quiet_risk {
        print_risk_lines(&prepared.risk_entries, verbose);
    }

    let prepared = Some(prepared);

    // A pipe the child writes to when it is ready (the control socket accepts);
    // errors before readiness are reported through it too.
    let (read_fd, write_fd) = pipe_cloexec()?;
    // The child echoes the session id it created in its ready line (which may
    // be random when --session-id is absent), so the parent does not need to
    // resolve it.

    // SAFETY: fork before any threads exist (the supervisor starts them later).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error()).context("fork supervisor");
    }
    if pid == 0 {
        // Child: become a session leader, detach from the terminal. The child
        // runs the supervisor; it redirects its own stdio to the session log
        // once the session dir exists and reports readiness on `write_fd`.
        drop(read_fd);
        // SAFETY: setsid in the forked child.
        unsafe { libc::setsid() };
        // Close every inherited fd except the ready pipe write end. Without
        // this the child keeps the parent's stdout/stderr pipe ends open for
        // the session's lifetime, so a parent that holds those pipes (e.g.
        // Wakil's exec) never sees EOF ("WaitDelay expired before I/O
        // complete"). Fds 0–2 (the parent's stdin/stdout/stderr) are reopened
        // from /dev/null so eprintln! works before redirect_stdio_to_log
        // replaces them with supervisor.log. If --ready-fd N is also passed,
        // keep that fd too (run_session writes to it later).
        let mut keep = vec![write_fd.as_raw_fd()];
        if let Some(rfd) = args.ready_fd {
            keep.push(rfd);
        }
        sys::close_all_except(&keep);
        // Reopen fds 0–2 from /dev/null: close_all_except left them as the
        // inherited parent pipes (it starts at 3).
        // SAFETY: close and reopen 0/1/2 from /dev/null. This is the fork
        // child, before threads.
        unsafe {
            let _ = libc::close(0);
            let _ = libc::close(1);
            let _ = libc::close(2);
            let r = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
            if r > 0 {
                libc::dup2(r, 0);
                libc::close(r);
            }
            let w = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
            if w >= 0 {
                if w != 1 {
                    libc::dup2(w, 1);
                    libc::close(w);
                }
                let w2 = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
                if w2 >= 0 && w2 != 2 {
                    libc::dup2(w2, 2);
                    libc::close(w2);
                }
            }
        }
        let code = match run_supervisor_with_ready(
            args,
            allow_host_abstract,
            verbose,
            prepared,
            Some(write_fd),
        ) {
            Ok(c) => c,
            Err(e) => {
                // The child has no ready channel contract beyond writing; the
                // parent already holds the error via EOF if this fails early.
                eprintln!("hisn: {e:#}");
                EXIT_START_FAILED
            }
        };
        // SAFETY: _exit ends the child without running the parent's atexit.
        unsafe { libc::_exit(code.clamp(0, 255)) };
    }
    // Parent: close the write end so the read end sees EOF if the child dies.
    drop(write_fd);
    // Read exactly the first line ("ready <id>" or "error ..."): the child may
    // keep the pipe open for its lifetime, so reading to EOF would block.
    let report = {
        use std::io::BufRead;
        // SAFETY: read_fd is a fresh read end we own.
        let f = unsafe { std::fs::File::from_raw_fd(read_fd.into_raw_fd()) };
        let mut line = String::new();
        let _ = std::io::BufReader::new(f).read_line(&mut line);
        line
    };
    // Reap the child if it exited (a failed start).
    let mut status = 0;
    // SAFETY: waitpid on our own child, non-blocking.
    let reaped = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    let exited = reaped == pid;
    match parse_ready_report(report.trim_end()) {
        ReadyReport::Ready(id) => {
            let name = args.name.as_deref().unwrap_or("-");
            println!("{id} {name} ready");
            return Ok(0);
        }
        ReadyReport::Error(msg) => {
            if msg.is_empty() {
                eprintln!("hisn: session failed to start (supervisor exited before reporting)");
            } else {
                eprintln!("hisn: session failed to start: {msg}");
            }
        }
    }
    if !exited {
        // Still alive but never reported readiness: kill it so a half-started
        // session does not linger.
        // SAFETY: kill on our own child.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        // SAFETY: reap our own child.
        unsafe { libc::waitpid(pid, &mut status, 0) };
    }
    Ok(start_failure_exit())
}

/// The exit status of a detached `run` that did not reach "ready". Every
/// start failure, however it arrives, is [`EXIT_START_FAILED`]: this is the
/// single place the parent maps a failed start to a status (0.4.1 R1). Pure;
/// unit-tested over each start-failure kind.
fn start_failure_exit() -> i32 {
    EXIT_START_FAILED
}

/// The first line the detached child writes on the ready pipe.
#[derive(Debug, PartialEq, Eq)]
enum ReadyReport {
    /// The session id (the child echoes the id it created).
    Ready(String),
    /// A start failure's message (possibly empty).
    Error(String),
}

/// Parse the first line the detached child writes. Pure; unit-tested.
fn parse_ready_report(line: &str) -> ReadyReport {
    if let Some(id) = line.strip_prefix("ready ") {
        ReadyReport::Ready(id.trim().to_owned())
    } else if let Some(msg) = line.strip_prefix("error ") {
        ReadyReport::Error(msg.trim().to_owned())
    } else if line.is_empty() {
        ReadyReport::Error(String::new())
    } else {
        ReadyReport::Error(line.to_owned())
    }
}

fn run_supervisor(args: RunArgs, allow_host_abstract: bool, verbose: u8) -> Result<i32> {
    run_supervisor_with_ready(args, allow_host_abstract, verbose, None, None)
}

/// A CLOEXEC pipe as `(read, write)`.
fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe2 writes two descriptors into the array we own.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both are fresh descriptors owned by nobody else.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// 0.4.1 step 4: point the (detached) supervisor's stdout and stderr at
/// `<session-dir>/supervisor.log`, mode 0600, so it has somewhere to write
/// once the parent has returned. The file is opened by the supervisor (owner
/// uid) with O_NOFOLLOW|O_CREAT|O_APPEND and dup2'ed over fds 1 and 2.
fn redirect_stdio_to_log(session_dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let log_path = session_dir.join("supervisor.log");
    let f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&log_path)?;
    let fd = f.as_raw_fd();
    // SAFETY: dup2 onto our own stdout/stderr; both target fds are valid.
    if unsafe { libc::dup2(fd, 1) } < 0 || unsafe { libc::dup2(fd, 2) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The child side of [`run_detached`]: report a start failure through the ready
/// pipe so the parent can print it, then run the supervisor body.
fn run_supervisor_with_ready(
    args: RunArgs,
    allow_host_abstract: bool,
    verbose: u8,
    prepared: Option<Prepared>,
    ready_fd: Option<OwnedFd>,
) -> Result<i32> {
    // Dup the fd so the error path can write to it without consuming the
    // OwnedFd (which is moved into run_supervisor_inner). The dup is closed
    // here on both paths: on error after writing, on success after the
    // supervisor returns (it already dropped the original via `drop(fd)`).
    let fd_for_error = ready_fd.as_ref().map(|f| {
        // SAFETY: duplicate the fd; the dup is closed below on both paths.
        unsafe { libc::dup(f.as_raw_fd()) }
    });
    let r = run_supervisor_inner(args, allow_host_abstract, verbose, prepared, ready_fd);
    if let (Err(e), Some(dup)) = (&r, fd_for_error)
        && dup >= 0
    {
        use std::io::Write;
        // SAFETY: the dup is a fresh descriptor we own; from_raw_fd takes
        // ownership and File::drop closes it after the write.
        let mut f = unsafe { std::fs::File::from_raw_fd(dup) };
        let _ = writeln!(f, "error {e:#}");
        // File::drop closes the fd (from_raw_fd took ownership).
    } else if let Some(dup) = fd_for_error
        && dup >= 0
    {
        // Success path: the supervisor already closed the original via
        // `drop(fd)`. Close the dup so the pipe reaches EOF.
        // SAFETY: the dup is a valid fd we own.
        unsafe { libc::close(dup) };
    }
    r
}

fn run_supervisor_inner(
    args: RunArgs,
    allow_host_abstract: bool,
    verbose: u8,
    prepared: Option<Prepared>,
    ready_fd: Option<OwnedFd>,
) -> Result<i32> {
    let (uid, gid, username) = getids(verbose);
    // A detached start prepared the policy before fork (single load); reuse
    // it. Any other start prepares here. Either way the document is loaded
    // at most once per process.
    let prep = match prepared {
        Some(p) => p,
        None => prepare(&args, uid)?,
    };
    let policy = prep.policy;
    let risk_entries = prep.risk_entries;
    if !args.grants.iter().all(|g| !g.is_empty()) {
        bail!("empty --grant");
    }

    // Profile trust check: a profile loaded from a file path (--profile
    // /path/to/profile.toml) that lies under the session cwd, a rw grant,
    // mounts.rw, or a persistent home cannot satisfy risk_ack
    // (E_PROFILE_UNTRUSTED) — the sandbox can write it and self-ack its own
    // risk. Built-in and $HISN_PROFILES profiles are trusted (they are not
    // under the session's writable set).
    if let Some(ref spec) = args.profile
        && spec.contains('/')
    {
        let (path, _source) = profile::resolve_profile_path(spec)?;
        let mut rw_paths: Vec<PathBuf> = prep
            .grants
            .iter()
            .filter(|(_, m)| *m == Mode::Rw)
            .map(|(p, _)| PathBuf::from(p))
            .collect();
        // Also check against mounts.rw and persistent home from the inner
        // policy — the profile's own [policy] can declare these.
        rw_paths.extend(policy.rw.iter().cloned());
        if let crate::policy::Home::Path(ref p) = policy.home {
            rw_paths.push(p.clone());
        }
        let rw_refs: Vec<&Path> = rw_paths.iter().map(|p| p.as_path()).collect();
        profile::check_profile_trust(&path, profile::ProfileSource::Path, &policy.cwd, &rw_refs)
            .map_err(anyhow::Error::msg)?;
    }

    // Risk labels were computed in `prepare` from the same document as the
    // applied policy (single load); they are carried in `risk_entries`.

    // Print RISK lines on start (one per widening capability), unless --quiet-risk.
    // Under --detach the parent prints them before forking (the child's stderr
    // is /dev/null until redirect_stdio_to_log), so skip here in that case.
    if !args.quiet_risk && !args.detach {
        print_risk_lines(&risk_entries, verbose);
    }

    // Preflight: fail early with a readable report instead of an EPERM.
    let report = crate::check::run_checks();
    if !report.ok() {
        bail!("this host cannot run hisn sessions:\n{}", report.render());
    }
    mountinfo_check(&policy, &prep.roots)?;

    let facts = HostFacts::probe(&policy, uid, gid, &username);
    // Only rw initial grants need a pre-created directory (Landlock anchors a
    // write rule on an existing inode). ro grants are created by the helper and
    // removed again on revoke, so a revoked ro path is ENOENT again.
    let grant_dirs: Vec<PathBuf> = prep
        .grants
        .iter()
        .filter(|(_, m)| *m == Mode::Rw)
        .map(|(p, _)| PathBuf::from(p))
        .collect();
    let plan = mounts::plan(&policy, &facts, &grant_dirs).context("mount plan")?;

    let id = match &args.session_id {
        Some(i) if is_valid_session_id(i) => i.clone(),
        Some(i) => bail!("invalid session id {i:?}"),
        None => session::random_id()?,
    };
    let root = session::pick_root(&prep.roots);
    // Handle a stale session dir for the same id: remove it and proceed.
    // A live dir is still an error (E_EXISTS).
    let dir_path = root.join(&id);
    if dir_path.is_dir() {
        if session::is_stale(&dir_path) {
            if let Err(e) = session::remove_safe(&dir_path, uid) {
                tracing::warn!("stale session {id}: removal refused: {e}");
                bail!("session {id} exists and cannot be removed: {e}");
            }
            tracing::info!("stale session {id}: removed");
        } else {
            bail!("session {id} already exists");
        }
    }
    // 0.4.0 step 1b: reserve the name (per-user registry, /tmp root), build
    // the session in `.tmp-<id>`, then publish it with one rename. A failure
    // before publication removes the tmp dir and releases the name.
    let reg_root = crate::registry::registry_root(uid);
    let name = args.name.clone();
    if let Some(n) = &name {
        let _lock = crate::registry::Lock::take(&reg_root, uid)?;
        crate::registry::reserve(&reg_root, &prep.roots, n, &id).map_err(anyhow::Error::from)?;
    }
    let tmp = match SessionDir::create_tmp(&root, uid, &id) {
        Ok(t) => t,
        Err(e) => {
            if let Some(n) = &name {
                let _lock = crate::registry::Lock::take(&reg_root, uid)?;
                let _ = crate::registry::release(&reg_root, n, &id);
            }
            return Err(e.into());
        }
    };
    let owner = sessionmeta::Owner {
        uid,
        label: crate::session::local_label(),
        client_id: String::new(),
    };
    // 0.4.0 step 4: parse --env K=V as the session env snapshot. Computed
    // names (HOME, USER, LOGNAME, cache vars) are refused at run with the
    // same error exec gives. Secret-looking values are stored on disk as
    // "<redacted>"; the real values go into the exec base_env.
    // 0.4.1 step 6: --env-file PATH adds KEY=VALUE lines (validated the same
    // way); it is the documented way to pass secret-shaped values, since they
    // never appear in /proc/<pid>/cmdline.
    let mut env_pairs: Vec<(String, String)> = Vec::new();
    for pair in &args.env {
        match pair.split_once('=') {
            Some((k, v)) if !k.is_empty() => env_pairs.push((k.to_owned(), v.to_owned())),
            _ => bail!("--env {pair:?}: expected K=V"),
        }
    }
    for path in &args.env_files {
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("--env-file {}", path.display()))?;
        let pairs = crate::cli::parse_env_file(&body)
            .map_err(|e| anyhow!("--env-file {}: {e}", path.display()))?;
        env_pairs.extend(pairs);
    }
    let mut declared_env: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    let mut declared_env_disk: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for (k, v) in env_pairs {
        if crate::env::is_computed(&k) {
            bail!("--env {k}: computed name (HOME, USER, LOGNAME, cache vars) cannot be declared");
        }
        declared_env.insert(k.clone(), v.clone());
        if crate::env::looks_secret(&k) {
            declared_env_disk.insert(k, "<redacted>".into());
        } else {
            declared_env_disk.insert(k, v);
        }
    }
    let prepared = (|| -> Result<()> {
        if let Some(n) = &name {
            crate::registry::write_name_file(&tmp.path, n)?;
        }
        let mut meta = sessionmeta::SessionMeta::new(
            &id,
            name.as_deref(),
            owner,
            &policy.cwd.to_string_lossy(),
            match policy.network {
                Network::None => "none",
                Network::Host => "host",
            },
        );
        meta.env_declared = declared_env_disk.clone();
        // 0.4.1 step 3: record the rootfs (name or path as given) so `ls`
        // shows it whether it came from a profile name or a path.
        meta.rootfs = prep.rootfs_display.clone();
        if let Some(timeout) = policy.idle_timeout_s {
            meta.lease = Some(sessionmeta::Lease {
                idle_timeout_s: Some(timeout),
                last_activity: Some(session::rfc3339_now()),
            });
        }
        meta.write_to(&tmp.path)?;
        Ok(())
    })();
    if let Err(e) = prepared {
        tmp.remove();
        if let Some(n) = &name {
            let _lock = crate::registry::Lock::take(&reg_root, uid)?;
            let _ = crate::registry::release(&reg_root, n, &id);
        }
        return Err(e);
    }
    let idle_timeout_s = policy.idle_timeout_s;
    let sdir = tmp.publish(&root)?;
    let _ = sessionmeta::set_state(&sdir.path, sessionmeta::State::Running);
    let result = run_session(SessionStart {
        args: &args,
        policy,
        plan,
        initial: prep.grants,
        sdir: &sdir,
        roots: prep.roots,
        uid,
        gid,
        username: &facts.username,
        allow_host_abstract,
        verbose,
        risk_entries: &risk_entries,
        services: &prep.services,
        forwards: &prep.forwards,
        host_services: &prep.host_services,
        ssh: prep.ssh.as_ref(),
        session_id: &id,
        declared_env: &declared_env,
        ready_fd,
    });
    // 0.4.0 step 5 / O3: keep the dir as stopped if the session was stopped
    // (hisn stop or idle expiry). Otherwise remove it (normal exit).
    let end = result.as_ref().ok().map(|e| {
        crate::lifecycle::end_of_session(
            &sdir.path,
            name.as_deref().unwrap_or(&id),
            idle_timeout_s,
            e.idle_expired_after,
            e.code,
        )
    });
    let keep = match &end {
        Some(e) => e.keep,
        // A failed start: unchanged — keep only a dir already `stopped`.
        None => {
            sessionmeta::read(&sdir.path).is_some_and(|m| m.state == sessionmeta::State::Stopped)
        }
    };
    if !keep {
        sdir.remove();
        // Release the name only when the dir was actually removed (a normal
        // end). A kept dir (stopped/crashed) holds its name until
        // `ls --prune` removes it and repairs the index (0.4.1 step 6).
        if let Some(n) = &name {
            let _lock = crate::registry::Lock::take(&reg_root, uid)?;
            let _ = crate::registry::release(&reg_root, n, &id);
        }
    }
    result?;
    let end = end.expect("end is computed for an Ok result");
    if let Some(m) = &end.message {
        eprintln!("{m}");
    }
    Ok(end.code)
}

/// How a session ended: the command's (or init's) code, and the idle time
/// when the idle timer stopped it.
struct SessionEnd {
    code: i32,
    idle_expired_after: Option<u64>,
}

/// The session's init as a [`crate::lifecycle::StopTarget`], held by a
/// pidfd opened while init is our unreaped child: once `relay_and_wait`
/// reaps it the pidfd refers to the dead process, so a reused pid is never
/// signalled. Without pidfd support (pre-5.3 kernels) it falls back to the
/// pid; init is then reaped only by `relay_and_wait`, after which the timer
/// thread is joined, so the window is the reap-to-exit-check gap.
struct InitTarget {
    pid: i32,
    pidfd: Option<OwnedFd>,
}

impl InitTarget {
    fn new(pid: i32) -> Self {
        Self {
            pid,
            pidfd: sys::pidfd_open(pid).ok(),
        }
    }
}

impl crate::lifecycle::StopTarget for InitTarget {
    fn signal(&self, sig: i32) -> std::result::Result<(), String> {
        match &self.pidfd {
            Some(fd) => {
                // SAFETY: plain syscall on our own pidfd.
                let r = unsafe {
                    libc::syscall(libc::SYS_pidfd_send_signal, fd.as_raw_fd(), sig, 0usize, 0)
                };
                if r == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error().to_string())
                }
            }
            None => sys::kill(self.pid, sig).map_err(|e| e.to_string()),
        }
    }

    fn exited(&self) -> bool {
        // A zombie still "exists" for signal 0; it is reaped promptly by
        // relay_and_wait, so "exited" lags by at most one reap.
        match &self.pidfd {
            Some(fd) => !sys::pidfd_alive(fd.as_raw_fd()),
            // SAFETY: signal 0 only checks for existence.
            None => unsafe { libc::kill(self.pid, 0) != 0 },
        }
    }

    fn exit_fd(&self) -> Option<std::os::fd::RawFd> {
        // 0.4.1 step 2: a pidfd makes the idle-expiry stop wait event-driven.
        self.pidfd.as_ref().map(std::os::fd::AsRawFd::as_raw_fd)
    }
}

impl crate::lifecycle::IdleSession for Shared {
    fn has_connected_clients(&self) -> bool {
        Shared::has_connected_clients(self)
    }

    fn has_running_execs(&self) -> bool {
        Shared::has_running_execs(self)
    }

    fn last_activity_secs(&self) -> i64 {
        Shared::last_activity_secs(self)
    }

    fn idle_snapshot(&self) -> (bool, bool, i64) {
        Shared::idle_snapshot(self)
    }

    fn audit_lease_expired(&self) {
        self.log("lease", "expired", None, None, Some("idle"), None);
    }
}

/// One input struct for [`run_session`], replacing its 19 parameters
/// (0.4.3): every field is one former parameter, in the former order.
struct SessionStart<'a> {
    args: &'a RunArgs,
    policy: ResolvedPolicy,
    plan: Vec<mounts::MountOp>,
    initial: Vec<(String, Mode)>,
    sdir: &'a SessionDir,
    roots: Vec<PathBuf>,
    uid: u32,
    gid: u32,
    username: &'a str,
    allow_host_abstract: bool,
    verbose: u8,
    risk_entries: &'a [profile::RiskEntry],
    services: &'a [profile::Service],
    forwards: &'a [profile::Forward],
    host_services: &'a [profile::HostService],
    ssh: Option<&'a profile::SshConfig>,
    session_id: &'a str,
    declared_env: &'a std::collections::BTreeMap<String, String>,
    ready_fd: Option<OwnedFd>,
}

/// Early-exit cleanup for a started session (0.4.3): on drop, kills the
/// already-started host services and then init and reaps all of them — the
/// order the hand-copied early exits used. Disarmed on the success path
/// (after `relay_and_wait`), where the normal stop path owns cleanup.
///
/// The `Drop` impl never panics: kills and reaps ignore errors, and a reap
/// of an already-reaped pid is a no-op waitpid error.
struct SessionGuard {
    init_pid: i32,
    host_pids: Vec<i32>,
    armed: bool,
}

impl SessionGuard {
    fn new(init_pid: i32) -> Self {
        Self {
            init_pid,
            host_pids: Vec::new(),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        for pid in &self.host_pids {
            // Host services run in their own process group (leader's pid is
            // the group id): kill the whole group, so children the service
            // spawned die with it on a failed start too. `killpg` tolerates
            // a group that is already gone; the direct kill covers the
            // leader if the group was never made. `killpg` is tried first:
            // a leader that already exited on its own still has its zombie
            // pinning the group id until reaped, so the group kill reaches
            // its children; reaping happens after in the loop below. A
            // reaped pid is never signalled (readiness dead-detection
            // removes it from `host_pids`).
            // SAFETY: killpg/kill on our own child and its group.
            unsafe {
                libc::killpg(*pid, libc::SIGKILL);
                libc::kill(*pid, libc::SIGKILL);
            }
            let _ = services::reap(*pid);
        }
        let _ = sys::kill(self.init_pid, libc::SIGKILL);
        let _ = services::reap(self.init_pid);
    }
}

fn run_session(start: SessionStart<'_>) -> Result<SessionEnd> {
    let SessionStart {
        args,
        policy,
        plan,
        initial,
        sdir,
        roots,
        uid,
        gid,
        username,
        allow_host_abstract,
        verbose,
        risk_entries,
        services,
        forwards,
        host_services,
        ssh,
        session_id,
        declared_env,
        ready_fd,
    } = start;
    // Phase: prepare.
    prepare_session_files(sdir, &policy, risk_entries)?;
    let (audit, tty, root_dir) = prepare_session_dirs(sdir, args)?;
    let mut rules = static_rules(&plan, &policy, &roots);
    let prepared = prepare_session_env(
        &mut PrepareEnvArgs {
            policy: &policy,
            plan: &plan,
            initial: &initial,
            username,
            declared_env,
            ssh,
            sdir,
        },
        &mut rules,
    )?;
    let exec_rules = prepared.exec_rules.clone();
    let exec_rules_for_services = exec_rules.clone();
    let exec_policy = policy.clone();
    let exec_ll = prepared.ll.clone();
    let exec_require_scope = landlock::scope_required(&policy, allow_host_abstract);
    let exec_seccomp = prepared.seccomp_progs.clone();

    let cfg = InitConfig {
        policy: policy.clone(),
        plan: plan.clone(),
        landlock: prepared.ll,
        require_scope: landlock::scope_required(&policy, allow_host_abstract),
        seccomp: prepared.seccomp_progs,
        root_dir,
        argv: args.command.clone(),
        env: prepared.session_env,
        use_pty: tty,
        detach: args.detach,
        uid,
        gid,
    };

    // Phase: namespaces (userns S + init clone + GO/READY handshake).
    let Namespaces {
        pid,
        master,
        sup_end,
        sandbox_pidns,
        mntns_fd,
        exec_ns,
    } = start_namespaces(uid, gid, cfg, verbose, sdir)?;
    let mut guard = SessionGuard::new(pid);

    // Phase: helpers (grant helper + exec helper, still single-threaded).
    // The namespace fds are dropped as soon as the helpers are forked (the
    // helpers hold their own dups): the supervisor must not pin the
    // namespaces — and hold 7–8 extra fds — for the session's lifetime.
    let (helper, exec_client) = start_helpers(
        &mntns_fd,
        exec_ns,
        exec_policy,
        exec_ll,
        exec_require_scope,
        exec_seccomp,
    )?;
    drop(mntns_fd);

    // Phase: control (shared state, listener, initial grants, forwards, SSH).
    let control = start_control(&mut SessionControlArgs {
        uid,
        pid,
        sandbox_pidns,
        policy: &policy,
        risk_entries,
        rules,
        helper: Some(helper),
        audit: Some(audit),
        exec_client: Some(exec_client),
        exec_rules: Some(exec_rules),
        sdir,
        allow_host_abstract,
        initial: &initial,
        forwards,
        ssh_proxy_listener: prepared.ssh_proxy_listener,
        ssh,
        session_id,
    })?;
    let shared = control.shared;
    let listener = control.listener;
    let handler = control.handler;
    let ssh_agent_expose = control.ssh_agent_expose;

    // Phase: services (host services, then in-sandbox services).
    let mut host_pids: Vec<(i32, profile::StopSpec)> = Vec::new();
    start_host_services(host_services, &shared, &mut guard, &mut host_pids)?;
    let service_handles = start_in_sandbox_services(services, &shared, &exec_rules_for_services)?;

    // START + control thread + ready reporting.
    sys::send_with_fd(sup_end.as_raw_fd(), &[MSG_START], None)?;
    thread::spawn(move || {
        // Process-directed signals (SIGCHLD, SIGTERM, ...) must be handled by
        // the main thread, which waits for them in `sigsuspend`. A thread that
        // leaves them unblocked can be picked by the kernel as the recipient:
        // the handler then runs here and the main thread is never woken.
        // Threads spawned by `serve` inherit this mask.
        let _ = sig::block(&[
            libc::SIGTERM,
            libc::SIGINT,
            libc::SIGHUP,
            libc::SIGWINCH,
            libc::SIGCHLD,
        ]);
        control::serve(listener, handler)
    });
    report_ready(args, ready_fd, sdir, session_id, ssh_agent_expose);

    // Phase: wait (idle timer + relay).
    let idle_timer = start_idle_timer(&policy, &shared, pid);
    let code = relay_and_wait(pid, master, tty);
    // The session is live and ending on the normal path: the guard must not
    // kill and reap init again (relay_and_wait already reaped it). The stop
    // paths below own the remaining cleanup.
    guard.disarm();
    let idle_expired_after = idle_timer.and_then(|t| t.join().ok().flatten());

    // Phase: teardown (host services, in-sandbox services, drain).
    teardown_services(&host_pids, &service_handles);
    control::drain(std::time::Duration::from_secs(2));
    drop(shared);
    Ok(SessionEnd {
        code,
        idle_expired_after,
    })
}

/// Phase `prepare` (file part): write the resolved policy, `risk.json`,
/// the audit log handle and `supervisor.pid`. Before any namespace setup.
fn prepare_session_files(
    sdir: &SessionDir,
    policy: &ResolvedPolicy,
    risk_entries: &[profile::RiskEntry],
) -> Result<()> {
    sdir.write_resolved_policy(&policy.to_toml())?;
    // Write risk.json (the risk labels for this session, DESIGN §16).
    let risk_json = serde_json::to_string_pretty(&serde_json::json!({
        "labels": risk_entries.iter().map(|e| serde_json::json!({
            "capability": e.capability,
            "label": e.label.kebab(),
        })).collect::<Vec<_>>(),
    }))?;
    fs::write(sdir.path.join("risk.json"), risk_json).context("writing risk.json")?;
    // Write supervisor.pid for stale-detection. Written after the dir is
    // created and before unshare — a crash here leaves a dir without the
    // pid file, which is_stale treats as "not stale" (fail safe).
    sdir.write_supervisor_pid(std::process::id() as i32)
        .context("writing supervisor.pid")?;
    Ok(())
}

/// Phase `prepare` (dirs part): open the audit log, report whether stdio is
/// a terminal, create the sandbox root dir.
fn prepare_session_dirs(sdir: &SessionDir, args: &RunArgs) -> Result<(Audit, bool, PathBuf)> {
    let audit = Audit::open(&sdir.audit_path())?;
    // A detached session has no command, hence no terminal to relay.
    let tty = !args.detach && sys::isatty(0);
    let root_dir = sdir.path.join("root");
    fs::create_dir(&root_dir).context("creating root dir")?;
    Ok((audit, tty, root_dir))
}

/// Phase `prepare` (env part): landlock/seccomp plans, step-7 scrub,
/// SSH proxy listener binding, session-env composition and exec rules.
struct PreparedEnv {
    ll: crate::landlock::LandlockPlan,
    seccomp_progs: Vec<seccompiler::BpfProgram>,
    session_env: std::collections::BTreeMap<String, String>,
    exec_rules: ExecRules,
    ssh_proxy_listener: Option<UnixListener>,
}

struct PrepareEnvArgs<'a> {
    policy: &'a ResolvedPolicy,
    plan: &'a [mounts::MountOp],
    initial: &'a [(String, Mode)],
    username: &'a str,
    declared_env: &'a std::collections::BTreeMap<String, String>,
    ssh: Option<&'a profile::SshConfig>,
    sdir: &'a SessionDir,
}

fn prepare_session_env(a: &mut PrepareEnvArgs<'_>, rules: &mut Rules) -> Result<PreparedEnv> {
    let policy = a.policy;
    let plan = a.plan;
    let initial = a.initial;
    let username = a.username;
    let declared_env = a.declared_env;
    let ssh = a.ssh;
    let sdir = a.sdir;
    // Landlock write set includes initial rw grants.
    let initial_rw: Vec<PathBuf> = initial
        .iter()
        .filter(|(_, m)| *m == Mode::Rw)
        .map(|(p, _)| PathBuf::from(p))
        .collect();
    // An initial rw grant is part of the Landlock write set by construction, so
    // the grant rules must accept it (round-2 finding).
    rules.grantable_rw.extend(initial_rw.iter().cloned());
    let ll = landlock::plan(policy, &initial_rw);
    let seccomp_progs = seccomp::build(&policy.extra_deny)?;

    // 0.4.1 step 7: read the host env with `vars_os` — `env::vars()` panics on a
    // non-UTF-8 name/value, and the host env is untrusted. Non-UTF-8 entries
    // are converted lossily; the scrub allowlist then decides what reaches the
    // child, so a lossy value cannot leak an unvetted name.
    let host_env: Vec<(String, String)> = std::env::vars_os()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            )
        })
        .collect();
    let visible = |p: &Path| {
        mounts::expected_targets(plan)
            .iter()
            .any(|t| p.starts_with(t))
            || p.starts_with(&policy.cwd)
    };
    let scrub = senv::scrub(
        policy,
        host_env.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        username,
        visible,
    );

    // 0.3.2: SSH agent T1 proxy. Bind the proxy socket on the host side
    // (before unshare — must not spawn threads), then spawn the accept loop
    // after the init clone (the process is multithreaded by then). The
    // proxy socket is forwarded into the sandbox at /run/ssh-agent.sock
    // and SSH_AUTH_SOCK is set in the scrubbed env.
    let mut ssh_proxy_listener: Option<UnixListener> = None;
    let ssh_agent_expose = "/run/ssh-agent.sock";
    let mut ssh_sock_expose: Option<&str> = None;
    if let Some(ssh_cfg) = ssh
        && ssh_cfg.agent
    {
        let host_auth_sock = std::env::var("SSH_AUTH_SOCK")
            .context("ssh-agent: SSH_AUTH_SOCK is not set (agent = true requires a host agent)")?;
        crate::ssh_agent::check_host_agent(&host_auth_sock)?;
        let proxy_socket_path = sdir.path.join("ssh-agent.sock");
        ssh_proxy_listener = Some(
            crate::ssh_agent::bind_proxy_socket(&proxy_socket_path).context("ssh-agent proxy")?,
        );
        // The proxy socket is forwarded into the sandbox at
        // ssh_agent_expose after init is ready; SSH_AUTH_SOCK is injected
        // into the session env by compose_session_env below.
        ssh_sock_expose = Some(ssh_agent_expose);
    }

    for n in &scrub.secretish_passed {
        eprintln!("hisn: warning: env.pass forwards {n}, which looks like a secret");
    }

    // 0.4.0 step 4: ONE composition for the main command and every
    // exec/attach (env::compose_session_env, unit-tested): scrub base
    // (env_pass, env_set, computed) < SSH_AUTH_SOCK < declared --env keys.
    // Computed names cannot appear in declared_env — run() refuses them.
    let session_env = crate::env::compose_session_env(scrub, ssh_sock_expose, declared_env);
    let exec_rules = ExecRules {
        env_pass: policy.env_pass.clone(),
        base_env: session_env.clone(),
        default_cwd: policy.cwd.display().to_string(),
        declared_env: declared_env.keys().cloned().collect(),
    };
    Ok(PreparedEnv {
        ll,
        seccomp_progs,
        session_env,
        exec_rules,
        ssh_proxy_listener,
    })
}

/// Phase `namespaces`: userns S, init clone, namespace fds, GO/READY.
struct Namespaces {
    pid: i32,
    master: Option<OwnedFd>,
    sup_end: OwnedFd,
    sandbox_pidns: u64,
    mntns_fd: OwnedFd,
    exec_ns: NsFds,
}

fn start_namespaces(
    uid: u32,
    gid: u32,
    cfg: InitConfig,
    verbose: u8,
    sdir: &SessionDir,
) -> Result<Namespaces> {
    // ---- 2. our own userns S + mount-ns copy (single-threaded here)
    write_s_maps_and_unshare(uid, gid)?;

    // ---- 3. clone init
    let (sup_end, init_end) = sys::socketpair()?;
    let mut flags = libc::CLONE_NEWUSER
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS;
    if cfg.policy.network == Network::None {
        flags |= libc::CLONE_NEWNET;
    }
    // SAFETY: single-threaded; the child immediately enters `init_main`,
    // which never returns into the supervisor's state.
    let pid = unsafe { sys::clone_ns(flags) }
        .context("clone sandbox init (are unprivileged user namespaces enabled?)")?;
    if pid == 0 {
        drop(sup_end);
        init::init_main(cfg, init_end);
    }
    drop(init_end);
    if verbose > 0 {
        eprintln!("hisn: session {} init pid {pid}", sdir.id);
    }

    // ---- 4. namespace fds, GO, READY
    let mntns_fd = open_ns(pid, "mnt")?;
    // The exec helper's namespaces, opened before `GO` while init is still
    // dumpable (D24). The root fd is not among them: see below.
    let ns_user = open_ns(pid, "user")?;
    let ns_mnt = open_ns(pid, "mnt")?;
    let ns_ipc = open_ns(pid, "ipc")?;
    let ns_uts = open_ns(pid, "uts")?;
    let ns_pid = open_ns(pid, "pid")?;
    let ns_net = if cfg.policy.network == Network::None {
        Some(open_ns(pid, "net")?)
    } else {
        None
    };
    let sandbox_pidns = sys::ns_inode(pid, "pid").context("sandbox pid namespace")?;
    sys::send_with_fd(sup_end.as_raw_fd(), &[MSG_GO], None)?;
    let mut buf = [0u8; 4096];
    let ready =
        sys::recv_with_fds(sup_end.as_raw_fd(), &mut buf).context("waiting for sandbox setup")?;
    if ready.truncated {
        bail!("sandbox init sent an oversized setup message");
    }
    let n = ready.len;
    // READY carries the sandbox root fd, then (with a pty) the pty master.
    let mut ready_fds = ready.fds.into_iter();
    let ready_root = ready_fds.next();
    let master = ready_fds.next();
    if n == 0 {
        let code = services::reap(pid);
        bail!(
            "sandbox init exited during setup (status {code}); run with -v and check `hisn check`"
        );
    }
    match buf[0] {
        MSG_READY => {}
        MSG_ERROR => {
            let _ = services::reap(pid);
            bail!(
                "sandbox setup failed: {}",
                String::from_utf8_lossy(&buf[1..n])
            );
        }
        other => bail!("unexpected message {other:#x} from sandbox init"),
    }

    // The sandbox root comes from init itself, passed with READY (D25): by
    // now init is non-dumpable (D6), so `/proc/<init>/root` is out of reach,
    // and before `GO` it would still be the host root.
    let root = ready_root.ok_or_else(|| anyhow!("sandbox init sent READY without its root fd"))?;
    if !fs::File::from(root.try_clone()?).metadata()?.is_dir() {
        bail!("sandbox root descriptor is not a directory");
    }
    let exec_ns = NsFds {
        user: ns_user,
        mnt: ns_mnt,
        ipc: ns_ipc,
        uts: ns_uts,
        pid: ns_pid,
        net: ns_net,
        root,
    };
    Ok(Namespaces {
        pid,
        master,
        sup_end,
        sandbox_pidns,
        mntns_fd,
        exec_ns,
    })
}

/// Phase `helpers`: the persistent grant helper and the exec helper,
/// forked while still single-threaded. Both namespace fds are consumed
/// here (moved into the exec helper; the grant helper keeps its own dup
/// of the mount namespace), so the caller can drop its originals.
fn start_helpers(
    mntns_fd: &OwnedFd,
    exec_ns: NsFds,
    exec_policy: ResolvedPolicy,
    exec_ll: crate::landlock::LandlockPlan,
    exec_require_scope: bool,
    exec_seccomp: Vec<seccompiler::BpfProgram>,
) -> Result<(HelperClient, ExecClient)> {
    let helper = spawn_helper(mntns_fd)?;
    let exec_client = spawn_exec_helper(ExecContext {
        policy: exec_policy,
        landlock: exec_ll,
        require_scope: exec_require_scope,
        seccomp: exec_seccomp,
        ns: exec_ns,
    })?;
    Ok((helper, exec_client))
}

/// Phase `control`: the shared state, the control listener, the initial
/// grants, the forwards and the SSH forward. The listener is bound here;
/// it only accepts once the control thread starts (in `run_session`).
struct SessionControlArgs<'a> {
    uid: u32,
    pid: i32,
    sandbox_pidns: u64,
    policy: &'a ResolvedPolicy,
    risk_entries: &'a [profile::RiskEntry],
    rules: Rules,
    helper: Option<HelperClient>,
    audit: Option<Audit>,
    exec_client: Option<ExecClient>,
    exec_rules: Option<ExecRules>,
    sdir: &'a SessionDir,
    allow_host_abstract: bool,
    initial: &'a [(String, Mode)],
    forwards: &'a [profile::Forward],
    ssh_proxy_listener: Option<UnixListener>,
    ssh: Option<&'a profile::SshConfig>,
    session_id: &'a str,
}

struct SessionControl {
    shared: Arc<Shared>,
    listener: UnixListener,
    handler: Arc<dyn Handler>,
    ssh_agent_expose: &'static str,
}

fn start_control(a: &mut SessionControlArgs<'_>) -> Result<SessionControl> {
    let ssh_agent_expose = "/run/ssh-agent.sock";
    let mut ssh_proxy_listener = a.ssh_proxy_listener.take();
    let listener = bind_socket(&a.sdir.socket_path())?;
    let shared = Arc::new(Shared {
        uid: a.uid,
        init_pid: a.pid,
        sandbox_pidns: a.sandbox_pidns,
        resolved_toml: a.policy.to_toml(),
        risk: a.risk_entries.to_vec(),
        rules: std::mem::take(&mut a.rules),
        table: Mutex::new(GrantTable::default()),
        held: Mutex::new(Default::default()),
        helper: Mutex::new(a.helper.take().expect("helper moved into control")),
        audit: a.audit.take().expect("audit moved into control"),
        op_lock: Mutex::new(()),
        exec: a
            .exec_client
            .take()
            .expect("exec client moved into control"),
        exec_rules: a.exec_rules.take().expect("exec rules moved into control"),
        spawn_gate: RwLock::new(()),
        exec_table: Mutex::new(ExecTable::default()),
        next_exec_id: std::sync::atomic::AtomicU64::new(1),
        seq: std::sync::atomic::AtomicU64::new(1),
        conns: Mutex::new(ConnRegistry::default()),
        services: Mutex::new(Default::default()),
        session_dir: a.sdir.path.clone(),
        session_json_lock: Mutex::new(()),
        idle_timeout_s: a.policy.idle_timeout_s,
        members_lock: Mutex::new(Default::default()),
        lease_lock: Mutex::new(()),
        lease_last_touch: Mutex::new(None),
        // The session start is activity (as in session.json's lease): a seat
        // nobody ever connects to expires too.
        last_activity_secs: std::sync::atomic::AtomicI64::new(crate::lifecycle::Clock::now_secs(
            &crate::lifecycle::SystemClock,
        )),
    });
    // The only way to start `network = "host"` without abstract-socket
    // scoping is the explicit flag; it is audited (DESIGN §7, B1).
    if a.allow_host_abstract && a.policy.network == Network::Host {
        shared.log(
            "session",
            "start",
            None,
            None,
            Some("allow-host-abstract-sockets"),
            None,
        );
    }
    let handler: Arc<dyn Handler> = Arc::new(Ctl {
        sh: Arc::clone(&shared),
    });
    // The initial grants go through the same code as dynamic ones, called
    // directly: the socket is bound (clients queue in its backlog) but only
    // accepts once the session is fully set up (DESIGN §14.7).
    for (path, mode) in a.initial {
        let internal = authz::ClientRecord::internal(shared.uid, shared.next_seq());
        let auth = authz::authorize(
            &internal,
            &authz::SessionAuth {
                owner_uid: shared.uid,
            },
            &Request::Grant {
                path: path.to_string(),
                mode: *mode,
                recursive: false,
                client: None,
            },
        )
        .expect("internal startup grant is authorized as the owner");
        let r = shared.do_grant(&auth, &internal, path, *mode, false);
        if r["ok"] != true {
            bail!(
                "initial grant {path}: {}",
                r["message"].as_str().unwrap_or("failed")
            );
        }
    }
    // Process [[forward]] entries (DESIGN §17): expose host sockets inside.
    for f in a.forwards {
        if let Err(e) = shared.do_forward(&f.socket, &f.expose, &f.name) {
            bail!("forward {}: {e}", f.name);
        }
    }
    // 0.3.2: Spawn the SSH agent proxy accept loop and forward its socket
    // into the sandbox. The listener was bound before unshare (single-
    // threaded); the accept loop is spawned now (post-clone, multithreaded).
    if let Some(listener) = ssh_proxy_listener.take() {
        let host_auth_sock = std::env::var("SSH_AUTH_SOCK").unwrap_or_default();
        let ssh_keys = a
            .ssh
            .and_then(|c| if c.agent { Some(c.keys.clone()) } else { None })
            .unwrap_or_default();
        let _ssh_handle = crate::ssh_agent::spawn_accept_loop(
            listener,
            host_auth_sock,
            ssh_keys,
            a.session_id.to_owned(),
        );
        let proxy_socket_path = a.sdir.path.join("ssh-agent.sock");
        if let Err(e) = shared.do_forward_inner(
            proxy_socket_path.to_str().unwrap_or(""),
            ssh_agent_expose,
            "ssh-agent",
            true,
        ) {
            bail!("ssh-agent forward: {e}");
        }
    }
    Ok(SessionControl {
        shared,
        listener,
        handler,
        ssh_agent_expose,
    })
}

/// Phase `services` (host part): start each `[[host_services]]` process,
/// wait for readiness and forward its socket. Fail closed on any error;
/// the caller-owned `guard` performs the kill+reap of already-started
/// processes and init when this function returns an error (the guard's
/// `Drop` runs on the `?` unwinding), and `host_pids` collects the
/// `(pid, stop spec)` pairs the teardown phase needs.
fn start_host_services(
    host_services: &[profile::HostService],
    shared: &Arc<Shared>,
    guard: &mut SessionGuard,
    host_pids: &mut Vec<(i32, profile::StopSpec)>,
) -> Result<()> {
    for h in host_services {
        let stop_spec = h.stop.clone().unwrap_or(profile::StopSpec {
            signal: "TERM".into(),
            grace: 5,
        });
        match services::start_host_service(h) {
            Ok(host_pid) => {
                // Register with the guard before the fallible steps, so an
                // error here still kills this process (before init, as
                // before).
                guard.host_pids.push(host_pid);
                // Wait for readiness (fails at once if the service dies).
                // The pid check reaps the child on detection, so an
                // already-reaped pid must leave the guard's kill set: the
                // guard never signals a reaped pid.
                let timeout_secs = h.ready.as_ref().and_then(|r| r.timeout).unwrap_or(15);
                let ready = services::wait_readiness_pid(h, timeout_secs, Some(host_pid));
                match ready {
                    Ok(()) => {}
                    Err(status) if status >= 0 => {
                        guard.host_pids.retain(|p| *p != host_pid);
                        bail!(
                            "host_service {}: exited with status {status} before readiness completed",
                            h.name
                        );
                    }
                    Err(-1) => {
                        bail!(
                            "host_service {}: socket {} does not exist",
                            h.name,
                            h.socket
                        );
                    }
                    Err(-2) => {
                        bail!(
                            "host_service {}: readiness timeout ({}s)",
                            h.name,
                            timeout_secs
                        );
                    }
                    Err(_) => {
                        bail!(
                            "host_service {}: readiness timeout ({}s)",
                            h.name,
                            timeout_secs
                        );
                    }
                }
                // Forward the socket.
                if let Err(e) = shared.do_forward(&h.socket, &h.expose, &h.name) {
                    bail!("host_service {}: forward: {e}", h.name);
                }
                host_pids.push((host_pid, stop_spec));
            }
            Err(e) => {
                bail!("host_service {}: {e}", h.name);
            }
        }
    }
    Ok(())
}

/// Phase `services` (in-sandbox part): start each `[[services]]` entry
/// through the exec helper chain. Readiness is checked with a timeout;
/// on timeout the session fails closed (the guard kills init).
fn start_in_sandbox_services(
    services_: &[profile::Service],
    shared: &Arc<Shared>,
    exec_rules_for_services: &ExecRules,
) -> Result<Vec<ServiceHandle>> {
    let mut service_handles: Vec<ServiceHandle> = Vec::new();
    for s in services_ {
        match services::start_in_sandbox_service(shared, s, exec_rules_for_services) {
            Ok(handle) => {
                // Wait for readiness.
                let timeout_secs = s.ready.as_ref().and_then(|r| r.timeout).unwrap_or(15);
                if let Err(e) = services::wait_service_readiness(shared, s, timeout_secs) {
                    bail!("service {}: readiness: {e}", s.name);
                }
                service_handles.push(handle);
            }
            Err(e) => {
                bail!("service {}: {e}", s.name);
            }
        }
    }
    Ok(service_handles)
}

/// Ready reporting after START: the `--ready-fd` line, then the detach
/// ready line + stdio redirect. On a start failure none of this runs
/// (the early `bail!` paths return first), so nothing is written and the
/// exit status carries it.
fn report_ready(
    args: &RunArgs,
    ready_fd: Option<OwnedFd>,
    sdir: &SessionDir,
    session_id: &str,
    _ssh_agent_expose: &str,
) {
    if let Some(fd) = args.ready_fd {
        // SAFETY: the fd is the caller's; we write to it and do not close it
        // (the caller owns the lifecycle). Using a borrowed fd, not owned.
        use std::os::fd::{FromRawFd, IntoRawFd};
        let f = unsafe { std::fs::File::from_raw_fd(fd) };
        let _ = std::io::Write::write_all(&mut &f, b"ready\n");
        let _ = f.into_raw_fd(); // do not close; caller owns it
    }

    // 0.4.1 step 4: a `--detach` child reports readiness through the pipe and
    // redirects its stdio to <session-dir>/supervisor.log (0600). The log is
    // opened from the supervisor (owner uid) after the dir exists, so both the
    // ownership and the mode are hisn's. The ready pipe write end is closed
    // right after the ready line so the parent's read sees EOF.
    if let Some(fd) = ready_fd {
        use std::io::Write;
        let raw = fd.as_raw_fd();
        // SAFETY: borrowed write on the ready pipe we own; into_raw_fd below
        // returns ownership to the OwnedFd, which closes it on drop.
        let mut f = unsafe { std::fs::File::from_raw_fd(raw) };
        let _ = writeln!(f, "ready {session_id}");
        let _ = f.into_raw_fd(); // do not close via File; OwnedFd closes it
        // Redirect stdout/stderr to the session log. stdin stays as inherited
        // (the child is detached; nothing reads it).
        if let Err(e) = redirect_stdio_to_log(&sdir.path) {
            tracing::warn!("detach: cannot redirect stdio to supervisor.log: {e}");
        }
        // Close the ready pipe write end so the parent's read sees EOF.
        drop(fd);
    }
}

/// Phase `wait` (idle timer part): spawn the idle-expiry timer thread when
/// `idle_timeout` is set. Returns the handle, or `None`.
fn start_idle_timer(
    policy: &ResolvedPolicy,
    shared: &Arc<Shared>,
    pid: i32,
) -> Option<thread::JoinHandle<Option<u64>>> {
    let timeout_s = policy.idle_timeout_s?;
    let sh = Arc::clone(shared);
    // Opened here, on the supervisor thread, while init cannot have been
    // reaped yet (only relay_and_wait below reaps it).
    let target = InitTarget::new(pid);
    Some(thread::spawn(move || {
        let write_state = |state: crate::sessionmeta::State| {
            let _lock = sh.session_json_lock.lock().expect("session_json lock");
            crate::sessionmeta::set_state(&sh.session_dir, state)
        };
        crate::lifecycle::run_idle_timer(
            &*sh,
            &target,
            &crate::lifecycle::SystemClock,
            timeout_s,
            crate::lifecycle::StopPlan::SUPERVISOR,
            &write_state,
        )
    }))
}

/// Phase `teardown`: stop host services (signal + grace then KILL) and
/// in-sandbox services (best-effort signal + grace), in that order.
fn teardown_services(host_pids: &[(i32, profile::StopSpec)], service_handles: &[ServiceHandle]) {
    // Stop host services (DESIGN §17): signal + grace then KILL.
    // Check if the process is already gone before sleeping the full grace (P27).
    for (hpid, stop_spec) in host_pids {
        let sig = control::parse_signal(&stop_spec.signal).unwrap_or(libc::SIGTERM);
        let target = services::HostServiceTarget { pid: *hpid };
        services::stop_and_reap(&target, sig, stop_spec.grace);
    }
    // Stop in-sandbox services (DESIGN §19): best-effort signal + grace.
    // If init has already exited, the kernel has killed everything in the pid
    // ns; the stop is moot but harmless. Check if the service is still alive
    // before sleeping the full grace period (P27).
    for handle in service_handles {
        let sig = control::parse_signal(&handle.stop.signal).unwrap_or(libc::SIGTERM);
        services::stop_and_reap(handle, sig, handle.stop.grace);
    }
}

fn write_s_maps_and_unshare(uid: u32, gid: u32) -> Result<()> {
    sys::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS)
        .context("unshare(NEWUSER|NEWNS) — unprivileged user namespaces are unavailable")?;
    fs::write("/proc/self/setgroups", "deny").context("S setgroups")?;
    fs::write("/proc/self/uid_map", format!("{uid} {uid} 1")).context("S uid_map")?;
    fs::write("/proc/self/gid_map", format!("{gid} {gid} 1")).context("S gid_map")?;
    // Our private copy of the mount tree must not propagate back to the host.
    sys::mount(
        None,
        Path::new("/"),
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        None,
    )
    .context("making / private in S")?;
    Ok(())
}

fn open_ns(pid: i32, name: &str) -> Result<OwnedFd> {
    let f = fs::File::open(format!("/proc/{pid}/ns/{name}"))
        .with_context(|| format!("opening ns/{name}"))?;
    Ok(f.into())
}

fn bind_socket(path: &Path) -> Result<UnixListener> {
    // Bind under a restrictive umask so the socket is never briefly wider than 0600.
    // SAFETY: umask is process-global but we are single-threaded here.
    let old = unsafe { libc::umask(0o177) };
    let l = UnixListener::bind(path);
    // SAFETY: restoring the previous umask.
    unsafe { libc::umask(old) };
    let l = l.with_context(|| format!("binding {}", path.display()))?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

fn spawn_helper(mntns: &OwnedFd) -> Result<HelperClient> {
    let (parent_end, child_end) = sys::socketpair()?;
    // SAFETY: single-threaded at this point; the child runs only `helper_serve`.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error()).context("fork helper");
    }
    if pid == 0 {
        drop(parent_end);
        let ns = mntns.try_clone().expect("dup mntns fd");
        grant::helper_serve(child_end, ns);
    }
    drop(child_end);
    Ok(HelperClient::new(parent_end, pid))
}

/// Fork the exec helper `E` (still single-threaded, like the grant helper).
fn spawn_exec_helper(ctx: ExecContext) -> Result<ExecClient> {
    let (parent_end, child_end) = sys::socketpair_seqpacket()?;
    // SAFETY: single-threaded at this point; the child runs only `helper_serve`.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error()).context("fork exec helper");
    }
    if pid == 0 {
        drop(parent_end);
        exec::helper_serve(child_end, ctx);
    }
    drop(child_end);
    // The parent's copies of the namespace fds must not outlive this call.
    drop(ctx);
    Ok(ExecClient::new(parent_end))
}

// -------------------------------------------------------------- stdio relay

/// Pass stdio through. With a pty: raw mode, bidirectional relay, resize
/// forwarding. Returns the command's exit code.
fn relay_and_wait(init_pid: i32, master: Option<OwnedFd>, tty: bool) -> i32 {
    let handled = [
        libc::SIGTERM,
        libc::SIGINT,
        libc::SIGHUP,
        libc::SIGWINCH,
        libc::SIGCHLD,
    ];
    let _ = sig::install(&handled);
    let Ok(old) = sig::block(&handled) else {
        return services::reap(init_pid);
    };

    let raw_guard = if tty { RawTerm::enter(0) } else { None };
    let mut buf = vec![0u8; 16384];
    let mut stdin_open = true;
    let mut status: Option<i32> = None;
    if let Some(m) = &master {
        resize_to(0, m.as_raw_fd());
    }

    loop {
        for s in sig::take_pending() {
            match s {
                libc::SIGWINCH => {
                    if let Some(m) = &master {
                        resize_to(0, m.as_raw_fd());
                    }
                }
                libc::SIGTERM | libc::SIGINT | libc::SIGHUP => {
                    let _ = sys::kill(init_pid, s);
                }
                _ => {}
            }
        }
        let mut st = 0;
        // SAFETY: non-blocking waitpid on our own child.
        let r = unsafe { libc::waitpid(init_pid, &mut st, libc::WNOHANG) };
        if r == init_pid {
            status = Some(init::decode_status(st));
        }
        match (&master, status) {
            (None, Some(_)) => break,
            (None, None) => sig::wait(&old),
            (Some(m), _) => {
                let mut fds = [
                    libc::pollfd {
                        fd: m.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: if stdin_open { 0 } else { -1 },
                        events: libc::POLLIN,
                        revents: 0,
                    },
                ];
                match sys::ppoll(&mut fds, &old) {
                    Ok(_) => {}
                    Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                    Err(_) => break,
                }
                if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                    // SAFETY: reading into our buffer from an fd we own.
                    let n =
                        unsafe { libc::read(m.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                    if n > 0 {
                        let _ = io::stdout().write_all(&buf[..n as usize]);
                        let _ = io::stdout().flush();
                    } else if status.is_some() {
                        break; // child gone and master drained
                    } else if n <= 0 && fds[0].revents & libc::POLLHUP != 0 {
                        thread::sleep(std::time::Duration::from_millis(5));
                    }
                }
                if stdin_open && fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                    // SAFETY: reading stdin into our buffer.
                    let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
                    if n > 0 {
                        // SAFETY: writing our buffer to the pty master.
                        unsafe { libc::write(m.as_raw_fd(), buf.as_ptr().cast(), n as usize) };
                    } else {
                        stdin_open = false;
                    }
                }
                if status.is_some() && fds[0].revents == 0 {
                    break;
                }
            }
        }
    }
    drop(raw_guard);
    status.unwrap_or_else(|| services::reap(init_pid))
}

pub(crate) fn resize_to(from_fd: RawFd, to_fd: RawFd) {
    // SAFETY: winsize ioctl round-trip with a zeroed buffer.
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(from_fd, libc::TIOCGWINSZ, &mut ws) == 0 {
            libc::ioctl(to_fd, libc::TIOCSWINSZ, &ws);
        }
    }
}

/// Puts a tty into raw mode; restores on drop (every exit path).
pub(crate) struct RawTerm {
    fd: RawFd,
    saved: libc::termios,
}

impl RawTerm {
    pub(crate) fn enter(fd: RawFd) -> Option<Self> {
        // SAFETY: termios get/set on a tty fd with zeroed storage.
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut t) != 0 {
                return None;
            }
            let saved = t;
            libc::cfmakeraw(&mut t);
            if libc::tcsetattr(fd, libc::TCSANOW, &t) != 0 {
                return None;
            }
            Some(Self { fd, saved })
        }
    }
}

impl Drop for RawTerm {
    fn drop(&mut self) {
        // SAFETY: restoring the attributes captured in `enter`.
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved) };
    }
}

// ----------------------------------------------------------- client commands

/// Locate the control socket of a session or fail with a clear message.
/// Resolve a `--session` argument (id or name) to its control socket.
pub fn socket_for(session_arg: &str) -> Result<PathBuf> {
    let uid = rustix::process::getuid().as_raw();
    let roots = session::runtime_roots(std::env::var("XDG_RUNTIME_DIR").ok().as_deref(), uid);
    let reg_root = crate::registry::registry_root(uid);
    let id = session::resolve_session_arg(&roots, &reg_root, session_arg)?;
    let dir = session::find_session(&roots, &id)?;
    use std::os::unix::fs::MetadataExt;
    if fs::metadata(&dir)?.uid() != uid {
        bail!("session {session_arg} belongs to another user");
    }
    Ok(dir.join("control.sock"))
}

pub fn client_request(session_arg: &str, req: &Value) -> Result<Value> {
    let sock = socket_for(session_arg)?;
    control::request(&sock, req).with_context(|| format!("talking to session {session_arg}"))
}

#[cfg(test)]
mod tests {
    use super::{ClientInfo, ConnRegistry};

    fn info() -> ClientInfo {
        ClientInfo {
            uid: 1000,
            pid: None,
            label: "connected".into(),
            label_source: "none".into(),
            connected_since: "2026-11-08T00:00:00Z".into(),
        }
    }

    #[test]
    fn every_start_failure_exits_125_with_or_without_detach() {
        // 0.4.1 R1: a failed start exits 125 (EXIT_START_FAILED), never 1.
        // Table over the start-failure kinds the leak suite checks: profile
        // refusal (L26), missing risk_ack (L29), home/persist refusal (L42 R5),
        // service readiness timeout (L41), and a supervisor that dies before
        // reporting. Each arrives as a ready-pipe line; the parent maps every
        // non-ready outcome through start_failure_exit().
        use super::{EXIT_START_FAILED, ReadyReport, parse_ready_report, start_failure_exit};
        let kinds = [
            (
                "untrusted profile",
                "error E_PROFILE_UNTRUSTED: profile under cwd",
            ),
            (
                "missing risk_ack",
                "error E_RISK_ACK_REQUIRED: docker-socket",
            ),
            ("home.persist refusal", "error E_HOME_PERSIST: refused"),
            (
                "service readiness timeout",
                "error service never-ready: readiness timeout (15s)",
            ),
            ("supervisor died before reporting", ""),
            ("unparseable report", "gibberish"),
        ];
        for (kind, line) in kinds {
            let report = parse_ready_report(line);
            assert!(
                matches!(report, ReadyReport::Error(_)),
                "{kind}: a failed start must not parse as ready"
            );
            assert_eq!(
                start_failure_exit(),
                125,
                "{kind}: a failed start must exit 125, not {}",
                start_failure_exit()
            );
        }
        // The child's own failure branch and the parent share the constant.
        assert_eq!(EXIT_START_FAILED, 125, "EXIT_START_FAILED must stay 125");
        // A session that reports ready is not a start failure.
        assert!(matches!(
            parse_ready_report("ready abc123"),
            ReadyReport::Ready(_)
        ));
    }

    #[test]
    fn connect_then_close_returns_to_zero_with_and_without_a_request() {
        // 0.4.1 R2: N connections that close (with or without a request) must
        // leave the registry empty; the count never goes negative or sticks.
        let mut r = ConnRegistry::default();
        for id in 1..=200u64 {
            assert!(r.connect(id, info()));
            if id % 2 == 0 {
                r.update(id, "local", "none", 1000, Some(4242));
            }
            assert_eq!(r.connected(), 1);
            assert!(r.disconnect(id));
            assert_eq!(r.connected(), 0, "count stuck after connection {id}");
        }
        assert!(r.clients.is_empty());
    }

    #[test]
    fn idle_fires_with_a_fake_clock_once_every_connection_is_gone() {
        // 0.4.1 R2 (L61): connections that came and went must not keep the
        // session alive. Drive the registry through connect/close (with and
        // without a request), then ask the production idle predicate with a
        // fake clock: it must hold while a client is connected and fire only
        // after the timeout once the count is back to zero.
        use crate::lifecycle::idle_due;
        const TIMEOUT: u64 = 30;
        let mut r = ConnRegistry::default();
        let mut last_activity: i64 = 1_000;
        for id in 1..=50u64 {
            assert!(r.connect(id, info()));
            if id % 2 == 0 {
                r.update(id, "local", "none", 1000, Some(1));
            }
            // A connected client is never idle, however long it has been.
            assert!(!idle_due(
                r.connected() > 0,
                false,
                last_activity,
                1_000_000,
                TIMEOUT
            ));
            assert!(r.disconnect(id));
            // The disconnect is the last activity (the supervisor bumps it).
            last_activity = 1_000 + id as i64;
        }
        assert_eq!(r.connected(), 0);
        let closed_at = last_activity;
        // Zero clients, no execs: not yet idle inside the window...
        assert!(!idle_due(false, false, closed_at, closed_at + 10, TIMEOUT));
        // ...and idle once the timeout has elapsed from the last disconnect.
        assert!(idle_due(
            false,
            false,
            closed_at,
            closed_at + TIMEOUT as i64 + 1,
            TIMEOUT
        ));
    }

    #[test]
    fn a_second_disconnect_for_the_same_connection_is_a_noop() {
        // Exactly one disconnect per connect: a duplicate must not drive the
        // count negative or remove a later connection's record.
        let mut r = ConnRegistry::default();
        assert!(r.connect(7, info()));
        assert!(r.disconnect(7));
        assert!(!r.disconnect(7));
        assert_eq!(r.connected(), 0);
    }

    #[test]
    fn a_duplicate_connect_does_not_double_count() {
        let mut r = ConnRegistry::default();
        assert!(r.connect(3, info()));
        assert!(!r.connect(3, info()));
        assert_eq!(r.connected(), 1);
        assert!(r.disconnect(3));
        assert_eq!(r.connected(), 0);
    }

    #[test]
    fn a_reused_fd_number_cannot_mis_pair_connections() {
        // The original bug: the kernel reuses a closed fd number, so a record
        // keyed by fd was replaced by the next connection and the wrong close
        // removed it. With ConnId, each connection owns its own record.
        let mut r = ConnRegistry::default();
        assert!(r.connect(10, info())); // fd 3, connection 10
        assert!(r.connect(11, info())); // fd 3 reused, connection 11
        assert_eq!(r.connected(), 2, "a reused fd replaced a live record");
        assert!(r.disconnect(10));
        assert_eq!(r.connected(), 1, "closing 10 removed 11's record");
        assert!(r.disconnect(11));
        assert_eq!(r.connected(), 0);
    }

    #[test]
    fn ready_report_is_parsed_from_the_first_line() {
        use super::{ReadyReport, parse_ready_report};
        assert_eq!(
            parse_ready_report("ready abc123"),
            ReadyReport::Ready("abc123".into())
        );
        assert_eq!(
            parse_ready_report("ready seat-a"),
            ReadyReport::Ready("seat-a".into())
        );
        assert_eq!(
            parse_ready_report("error cannot start: EPERM"),
            ReadyReport::Error("cannot start: EPERM".into())
        );
        assert_eq!(parse_ready_report(""), ReadyReport::Error(String::new()));
        // An unexpected line is treated as an error, never as readiness.
        assert_eq!(
            parse_ready_report("gibberish"),
            ReadyReport::Error("gibberish".into())
        );
        assert_eq!(
            parse_ready_report("ready"),
            ReadyReport::Error("ready".into())
        );
    }

    #[test]
    fn username_comes_from_the_lookup_and_falls_back_with_a_reason() {
        let (n, why) = pick_username(Ok(Some("alice".into())));
        assert_eq!((n.as_str(), why), ("alice", None));
        for bad in [
            "",
            "a:b",
            "a\nroot:x:0:0::/:/bin/sh",
            "a b",
            "a/b",
            "-x",
            &"x".repeat(MAX_USERNAME + 1),
        ] {
            let (n, why) = pick_username(Ok(Some(bad.into())));
            assert_eq!(n, "user", "{bad:?}");
            assert!(why.is_some(), "{bad:?}");
        }
        let (n, why) = pick_username(Ok(None));
        assert_eq!(n, "user");
        assert!(why.unwrap().contains("no passwd entry"));
        let (n, why) = pick_username(Err(io::Error::from_raw_os_error(libc::EIO)));
        assert_eq!(n, "user");
        assert!(why.unwrap().contains("getpwuid_r failed"));
        assert!(valid_username(&"x".repeat(MAX_USERNAME)) && valid_username("a.b_c-d9"));
    }

    #[test]
    fn passwd_name_of_the_current_uid_matches_id_un() {
        // `id -un` is the reference; skip quietly where it is unavailable or
        // the uid has no passwd entry (some CI containers).
        let Ok(out) = std::process::Command::new("id").arg("-un").output() else {
            return;
        };
        if !out.status.success() {
            return;
        }
        let want = String::from_utf8(out.stdout).unwrap().trim().to_owned();
        let euid = rustix::process::geteuid().as_raw();
        assert_eq!(
            sys::passwd_name(euid).unwrap().as_deref(),
            Some(want.as_str())
        );
        // An absent uid is Ok(None) (some NSS backends report an error
        // instead); either way it is never a name.
        assert!(!matches!(sys::passwd_name(4_000_000_123), Ok(Some(_))));
    }

    use super::*;
    use crate::policy::Home;

    const SANDBOX_NS: u64 = 4_026_531_836;

    fn authz(
        uid: u32,
        ns: io::Result<u64>,
        tree: io::Result<bool>,
        alive: bool,
    ) -> Result<(), Refuse> {
        authorize_peer(uid, 1000, ns, SANDBOX_NS, tree, alive)
    }

    fn eperm() -> io::Error {
        io::Error::from_raw_os_error(libc::EACCES)
    }

    #[test]
    fn r5_allows_a_same_uid_peer_in_another_pidns() {
        assert_eq!(authz(1000, Ok(SANDBOX_NS + 1), Ok(false), true), Ok(()));
    }

    #[test]
    fn r5_allows_a_host_peer_whose_ns_link_is_unreadable() {
        // The supervisor lives in a child userns: /proc/<host pid>/ns/pid is
        // EACCES for it. Ancestry decides, and says "not in the sandbox".
        assert_eq!(authz(1000, Err(eperm()), Ok(false), true), Ok(()));
    }

    #[test]
    fn r5_refuses_peers_inside_the_sandbox_pidns() {
        // Either signal alone is enough to refuse.
        assert_eq!(
            authz(1000, Ok(SANDBOX_NS), Ok(false), true),
            Err(Refuse::InSandboxPidns)
        );
        assert_eq!(
            authz(1000, Err(eperm()), Ok(true), true),
            Err(Refuse::InSandboxPidns)
        );
        assert_eq!(
            authz(1000, Ok(SANDBOX_NS + 1), Ok(true), true),
            Err(Refuse::InSandboxPidns)
        );
    }

    #[test]
    fn r5_fails_closed_on_missing_facts() {
        // Ancestry undecidable -> refuse, whatever the ns link says.
        assert!(matches!(
            authz(1000, Ok(1), Err(eperm()), true),
            Err(Refuse::Unknown(_))
        ));
        assert!(matches!(
            authz(1000, Err(eperm()), Err(eperm()), true),
            Err(Refuse::Unknown(_))
        ));
        assert!(matches!(
            authz(1000, Ok(1), Ok(false), false),
            Err(Refuse::Unknown(_))
        ));
    }

    #[test]
    fn r5_refuses_other_uids_first() {
        assert_eq!(
            authz(0, Ok(1), Ok(false), true),
            Err(Refuse::WrongUid {
                peer: 0,
                ours: 1000
            })
        );
    }

    #[test]
    fn env_set_redaction_hides_secret_shaped_values() {
        use super::redact_env_set;
        // Real serialized shape from `ResolvedPolicy::to_toml`.
        let toml = "version = \"hisn-policy/v1\"\n\
                    [env]\n\
                    pass = [\"GOFLAGS\"]\n\
                    \n\
                    [env.set]\n\
                    GOFLAGS = \"-mod=mod\"\n\
                    GITHUB_TOKEN = \"ghp_secret\"\n\
                    MY_PASSWORD = \"hunter2\"\n";
        let out = redact_env_set(toml);
        // Every secret-shaped value is gone; the safe one survives.
        assert!(!out.contains("ghp_secret"), "{out}");
        assert!(!out.contains("hunter2"), "{out}");
        assert!(out.contains("-mod=mod"), "{out}");
        // The result is valid TOML.
        let v: toml::Value = toml::from_str(&out).expect("redacted TOML parses");
        assert_eq!(v["env"]["set"]["GITHUB_TOKEN"].as_str(), Some("<redacted>"));
        assert_eq!(v["env"]["set"]["MY_PASSWORD"].as_str(), Some("<redacted>"));
        assert_eq!(v["env"]["set"]["GOFLAGS"].as_str(), Some("-mod=mod"));

        // A secret value containing a newline must not leak through a
        // multiline TOML string.
        let ml = "[env.set]\nSECRET_PEM = \"\"\"line1\nline2\n\"\"\"\n";
        let out_ml = redact_env_set(ml);
        assert!(
            !out_ml.contains("line1"),
            "multiline secret leaked: {out_ml}"
        );
        assert!(
            !out_ml.contains("line2"),
            "multiline secret leaked: {out_ml}"
        );
        let v2: toml::Value = toml::from_str(&out_ml).expect("redacted multiline TOML parses");
        assert_eq!(v2["env"]["set"]["SECRET_PEM"].as_str(), Some("<redacted>"));

        // A policy with no secret-shaped keys: values are preserved.
        let clean = "[env.set]\nGOFLAGS = \"-mod=mod\"\n";
        let vc: toml::Value = toml::from_str(&redact_env_set(clean)).unwrap();
        assert_eq!(vc["env"]["set"]["GOFLAGS"].as_str(), Some("-mod=mod"));
    }

    #[test]
    fn open_fd_count_tracks_descriptors() {
        // Forked child: the harness runs tests as threads of one process, so
        // other tests open and close descriptors while this one counts.
        // SAFETY: the child only opens/closes files, counts and `_exit`s.
        unsafe {
            let pid = libc::fork();
            if pid == 0 {
                let before = open_fd_count().unwrap_or(usize::MAX);
                let f = fs::File::open("/dev/null").unwrap();
                let during = open_fd_count().unwrap_or(0);
                drop(f);
                let after = open_fd_count().unwrap_or(usize::MAX);
                libc::_exit(if during == before + 1 && after == before {
                    0
                } else {
                    1
                });
            }
            let mut st = 0;
            libc::waitpid(pid, &mut st, 0);
            assert_eq!(crate::init::decode_status(st), 0);
        }
    }

    #[test]
    fn holders_serialise_with_kinds() {
        let mut h = BTreeSet::new();
        h.insert(Holder {
            pid: 7,
            kind: HolderKind::Fd,
        });
        h.insert(Holder {
            pid: 7,
            kind: HolderKind::Unknown,
        });
        assert_eq!(
            holders_json(&h),
            json!([{"pid":7,"kind":"fd"},{"pid":7,"kind":"unknown"}])
        );
        assert_eq!(holders_json(&BTreeSet::new()), json!([]));
    }

    fn plan_for(policy: &ResolvedPolicy) -> Vec<mounts::MountOp> {
        let mut f = HostFacts {
            uid: 1000,
            gid: 1000,
            username: "u".into(),
            ..Default::default()
        };
        f.toolchain.insert("/usr".into(), mounts::EntryKind::Dir);
        f.etc.insert("hosts".into(), mounts::EntryKind::File);
        mounts::plan(policy, &f, &[]).unwrap()
    }

    fn policy() -> ResolvedPolicy {
        ResolvedPolicy {
            version: "hisn-policy/v1".into(),
            cwd: "/work/p".into(),
            home: Home::Tmpfs,
            network: Network::None,
            hostname: "hisn".into(),
            ro: vec!["/opt/tc".into()],
            ro_binds: vec![],
            rw: vec![],
            mask: vec![],
            grantable_rw: vec!["/data/shared".into()],
            env_pass: vec![],
            env_set: Default::default(),
            extra_deny: vec![],
            landlock_scoped: vec![],
            nofile: 1,
            nproc: 1,
            shm: false,
            shm_size: 64,
            tmp_size: 1024,
            rootfs: None,
            nameservers: None,
            idle_timeout_s: None,
        }
    }

    #[test]
    fn static_rules_come_from_the_plan() {
        let p = policy();
        let r = static_rules(&plan_for(&p), &p, &["/run/user/1000/hisn".into()]);
        assert!(r.static_mounts.contains(&PathBuf::from("/usr")));
        assert!(r.static_mounts.contains(&PathBuf::from("/work/p")));
        assert!(r.static_ro.contains(&PathBuf::from("/usr")));
        assert!(r.static_ro.contains(&PathBuf::from("/etc")));
        assert!(
            !r.static_ro.contains(&PathBuf::from("/work/p")),
            "cwd is rw"
        );
        assert_eq!(r.grantable_rw, vec![PathBuf::from("/data/shared")]);
        assert_eq!(r.runtime_roots, vec![PathBuf::from("/run/user/1000/hisn")]);
        // the plain-directory grantable prefix is not a *mount*
        assert!(!r.static_mounts.contains(&PathBuf::from("/data/shared")));
    }

    #[test]
    fn prepare_applies_flags_over_the_policy() {
        let d = tempfile::tempdir().unwrap();
        let cwd = fs::canonicalize(d.path()).unwrap();
        let args = RunArgs {
            policy: None,
            profile: None,
            cwd: Some(cwd.clone()),
            session_id: None,
            name: None,
            network: Some(crate::cli::NetworkArg::Host),
            allow_host_abstract_sockets: false,
            quiet_risk: false,
            home_persist: None,
            rootfs_path: None,
            grants: vec!["/x:rw".into(), "/y".into()],
            detach: false,
            ready_fd: None,
            command: vec!["true".into()],
            env: vec![],
            env_files: vec![],
        };
        let p = prepare(&args, 1000).unwrap();
        assert_eq!(p.policy.cwd, cwd);
        assert_eq!(p.policy.network, Network::Host);
        assert_eq!(
            p.grants,
            vec![("/x".to_owned(), Mode::Rw), ("/y".to_owned(), Mode::Ro)]
        );
        assert!(p.roots.iter().any(|r| r.ends_with("hisn-1000")));
    }

    /// Test fake for [`SessionGuard`]: the kill/reap actions are injected
    /// as a closure so the guard's ordering and disarm semantics are
    /// testable without real processes. Production uses the kill+reap
    /// `Drop` impl; the tests below pin its contract through this seam.
    struct FakeGuard {
        init_pid: i32,
        host_pids: Vec<i32>,
        armed: bool,
        log: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    }

    impl FakeGuard {
        fn new(init_pid: i32, log: std::rc::Rc<std::cell::RefCell<Vec<String>>>) -> Self {
            Self {
                init_pid,
                host_pids: Vec::new(),
                armed: true,
                log,
            }
        }

        fn disarm(&mut self) {
            self.armed = false;
        }

        fn cleanup(&self) {
            if !self.armed {
                return;
            }
            for pid in &self.host_pids {
                self.log.borrow_mut().push(format!("kill host {pid}"));
                self.log.borrow_mut().push(format!("reap host {pid}"));
            }
            self.log
                .borrow_mut()
                .push(format!("kill init {}", self.init_pid));
            self.log
                .borrow_mut()
                .push(format!("reap init {}", self.init_pid));
        }
    }

    impl Drop for FakeGuard {
        fn drop(&mut self) {
            self.cleanup();
        }
    }

    fn early_return(guard: FakeGuard) -> Result<()> {
        let _held = guard;
        bail!("simulated early return")
    }

    #[test]
    fn guard_cleanup_runs_once_on_early_return() {
        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut guard = FakeGuard::new(100, log.clone());
        guard.host_pids.push(101);
        // The guard is consumed by an early return: Drop must run cleanup.
        assert!(early_return(guard).is_err());
        assert_eq!(
            *log.borrow(),
            vec![
                "kill host 101",
                "reap host 101",
                "kill init 100",
                "reap init 100",
            ],
            "cleanup runs once on early return, host services before init"
        );
    }

    #[test]
    fn guard_cleanup_never_runs_after_disarm() {
        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut guard = FakeGuard::new(100, log.clone());
        guard.host_pids.push(101);
        guard.disarm();
        // Success path: the guard is dropped disarmed; no cleanup at all.
        drop(guard);
        assert!(
            log.borrow().is_empty(),
            "disarmed guard must not clean up: {:?}",
            log.borrow()
        );
    }

    #[test]
    fn guard_cleanup_order_is_host_services_before_init() {
        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut guard = FakeGuard::new(100, log.clone());
        guard.host_pids.push(201);
        guard.host_pids.push(202);
        drop(guard);
        let entries = log.borrow().clone();
        let host_pos = entries
            .iter()
            .position(|e| e == "kill host 201")
            .expect("host kill recorded");
        let init_pos = entries
            .iter()
            .position(|e| e == "kill init 100")
            .expect("init kill recorded");
        assert!(
            host_pos < init_pos,
            "host services killed before init: {entries:?}"
        );
        // Every kill is followed by its reap, in the same order.
        assert_eq!(
            entries,
            vec![
                "kill host 201",
                "reap host 201",
                "kill host 202",
                "reap host 202",
                "kill init 100",
                "reap init 100",
            ]
        );
    }

    #[test]
    fn production_guard_drop_never_panics_even_for_unknown_pids() {
        // The production guard's Drop must never panic (fork-safety rule 6):
        // killing and reaping pids that do not exist is a no-op error, not
        // a panic. This exercises the real Drop impl with a pid the kernel
        // will reject (a very large pid in this process's namespace).
        let mut guard = super::SessionGuard::new(i32::MAX);
        guard.host_pids.push(i32::MAX - 1);
        std::panic::catch_unwind(move || drop(guard))
            .expect("guard Drop must not panic for unknown pids");
    }
}
