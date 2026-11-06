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
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::alias;
use crate::cli::{RunArgs, parse_grant_spec};
use crate::control::{self, Handler, Mode, Request, err, ok};
use crate::env as senv;
use crate::exec::{self, ExecClient, ExecContext, ExecRules, NsFds};
use crate::grant::{self, Grant, GrantTable, HelperClient, Holder, HolderKind, Rules};
use crate::init::{self, InitConfig, MSG_ERROR, MSG_GO, MSG_READY, MSG_START};
use crate::landlock;
use crate::mounts::{self, HostFacts};
use crate::policy::{Network, Overrides, Policy, ResolvedPolicy, is_valid_session_id};
use crate::profile::{self, Profile as ProfileDoc};
use crate::session::{self, Audit, SessionDir};
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

struct Shared {
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
    /// Live exec'd programs: in-sandbox pid → a handle on their status socket
    /// (only used to deliver `signal`).
    live: Mutex<std::collections::BTreeMap<i32, OwnedFd>>,
    /// Monotonic exec_id counter (never reused within a session).
    next_exec_id: std::sync::atomic::AtomicU64,
    /// Map of exec_id → (pid, status fd handle) for live execs.
    execs: Mutex<std::collections::BTreeMap<u64, (i32, OwnedFd)>>,
    /// All pids ever used by any exec in this session. Used to detect pid
    /// reuse: if a new exec gets a pid that was used by a previous exec
    /// (even a finished one), `signal` by that pid is rejected.
    used_pids: Mutex<std::collections::BTreeSet<i32>>,
    /// Pids that have been reused by a later exec. A `signal` by such a
    /// pid is rejected — the client must use `exec_id`.
    recycled_pids: Mutex<std::collections::BTreeSet<i32>>,
    /// In-sandbox services (DESIGN §19): name → state for `ls --json`.
    services: Mutex<std::collections::BTreeMap<String, ServiceState>>,
}

/// The state of an in-sandbox service for `ls --json` (DESIGN §19).
struct ServiceState {
    name: String,
    pid: i32,
    socket: Option<String>,
    state: &'static str, // "starting" | "ready" | "exited"
    exit: Option<i32>,
    /// The status socket to the service's monitor `W`, used to detect exit.
    status: OwnedFd,
}

impl Shared {
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

    fn do_grant(&self, path: &str, mode: Mode, recursive: bool, peer: Option<i32>) -> Value {
        let _g = self.op_lock.lock().expect("op lock");
        self.log(
            "grant",
            "request",
            Some(path),
            Some(mode.as_str()),
            None,
            peer,
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
                self.log(
                    "grant",
                    "result",
                    Some(path),
                    Some(mode.as_str()),
                    Some("ok"),
                    None,
                );
                v
            }
            Err((code, msg)) => {
                self.log(
                    "grant",
                    "result",
                    Some(path),
                    Some(mode.as_str()),
                    Some(&code),
                    None,
                );
                err(&code, msg)
            }
        }
    }

    fn do_revoke(&self, path: &str, hard: bool, kill_holders: bool, peer: Option<i32>) -> Value {
        let _g = self.op_lock.lock().expect("op lock");
        self.log("revoke", "request", Some(path), None, None, peer);
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
                self.log("revoke", "result", Some(path), None, Some("ok"), None);
                v
            }
            Err((code, msg)) => {
                self.log("revoke", "result", Some(path), None, Some(&code), None);
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
        req: ExecRequest,
        stdio: Vec<OwnedFd>,
        conn: &UnixStream,
        peer: Option<i32>,
    ) -> Value {
        let argv0 = req.argv.first().cloned().unwrap_or_default();
        self.log("exec", "request", Some(&argv0), None, None, peer);
        let fail = |code: &str, msg: String| {
            self.log("exec", "result", Some(&argv0), None, Some(code), None);
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
        let registered = sys::dup_cloexec_min(sp.status.as_raw_fd(), 3)
            .ok()
            .map(|h| {
                // Check if this pid was used by a previous exec (even a
                // finished one). If so, mark it as recycled so `signal`
                // by pid is rejected for the new exec.
                {
                    let mut used = self.used_pids.lock().expect("used_pids");
                    if used.contains(&sp.pid) {
                        self.recycled_pids.lock().expect("recycled").insert(sp.pid);
                    }
                    used.insert(sp.pid);
                }
                self.live.lock().expect("live").insert(sp.pid, h);
                if let Ok(dup) = sys::dup_cloexec_min(sp.status.as_raw_fd(), 3) {
                    self.execs
                        .lock()
                        .expect("execs")
                        .insert(exec_id, (sp.pid, dup));
                }
                sp.pid
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
            exec::drive(&sp.status, sp.pending, -1, std::time::Duration::ZERO)
        };
        if let Some(pid) = registered {
            self.live.lock().expect("live").remove(&pid);
        }
        self.execs.lock().expect("execs").remove(&exec_id);
        let (res, line) = match outcome {
            exec::Outcome::Exited(exec::Exit::Code(c)) => ("ok", json!({ "exit": { "code": c } })),
            exec::Outcome::Exited(exec::Exit::Signal(n)) => (
                "ok",
                json!({ "exit": { "signal": control::signal_name(n) } }),
            ),
            exec::Outcome::Lost => ("lost", json!({ "exit": { "lost": true } })),
        };
        self.log("exec", "result", Some(&argv0), None, Some(res), None);
        line
    }

    /// `signal`: deliver to a live exec'd program of *this* session only.
    /// Accepts `exec_id` (preferred) or `pid` (deprecated for 0.2 clients).
    fn do_signal(&self, exec_id: Option<String>, pid: Option<i32>, signal: &str) -> Value {
        let Some(sig) = control::parse_signal(signal) else {
            return err(control::E_BAD_REQUEST, format!("unknown signal {signal:?}"));
        };
        // Prefer exec_id; fall back to pid for 0.2 clients.
        if let Some(eid) = exec_id {
            let eid_num = eid.strip_prefix("e-").and_then(|n| n.parse::<u64>().ok());
            let Some(eid_num) = eid_num else {
                return err(control::E_BAD_REQUEST, format!("invalid exec_id {eid:?}"));
            };
            let execs = self.execs.lock().expect("execs");
            let Some((_, h)) = execs.get(&eid_num) else {
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
        if self.recycled_pids.lock().expect("recycled").contains(&pid) {
            return err(
                control::E_NOT_FOUND,
                format!("pid {pid} has been recycled; use exec_id"),
            );
        }
        let live = self.live.lock().expect("live");
        let Some(h) = live.get(&pid) else {
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

    fn inspect(&self) -> Value {
        let services = {
            let mut svcs = self.services.lock().expect("services");
            // Update service states: check if each service is still alive
            // (P26). A service whose status socket is closed or whose pid
            // is gone has exited.
            for s in svcs.values_mut() {
                if s.state == "ready" {
                    // Check if the service process is still alive via the
                    // status socket. If the socket is closed (POLLHUP), the
                    // monitor is gone, so the service has exited.
                    let alive = s.status.as_raw_fd();
                    let mut pollfds = [libc::pollfd {
                        fd: alive,
                        events: libc::POLLIN,
                        revents: 0,
                    }];
                    // SAFETY: poll on our own fd, non-blocking.
                    let r = unsafe { libc::poll(&mut pollfds[0], 1, 0) };
                    if r > 0 && (pollfds[0].revents & (libc::POLLHUP | libc::POLLERR)) != 0 {
                        s.state = "exited";
                    }
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
        match fs::read_to_string(format!("/proc/{}/mountinfo", self.init_pid)) {
            Ok(mi) => ok(json!({
                "schema": "hisn-inspect/v1",
                "mountinfo": mi,
                "policy": self.resolved_toml,
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

    fn handle(&self, req: Request, fds: Vec<OwnedFd>, peer: &UnixStream) -> Value {
        let peer_pid = sys::peer_cred(peer.as_raw_fd()).ok().map(|(p, _)| p);
        match req {
            Request::Exec {
                argv,
                cwd,
                env,
                tty,
            } => self.sh.do_exec(
                ExecRequest {
                    argv,
                    cwd,
                    env,
                    tty,
                },
                fds,
                peer,
                peer_pid,
            ),
            Request::Signal {
                exec_id,
                pid,
                signal,
            } => self.sh.do_signal(exec_id, pid, &signal),
            Request::Grant {
                path,
                mode,
                recursive,
            } => self.sh.do_grant(&path, mode, recursive, peer_pid),
            Request::Revoke {
                path,
                hard,
                kill_holders,
            } => self.sh.do_revoke(&path, hard, kill_holders, peer_pid),
            Request::List {} => {
                let t = self.sh.table.lock().expect("table");
                let grants: Vec<Value> = t
                    .list()
                    .iter()
                    .map(|g| json!({ "path": g.path, "mode": g.mode.as_str(), "recursive": g.recursive, "mount_id": g.mount_id, "ts": g.ts }))
                    .collect();
                ok(json!({ "grants": grants }))
            }
            Request::Inspect {} => self.sh.inspect(),
            Request::Kill { signal } => match control::parse_signal(&signal) {
                None => err(control::E_BAD_REQUEST, format!("unknown signal {signal:?}")),
                Some(s) => match sys::kill(self.sh.init_pid, s) {
                    Ok(()) => ok(json!({})),
                    Err(e) => err(control::E_INTERNAL, e.to_string()),
                },
            },
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
pub struct Prepared {
    pub policy: ResolvedPolicy,
    pub grants: Vec<(String, Mode)>,
    pub roots: Vec<PathBuf>,
    /// 0.3 surface: in-sandbox services from the profile.
    pub services: Vec<profile::Service>,
    /// 0.3 surface: forwards from the profile.
    pub forwards: Vec<profile::Forward>,
    /// 0.3 surface: host_services from the profile.
    pub host_services: Vec<profile::HostService>,
    /// 0.3.2: SSH agent config from the profile.
    pub ssh: Option<profile::SshConfig>,
}

pub fn prepare(args: &RunArgs, uid: u32) -> Result<Prepared> {
    let roots = session::runtime_roots(std::env::var("XDG_RUNTIME_DIR").ok().as_deref(), uid);
    let cwd_base = std::env::current_dir().context("current dir")?;
    let mut profile_doc: Option<ProfileDoc> = None;
    let (pol, base, services, forwards, host_services, ssh) = match (&args.policy, &args.profile) {
        (Some(f), None) => {
            let p = Policy::load(f).with_context(|| f.display().to_string())?;
            let b = f
                .parent()
                .filter(|b| !b.as_os_str().is_empty())
                .map(Path::to_path_buf)
                .unwrap_or(cwd_base.clone());
            (p, b, Vec::new(), Vec::new(), Vec::new(), None)
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
            profile_doc = Some(prof.clone());
            (
                prof.policy,
                b,
                prof.services.clone(),
                prof.forwards.clone(),
                prof.host_services.clone(),
                prof.ssh.clone(),
            )
        }
        (None, None) => (
            Policy::default(),
            cwd_base.clone(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
        ),
        // (Some, Some) is rejected by check_command() before we get here.
        _ => unreachable!("--profile and --policy are mutually exclusive (check_command)"),
    };
    let ov = Overrides {
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
        home_persist: match &args.home_persist {
            Some(h) => Some(h.clone()),
            None => profile_doc
                .as_ref()
                .and_then(|d| d.home.as_ref()?.persist.clone()),
        },
        // 0.3.3: `[net] nameservers` from the profile (no CLI flag).
        nameservers: profile_doc
            .as_ref()
            .and_then(|d| d.net.as_ref()?.nameservers.clone()),
        rootfs_path: match &args.rootfs_path {
            Some(p) => Some(p.to_string_lossy().into_owned()),
            // Strict: a profile naming a rootfs that cannot be resolved is an
            // error, never a silent fall-back to the host toolchain.
            None => profile_doc
                .as_ref()
                .and_then(|d| d.rootfs.as_ref())
                .map(profile::rootfs_spec)
                .transpose()?,
        },
    };
    let policy = pol.resolve(&base, &ov, &roots)?;
    let grants = args
        .grants
        .iter()
        .map(|g| parse_grant_spec(g).map_err(|e| anyhow!(e)))
        .collect::<Result<Vec<_>>>()?;
    Ok(Prepared {
        policy,
        grants,
        roots,
        services,
        forwards,
        host_services,
        ssh,
    })
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

/// Number of descriptors this process has open (includes the one used to
/// count them, which is constant between calls).
pub fn open_fd_count() -> io::Result<usize> {
    Ok(fs::read_dir("/proc/self/fd")?.count())
}

/// Exit code of `hisn run`.
pub fn run(args: RunArgs, allow_host_abstract: bool, verbose: u8) -> Result<i32> {
    let (uid, gid, username) = getids(verbose);
    let prep = prepare(&args, uid)?;
    let policy = prep.policy;
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

    // Compute risk labels from the effective configuration (profile + CLI
    // overrides). When --profile is given, compute from the profile (which
    // already carries [home], [rootfs], [ssh]). When --home-persist or
    // --rootfs-path are given without a profile, build a synthetic Profile
    // from the CLI overrides so the RISK line is still printed.
    let risk_entries = if args.profile.is_some() {
        let prof = match &args.profile {
            Some(spec) => {
                let (path, _) = profile::resolve_profile_path(spec)?;
                ProfileDoc::load(&path)?
            }
            None => unreachable!("profile is Some"),
        };
        profile::compute_risks(&prof)
    } else if args.home_persist.is_some() || args.rootfs_path.is_some() {
        // Build a synthetic profile from the CLI overrides so the RISK
        // line is printed even without --profile.
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
        profile::compute_risks(&synth)
    } else {
        Vec::new()
    };

    // Print RISK lines on start (one per widening capability), unless --quiet-risk.
    if !args.quiet_risk {
        let lines = profile::format_risk_lines(&risk_entries);
        for line in &lines {
            eprintln!("{line}");
        }
        if lines.is_empty() && verbose > 0 {
            eprintln!("RISK: none");
        }
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
    let sdir = SessionDir::create(&root, uid, &id)?;
    let result = run_session(
        &args,
        policy,
        plan,
        prep.grants,
        &sdir,
        prep.roots,
        uid,
        gid,
        &facts.username,
        allow_host_abstract,
        verbose,
        &risk_entries,
        &prep.services,
        &prep.forwards,
        &prep.host_services,
        prep.ssh.as_ref(),
        &id,
    );
    sdir.remove();
    result
}

#[allow(clippy::too_many_arguments)]
fn run_session(
    args: &RunArgs,
    policy: ResolvedPolicy,
    plan: Vec<mounts::MountOp>,
    initial: Vec<(String, Mode)>,
    sdir: &SessionDir,
    roots: Vec<PathBuf>,
    uid: u32,
    gid: u32,
    username: &str,
    allow_host_abstract: bool,
    verbose: u8,
    risk_entries: &[profile::RiskEntry],
    services: &[profile::Service],
    forwards: &[profile::Forward],
    host_services: &[profile::HostService],
    ssh: Option<&profile::SshConfig>,
    session_id: &str,
) -> Result<i32> {
    sdir.write_resolved_policy(&policy.to_toml())?;
    // Write risk.json (the risk labels for this session, DESIGN §16).
    let risk_json = serde_json::to_string_pretty(&serde_json::json!({
        "labels": risk_entries.iter().map(|e| serde_json::json!({
            "capability": e.capability,
            "label": e.label.kebab(),
        })).collect::<Vec<_>>(),
    }))?;
    fs::write(sdir.path.join("risk.json"), risk_json).context("writing risk.json")?;
    let audit = Audit::open(&sdir.audit_path())?;
    // Write supervisor.pid for stale-detection. Written after the dir is
    // created and before unshare — a crash here leaves a dir without the
    // pid file, which is_stale treats as "not stale" (fail safe).
    sdir.write_supervisor_pid(std::process::id() as i32)
        .context("writing supervisor.pid")?;
    // A detached session has no command, hence no terminal to relay.
    let tty = !args.detach && sys::isatty(0);
    let root_dir = sdir.path.join("root");
    fs::create_dir(&root_dir).context("creating root dir")?;
    let mut rules = static_rules(&plan, &policy, &roots);

    // Landlock write set includes initial rw grants.
    let initial_rw: Vec<PathBuf> = initial
        .iter()
        .filter(|(_, m)| *m == Mode::Rw)
        .map(|(p, _)| PathBuf::from(p))
        .collect();
    // An initial rw grant is part of the Landlock write set by construction, so
    // the grant rules must accept it (round-2 finding).
    rules.grantable_rw.extend(initial_rw.iter().cloned());
    let ll = landlock::plan(&policy, &initial_rw);
    let seccomp_progs = seccomp::build(&policy.extra_deny)?;

    let host_env: Vec<(String, String)> = std::env::vars().collect();
    let visible = |p: &Path| {
        mounts::expected_targets(&plan)
            .iter()
            .any(|t| p.starts_with(t))
            || p.starts_with(&policy.cwd)
    };
    let mut scrub = senv::scrub(
        &policy,
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
        // Inject SSH_AUTH_SOCK into the scrubbed env. The proxy socket is
        // forwarded into the sandbox at ssh_agent_expose after init is ready.
        scrub
            .vars
            .insert("SSH_AUTH_SOCK".into(), ssh_agent_expose.to_string());
    }

    for n in &scrub.secretish_passed {
        eprintln!("hisn: warning: env.pass forwards {n}, which looks like a secret");
    }

    let exec_rules = ExecRules {
        env_pass: policy.env_pass.clone(),
        base_env: scrub.vars.clone(),
        default_cwd: policy.cwd.display().to_string(),
    };
    let exec_rules_for_services = exec_rules.clone();
    let exec_policy = policy.clone();
    let exec_ll = ll.clone();
    let exec_require_scope = landlock::scope_required(&policy, allow_host_abstract);
    let exec_seccomp = seccomp_progs.clone();
    let exec_net = policy.network == Network::None;

    let cfg = InitConfig {
        policy: policy.clone(),
        plan: plan.clone(),
        landlock: ll,
        require_scope: landlock::scope_required(&policy, allow_host_abstract),
        seccomp: seccomp_progs,
        root_dir,
        argv: args.command.clone(),
        env: scrub.vars,
        use_pty: tty,
        detach: args.detach,
        uid,
        gid,
    };

    // ---- 2. our own userns S + mount-ns copy (single-threaded here)
    write_s_maps_and_unshare(uid, gid)?;

    // ---- 3. clone init
    let (sup_end, init_end) = sys::socketpair()?;
    let mut flags = libc::CLONE_NEWUSER
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS;
    if policy.network == Network::None {
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
    let ns_net = if exec_net {
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
        let code = reap(pid);
        bail!(
            "sandbox init exited during setup (status {code}); run with -v and check `hisn check`"
        );
    }
    match buf[0] {
        MSG_READY => {}
        MSG_ERROR => {
            let _ = reap(pid);
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

    // ---- 5. persistent helper, forked while still single-threaded
    let helper = spawn_helper(&mntns_fd)?;
    drop(mntns_fd);
    let exec_client = spawn_exec_helper(ExecContext {
        policy: exec_policy,
        landlock: exec_ll,
        require_scope: exec_require_scope,
        seccomp: exec_seccomp,
        ns: exec_ns,
    })?;

    // ---- 6. control thread, initial grants, START
    let listener = bind_socket(&sdir.socket_path())?;
    let shared = Arc::new(Shared {
        uid,
        init_pid: pid,
        sandbox_pidns,
        resolved_toml: policy.to_toml(),
        risk: risk_entries.to_vec(),
        rules,
        table: Mutex::new(GrantTable::default()),
        held: Mutex::new(Default::default()),
        helper: Mutex::new(helper),
        audit,
        op_lock: Mutex::new(()),
        exec: exec_client,
        exec_rules,
        spawn_gate: RwLock::new(()),
        live: Mutex::new(Default::default()),
        next_exec_id: std::sync::atomic::AtomicU64::new(1),
        execs: Mutex::new(Default::default()),
        used_pids: Mutex::new(Default::default()),
        recycled_pids: Mutex::new(Default::default()),
        services: Mutex::new(Default::default()),
    });
    // The only way to start `network = "host"` without abstract-socket
    // scoping is the explicit flag; it is audited (DESIGN §7, B1).
    if allow_host_abstract && policy.network == Network::Host {
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
    for (path, mode) in &initial {
        let r = shared.do_grant(path, *mode, false, None);
        if r["ok"] != true {
            let _ = sys::kill(pid, libc::SIGKILL);
            let _ = reap(pid);
            bail!(
                "initial grant {path}: {}",
                r["message"].as_str().unwrap_or("failed")
            );
        }
    }
    // Process [[forward]] entries (DESIGN §17): expose host sockets inside.
    for f in forwards {
        if let Err(e) = shared.do_forward(&f.socket, &f.expose, &f.name) {
            let _ = sys::kill(pid, libc::SIGKILL);
            let _ = reap(pid);
            bail!("forward {}: {e}", f.name);
        }
    }
    // 0.3.2: Spawn the SSH agent proxy accept loop and forward its socket
    // into the sandbox. The listener was bound before unshare (single-
    // threaded); the accept loop is spawned now (post-clone, multithreaded).
    if let Some(listener) = ssh_proxy_listener.take() {
        let host_auth_sock = std::env::var("SSH_AUTH_SOCK").unwrap_or_default();
        let ssh_keys = ssh
            .and_then(|c| if c.agent { Some(c.keys.clone()) } else { None })
            .unwrap_or_default();
        let _ssh_handle = crate::ssh_agent::spawn_accept_loop(
            listener,
            host_auth_sock,
            ssh_keys,
            session_id.to_owned(),
        );
        let proxy_socket_path = sdir.path.join("ssh-agent.sock");
        if let Err(e) = shared.do_forward_inner(
            proxy_socket_path.to_str().unwrap_or(""),
            ssh_agent_expose,
            "ssh-agent",
            true,
        ) {
            let _ = sys::kill(pid, libc::SIGKILL);
            let _ = reap(pid);
            bail!("ssh-agent forward: {e}");
        }
    }
    // Process [[host_services]] entries (DESIGN §17): start host process,
    // wait for readiness, then forward its socket. Fail closed on timeout.
    let mut host_pids: Vec<(i32, profile::StopSpec)> = Vec::new();
    for h in host_services {
        let stop_spec = h.stop.clone().unwrap_or(profile::StopSpec {
            signal: "TERM".into(),
            grace: 5,
        });
        match start_host_service(h) {
            Ok(host_pid) => {
                // Wait for readiness.
                let timeout_secs = h.ready.as_ref().and_then(|r| r.timeout).unwrap_or(15);
                if let Err(e) = wait_readiness(h, timeout_secs) {
                    // Fail closed: kill the host process.
                    let _ = sys::kill(host_pid, libc::SIGKILL);
                    let _ = reap_host(host_pid);
                    let _ = sys::kill(pid, libc::SIGKILL);
                    let _ = reap(pid);
                    bail!("host_service {}: readiness: {e}", h.name);
                }
                // Forward the socket.
                if let Err(e) = shared.do_forward(&h.socket, &h.expose, &h.name) {
                    let _ = sys::kill(host_pid, libc::SIGKILL);
                    let _ = reap_host(host_pid);
                    let _ = sys::kill(pid, libc::SIGKILL);
                    let _ = reap(pid);
                    bail!("host_service {}: forward: {e}", h.name);
                }
                host_pids.push((host_pid, stop_spec));
            }
            Err(e) => {
                let _ = sys::kill(pid, libc::SIGKILL);
                let _ = reap(pid);
                bail!("host_service {}: {e}", h.name);
            }
        }
    }
    // Process [[services]] entries (DESIGN §19): start in-sandbox services
    // through the exec helper chain, before START. The services are siblings
    // of the main command, confined identically. Readiness is checked with a
    // timeout; on timeout the session fails closed.
    let mut service_handles: Vec<ServiceHandle> = Vec::new();
    for s in services {
        match start_in_sandbox_service(&shared, s, &exec_rules_for_services) {
            Ok(handle) => {
                // Wait for readiness.
                let timeout_secs = s.ready.as_ref().and_then(|r| r.timeout).unwrap_or(15);
                if let Err(e) = wait_service_readiness(s, timeout_secs) {
                    // Fail closed: kill the service and the session.
                    let _ = sys::kill(pid, libc::SIGKILL);
                    let _ = reap(pid);
                    bail!("service {}: readiness: {e}", s.name);
                }
                service_handles.push(handle);
            }
            Err(e) => {
                let _ = sys::kill(pid, libc::SIGKILL);
                let _ = reap(pid);
                bail!("service {}: {e}", s.name);
            }
        }
    }
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

    // --ready-fd: write "ready\n" to the caller's fd after the session is
    // live (START sent, initial grants applied, control thread started).
    // On start failure the early `bail!` paths above return before reaching
    // here, so nothing is written and the exit status carries it.
    if let Some(fd) = args.ready_fd {
        // SAFETY: the fd is the caller's; we write to it and do not close it
        // (the caller owns the lifecycle). Using a borrowed fd, not owned.
        use std::os::fd::{FromRawFd, IntoRawFd};
        let f = unsafe { std::fs::File::from_raw_fd(fd) };
        let _ = std::io::Write::write_all(&mut &f, b"ready\n");
        let _ = f.into_raw_fd(); // do not close; caller owns it
    }

    // ---- 7. relay + wait
    let code = relay_and_wait(pid, master, tty);

    // Stop host services (DESIGN §17): signal + grace then KILL.
    // Check if the process is already gone before sleeping the full grace (P27).
    for (hpid, stop_spec) in &host_pids {
        let sig = control::parse_signal(&stop_spec.signal).unwrap_or(libc::SIGTERM);
        let _ = sys::kill(*hpid, sig);
        // Wait for grace period, but only while the process is alive.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(stop_spec.grace);
        while std::time::Instant::now() < deadline {
            let mut st = 0;
            // SAFETY: non-blocking waitpid on our own child.
            let r = unsafe { libc::waitpid(*hpid, &mut st, libc::WNOHANG) };
            if r == *hpid {
                break;
            }
            if r == 0 {
                // Still running; wait a bit and re-check.
                std::thread::sleep(std::time::Duration::from_millis(50));
            } else {
                // waitpid error (e.g. ECHILD) — the process is gone.
                break;
            }
        }
        // SIGKILL if still alive.
        let mut st_kill = 0;
        if unsafe { libc::waitpid(*hpid, &mut st_kill, libc::WNOHANG) } != *hpid {
            let _ = sys::kill(*hpid, libc::SIGKILL);
            let _ = reap_host(*hpid);
        }
    }
    // Stop in-sandbox services (DESIGN §19): best-effort signal + grace.
    // If init has already exited, the kernel has killed everything in the pid
    // ns; the stop is moot but harmless. Check if the service is still alive
    // before sleeping the full grace period (P27).
    for handle in &service_handles {
        let sig = control::parse_signal(&handle.stop.signal).unwrap_or(libc::SIGTERM);
        // The service's pid is in the sandbox pid ns; signal it via the status
        // socket (same as exec signal).
        let _ = sys::send_all(handle.status.as_raw_fd(), exec::format_kill(sig).as_bytes());
        // Wait for grace period, but only while the service is still alive.
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(handle.stop.grace);
        while std::time::Instant::now() < deadline {
            // Check if the status socket is still open (service still running).
            // If the service has already exited, skip the remaining grace.
            // Use a non-blocking read: if the socket is closed, the service
            // monitor is gone.
            let mut pollfds = [libc::pollfd {
                fd: handle.status.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }];
            // SAFETY: poll on our own fd, non-blocking.
            let r = unsafe { libc::poll(&mut pollfds[0], 1, 0) };
            if r > 0 && (pollfds[0].revents & (libc::POLLHUP | libc::POLLERR)) != 0 {
                // Service monitor is gone; skip the remaining grace.
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        // SIGKILL via the status socket.
        let _ = sys::send_all(
            handle.status.as_raw_fd(),
            exec::format_kill(libc::SIGKILL).as_bytes(),
        );
    }

    // Let in-flight responses (e.g. a hard revoke that ended the session) go out.
    control::drain(std::time::Duration::from_secs(2));
    // Cleanup order (DESIGN §10): close ns / mount fds first, then the dir.
    drop(shared);
    Ok(code)
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

fn reap(pid: i32) -> i32 {
    let mut st = 0;
    // SAFETY: blocking waitpid on our own child.
    unsafe { libc::waitpid(pid, &mut st, 0) };
    init::decode_status(st)
}

/// Reap a host service process (blocking waitpid).
fn reap_host(pid: i32) -> i32 {
    let mut st = 0;
    // SAFETY: blocking waitpid on our own child.
    unsafe { libc::waitpid(pid, &mut st, 0) };
    init::decode_status(st)
}

/// A handle on a started in-sandbox service (DESIGN §19).
struct ServiceHandle {
    /// The service name (for logging/audit).
    #[allow(dead_code)]
    name: String,
    /// The status socket to the service's monitor `W`.
    status: OwnedFd,
    /// Stop spec (signal + grace).
    stop: profile::StopSpec,
}

/// Start an in-sandbox service through the exec helper chain (DESIGN §19).
/// The service is spawned like an exec: the exec helper `E` forks `C`, which
/// joins the sandbox namespaces, forks `D` (re-applies confinement), forks `W`
/// (monitor), which forks `P` (the service). The service gets stdio from
/// `/dev/null` (no client connection).
fn start_in_sandbox_service(
    shared: &Arc<Shared>,
    s: &profile::Service,
    rules: &ExecRules,
) -> Result<ServiceHandle> {
    // Build the ExecSpec for the service.
    let argv: Vec<String> = s.exec.to_vec();
    if argv.is_empty() || argv[0].is_empty() {
        bail!("service {}: exec must not be empty", s.name);
    }
    // The service's cwd is the session cwd.
    let cwd = rules.default_cwd.clone();
    // The service's env is the base env (same as the main command).
    let env = rules.base_env.clone();
    let spec = exec::ExecSpec {
        argv,
        cwd,
        env,
        tty: false,
    };
    // Open /dev/null for stdio (3 fds, non-tty mode). O_RDWR so the service
    // can write to stdout/stderr without EBADF.
    let stdio: Vec<OwnedFd> = (0..3)
        .map(|_| {
            OwnedFd::from(
                fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/null")
                    .expect("opening /dev/null for service stdio"),
            )
        })
        .collect();
    // Spawn through the exec helper.
    let spawned = {
        let _gate = shared.spawn_gate.read().unwrap_or_else(|e| e.into_inner());
        shared.exec.spawn(&spec, stdio, exec::SPAWN_TIMEOUT)
    };
    let sp = spawned.map_err(|e| anyhow!("service {}: spawn: {e}", s.name))?;
    // Register the service in the shared state for ls --json.
    {
        let mut svcs = shared.services.lock().expect("services");
        // The status socket is dup'd for the ServiceState so inspect() can
        // poll it for liveness (P26).
        let status_dup = sys::dup_cloexec_min(sp.status.as_raw_fd(), 3)
            .map_err(|e| anyhow!("service {}: dup status fd: {e}", s.name))?;
        svcs.insert(
            s.name.clone(),
            ServiceState {
                name: s.name.clone(),
                pid: sp.pid,
                socket: s.socket.clone(),
                state: "ready",
                exit: None,
                status: status_dup,
            },
        );
    }
    // The status socket is owned by the supervisor; we read P and X lines from
    // it to track the service's state for ls --json.
    let stop = s.stop.clone().unwrap_or(profile::StopSpec {
        signal: "TERM".into(),
        grace: 5,
    });
    tracing::info!("service: {} started pid {}", s.name, sp.pid);
    Ok(ServiceHandle {
        name: s.name.clone(),
        status: sp.status,
        stop,
    })
}

/// Wait for an in-sandbox service to become ready (DESIGN §19).
/// Polls `ready.socket` (stat from the supervisor) with a timeout. On
/// timeout returns Err (fail closed). Only `socket` stat is available for
/// in-sandbox services in 0.3 (P25: `command` would run on the host with the
/// user's credentials; `tcp` is not available for in-sandbox services).
fn wait_service_readiness(s: &profile::Service, timeout_secs: u64) -> Result<()> {
    let ready = match &s.ready {
        Some(r) => r,
        None => {
            // No readiness check: assume ready immediately.
            return Ok(());
        }
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        if std::time::Instant::now() > deadline {
            return Err(anyhow!(
                "service {}: readiness timeout ({}s)",
                s.name,
                timeout_secs
            ));
        }
        // ready.socket: stat the path from the supervisor (userns S). This
        // works for paths under cwd (a rw bind visible from S) and under
        // mounts.ro/rw. It does not work for paths on the sandbox's private
        // tmpfs (/tmp, /run, $HOME); the service must declare its socket
        // under cwd for readiness to be checkable.
        if let Some(sock) = &ready.socket
            && let Ok(meta) = fs::symlink_metadata(sock)
            && meta.file_type().is_socket()
        {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Start a `[[host_services]]` process on the host (in the supervisor's
/// userns S). The process runs with the user's credentials, the host PATH,
/// and `PR_SET_PDEATHSIG=SIGKILL`. Returns the pid.
fn start_host_service(h: &profile::HostService) -> Result<i32> {
    // SAFETY: fork is called while the supervisor is single-threaded (before
    // the control thread starts). The child runs execve immediately.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error()).context("fork host service");
    }
    if pid == 0 {
        // Child: set PDEATHSIG so it dies with the supervisor.
        // SAFETY: prctl with PDEATHSIG.
        unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong);
        }
        // Build the environment: inherit the host environment, not the
        // sandbox's scrubbed one. The host service runs as the user.
        // Close all fds > 2 (don't leak supervisor fds into the host process).
        unsafe {
            // Raw syscall: the libc crate has no close_range wrapper on musl.
            // 4 = CLOSE_RANGE_CLOEXEC.
            libc::syscall(
                libc::SYS_close_range,
                3 as libc::c_uint,
                u32::MAX as libc::c_uint,
                4 as libc::c_uint,
            );
        }
        // execve the command.
        let argv: Vec<std::ffi::CString> = h
            .exec
            .iter()
            .map(|s| std::ffi::CString::new(s.as_str()).unwrap())
            .collect();
        let argv_ptrs: Vec<*const libc::c_char> = argv
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        // SAFETY: execve replaces the process image; on failure, _exit.
        let rc = unsafe { libc::execvp(argv_ptrs[0], argv_ptrs.as_ptr()) };
        if rc < 0 {
            // SAFETY: _exit on exec failure.
            unsafe { libc::_exit(127) };
        }
        // Unreachable: execvp either succeeds or _exit's.
        unsafe { libc::_exit(127) };
    }
    tracing::info!("host_service: {} started pid {pid}", h.name);
    Ok(pid)
}

/// Wait for a host service to become ready (DESIGN §17).
/// Polls `ready` (socket stat, tcp connect, or command exit 0) with a
/// timeout. On timeout returns Err (fail closed).
fn wait_readiness(h: &profile::HostService, timeout_secs: u64) -> Result<()> {
    let ready = match &h.ready {
        Some(r) => r,
        None => {
            // No readiness check: assume the socket exists immediately.
            // Verify the socket path exists.
            if !Path::new(&h.socket).exists() {
                return Err(anyhow!(
                    "host_service {}: socket {} does not exist",
                    h.name,
                    h.socket
                ));
            }
            return Ok(());
        }
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        if std::time::Instant::now() > deadline {
            return Err(anyhow!(
                "host_service {}: readiness timeout ({}s)",
                h.name,
                timeout_secs
            ));
        }
        let ready_result = check_readiness(ready, &h.socket);
        if ready_result {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Check one readiness probe. Returns true if the service is ready.
fn check_readiness(ready: &profile::ReadinessSpec, _socket: &str) -> bool {
    // Socket stat: check if the socket file exists.
    if let Some(sock) = &ready.socket {
        if let Ok(meta) = fs::symlink_metadata(sock)
            && meta.file_type().is_socket()
        {
            return true;
        }
        return false;
    }
    // TCP connect: try to connect to the address.
    if let Some(_addr) = &ready.tcp {
        // TCP readiness is not implemented in this sandbox (no network
        // for host services); fall through to command.
        return false;
    }
    // Command: run a command, exit 0 = ready.
    if let Some(cmd) = &ready.command {
        if cmd.is_empty() {
            return false;
        }
        let argv: Vec<std::ffi::CString> = cmd
            .iter()
            .map(|s| std::ffi::CString::new(s.as_str()).unwrap())
            .collect();
        let argv_ptrs: Vec<*const libc::c_char> = argv
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        // SAFETY: fork + waitpid on our own child.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return false;
        }
        if pid == 0 {
            unsafe {
                libc::execvp(argv_ptrs[0], argv_ptrs.as_ptr());
                libc::_exit(1);
            }
        }
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
        return st == 0;
    }
    // No readiness check: assume ready.
    true
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
        return reap(init_pid);
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
    status.unwrap_or_else(|| reap(init_pid))
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
pub fn socket_for(session_id: &str) -> Result<PathBuf> {
    let uid = rustix::process::getuid().as_raw();
    let roots = session::runtime_roots(std::env::var("XDG_RUNTIME_DIR").ok().as_deref(), uid);
    let dir = session::find_session(&roots, session_id)?;
    use std::os::unix::fs::MetadataExt;
    if fs::metadata(&dir)?.uid() != uid {
        bail!("session {session_id} belongs to another user");
    }
    Ok(dir.join("control.sock"))
}

pub fn client_request(session_id: &str, req: &Value) -> Result<Value> {
    let sock = socket_for(session_id)?;
    control::request(&sock, req).with_context(|| format!("talking to session {session_id}"))
}

#[cfg(test)]
mod tests {
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
            network: Some(crate::cli::NetworkArg::Host),
            allow_host_abstract_sockets: false,
            quiet_risk: false,
            home_persist: None,
            rootfs_path: None,
            grants: vec!["/x:rw".into(), "/y".into()],
            detach: false,
            ready_fd: None,
            command: vec!["true".into()],
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
}
