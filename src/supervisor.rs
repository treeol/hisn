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

// ------------------------------------------------------------------- state

struct Held {
    mount_root: OwnedFd,
}

struct Shared {
    uid: u32,
    init_pid: i32,
    sandbox_pidns: u64,
    resolved_toml: String,
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
        let registered = sys::dup_cloexec_min(sp.status.as_raw_fd(), 3)
            .ok()
            .map(|h| {
                self.live.lock().expect("live").insert(sp.pid, h);
                sp.pid
            });
        let mut w = conn;
        let started = writeln!(w, "{}", ok(json!({ "pid": sp.pid })));
        let outcome = if started.is_ok() {
            exec::drive(&sp.status, sp.pending, conn.as_raw_fd(), exec::CANCEL_GRACE)
        } else {
            // Client already gone: cancel through the normal path.
            exec::drive(&sp.status, sp.pending, -1, std::time::Duration::ZERO)
        };
        if let Some(pid) = registered {
            self.live.lock().expect("live").remove(&pid);
        }
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
    fn do_signal(&self, pid: i32, signal: &str) -> Value {
        let Some(sig) = control::parse_signal(signal) else {
            return err(control::E_BAD_REQUEST, format!("unknown signal {signal:?}"));
        };
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
        match fs::read_to_string(format!("/proc/{}/mountinfo", self.init_pid)) {
            Ok(mi) => ok(json!({
                "mountinfo": mi,
                "policy": self.resolved_toml,
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
            Request::Signal { pid, signal } => self.sh.do_signal(pid, &signal),
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

fn getids() -> (u32, u32, String) {
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    let name = std::env::var("USER")
        .ok()
        .filter(|u| {
            !u.is_empty()
                && u.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        })
        .unwrap_or_else(|| "user".into());
    (uid, gid, name)
}

/// Resolve policy + flags into the resolved policy, grant list, runtime roots.
pub struct Prepared {
    pub policy: ResolvedPolicy,
    pub grants: Vec<(String, Mode)>,
    pub roots: Vec<PathBuf>,
}

pub fn prepare(args: &RunArgs, uid: u32) -> Result<Prepared> {
    let roots = session::runtime_roots(std::env::var("XDG_RUNTIME_DIR").ok().as_deref(), uid);
    let cwd_base = std::env::current_dir().context("current dir")?;
    let (pol, base) = match &args.policy {
        Some(f) => {
            let p = Policy::load(f).with_context(|| f.display().to_string())?;
            let b = f
                .parent()
                .filter(|b| !b.as_os_str().is_empty())
                .map(Path::to_path_buf)
                .unwrap_or(cwd_base.clone());
            (p, b)
        }
        None => (Policy::default(), cwd_base.clone()),
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
    })
}

fn mountinfo_check(policy: &ResolvedPolicy, roots: &[PathBuf]) -> Result<()> {
    let mi = fs::read_to_string("/proc/self/mountinfo")
        .context("reading mountinfo (R1b fails closed)")?;
    let mut trees: Vec<(PathBuf, bool)> = vec![(policy.cwd.clone(), true)];
    trees.extend(policy.ro.iter().map(|p| (p.clone(), true)));
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
    let (uid, gid, username) = getids();
    let prep = prepare(&args, uid)?;
    let policy = prep.policy;
    if !args.grants.iter().all(|g| !g.is_empty()) {
        bail!("empty --grant");
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
        allow_host_abstract,
        verbose,
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
    allow_host_abstract: bool,
    verbose: u8,
) -> Result<i32> {
    sdir.write_resolved_policy(&policy.to_toml())?;
    let audit = Audit::open(&sdir.audit_path())?;
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
    let scrub = senv::scrub(
        &policy,
        host_env.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        visible,
    );
    for n in &scrub.secretish_passed {
        eprintln!("hisn: warning: env.pass forwards {n}, which looks like a secret");
    }

    let exec_rules = ExecRules {
        env_pass: policy.env_pass.clone(),
        base_env: scrub.vars.clone(),
        default_cwd: policy.cwd.display().to_string(),
    };
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
    // The exec helper's namespaces, opened now like the mount namespace (D24).
    // `root` is the sandbox root as reached from the supervisor:
    // `/proc/<init>/root` — after pivot_root that is the sandbox tmpfs root.
    // `C` fchdirs onto it because `setns(mnt)` does not move root/cwd (D25).
    let exec_ns = NsFds {
        user: open_ns(pid, "user")?,
        mnt: open_ns(pid, "mnt")?,
        ipc: open_ns(pid, "ipc")?,
        uts: open_ns(pid, "uts")?,
        pid: open_ns(pid, "pid")?,
        net: if exec_net {
            Some(open_ns(pid, "net")?)
        } else {
            None
        },
        root: {
            let f = fs::File::open(format!("/proc/{pid}/root"))
                .with_context(|| format!("opening /proc/{pid}/root"))?;
            let m = f.metadata()?;
            if !m.is_dir() {
                bail!("/proc/{pid}/root is not a directory");
            }
            f.into()
        },
    };
    let sandbox_pidns = sys::ns_inode(pid, "pid").context("sandbox pid namespace")?;
    sys::send_with_fd(sup_end.as_raw_fd(), &[MSG_GO], None)?;
    let mut buf = [0u8; 4096];
    let (n, master) =
        sys::recv_with_fd(sup_end.as_raw_fd(), &mut buf).context("waiting for sandbox setup")?;
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
    });
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
    sys::send_with_fd(sup_end.as_raw_fd(), &[MSG_START], None)?;
    thread::spawn(move || control::serve(listener, handler));

    // ---- 7. relay + wait
    let code = relay_and_wait(pid, master, tty);

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
            rw: vec![],
            mask: vec![],
            grantable_rw: vec!["/data/shared".into()],
            env_pass: vec![],
            env_set: Default::default(),
            extra_deny: vec![],
            nofile: 1,
            nproc: 1,
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
            cwd: Some(cwd.clone()),
            session_id: None,
            network: Some(crate::cli::NetworkArg::Host),
            allow_host_abstract_sockets: false,
            grants: vec!["/x:rw".into(), "/y".into()],
            detach: false,
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
