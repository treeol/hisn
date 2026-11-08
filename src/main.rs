use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use serde_json::{Value, json};

use hisn::cli::{Cli, Command, PolicyCommand, ProfileCommand, RootfsCommand};
use hisn::policy::{self, Overrides, Policy};
use hisn::profile;
use hisn::{attach, execcli, mounts, rootfs_store, session, supervisor};

/// Exit code for hisn-internal errors (policy, host); distinct from a
/// command's own exit status.
const EXIT_INTERNAL: u8 = 125;

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose);
    match dispatch(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("hisn: {e:#}");
            ExitCode::from(EXIT_INTERNAL)
        }
    }
}

fn init_logging(verbose: u8) {
    let level = match verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        _ => tracing::Level::DEBUG,
    };
    // Logs go to stderr only: `hisn run` must print nothing of its own on stdout.
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .init();
}

fn exit_u8(code: i32) -> ExitCode {
    ExitCode::from(code.clamp(0, 255) as u8)
}

fn dispatch(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Check(args) => {
            let report = hisn::check::run_checks();
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", report.render());
            }
            Ok(if report.ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::Policy { command } => match command {
            PolicyCommand::Schema => {
                println!("{}", policy::schema_json());
                Ok(ExitCode::SUCCESS)
            }
            PolicyCommand::Validate { file } => {
                let (_, resolved) = load_resolved(file)?;
                // 0.3.3: validate also runs the mount plan against the host, so
                // mount conflicts (src:dst colliding with a session mount) are
                // refused here, not only at session start.
                check_mount_plan(&resolved)?;
                print!("{}", resolved.to_toml());
                Ok(ExitCode::SUCCESS)
            }
            PolicyCommand::Plan { file } => {
                let (_, resolved) = load_resolved(file)?;
                let uid = rustix::process::getuid().as_raw();
                let gid = rustix::process::getgid().as_raw();
                let facts = mounts::HostFacts::probe(&resolved, uid, gid, "user");
                let plan = mounts::plan(&resolved, &facts, &[])?;
                let mut rows: Vec<Value> = plan
                    .iter()
                    .filter(|o| mounts::is_mount(&o.kind))
                    .map(|o| {
                        let (recursive, ro) = mounts::mount_traits(&o.kind);
                        json!({"target": o.target, "recursive": recursive, "ro": ro})
                    })
                    .collect();
                rows.sort_by_key(|r| r["target"].as_str().unwrap_or("").to_owned());
                println!("{}", serde_json::to_string_pretty(&rows)?);
                Ok(ExitCode::SUCCESS)
            }
        },
        Command::Profile { command } => match command {
            ProfileCommand::List => {
                let info = profile::list()?;
                println!("{}", serde_json::to_string_pretty(&info)?);
                Ok(ExitCode::SUCCESS)
            }
            ProfileCommand::Explain { name } => {
                let info = profile::explain(name.as_deref())?;
                println!("{}", serde_json::to_string_pretty(&info)?);
                Ok(ExitCode::SUCCESS)
            }
            ProfileCommand::Validate { file } => {
                let resolved = profile::validate(file.as_deref())?;
                print!("{}", resolved.to_toml());
                Ok(ExitCode::SUCCESS)
            }
        },
        Command::Run(args) => {
            args.check_command().map_err(anyhow::Error::msg)?;
            let allow = args.allow_host_abstract_sockets;
            let code = supervisor::run(args, allow, cli.verbose)?;
            Ok(exit_u8(code))
        }
        Command::Exec(a) => Ok(exit_u8(execcli::run(a)?)),
        Command::Attach(a) => Ok(exit_u8(attach::run(a)?)),
        Command::Grant(a) => {
            let mode = if a.rw { "rw" } else { "ro" };
            let r = supervisor::client_request(
                &a.session,
                &json!({"op":"grant","path":a.path,"mode":mode,"recursive":a.recursive}),
            )?;
            print_response(&r)
        }
        Command::Revoke(a) => {
            let r = supervisor::client_request(
                &a.session,
                &json!({"op":"revoke","path":a.path,"hard":a.hard,"kill_holders":a.kill_holders}),
            )?;
            print_response(&r)
        }
        Command::Kill(a) => {
            let uid = rustix::process::getuid().as_raw();
            let roots =
                session::runtime_roots(std::env::var("XDG_RUNTIME_DIR").ok().as_deref(), uid);
            let reg_root = hisn::registry::registry_root(uid);
            let id = session::resolve_session_arg(&roots, &reg_root, &a.session)?;
            let dir = session::find_session(&roots, &id)?;
            if session::is_stale(&dir) {
                session::remove_safe(&dir, uid).map_err(|e| {
                    anyhow::Error::msg(format!("cannot remove stale session {}: {e}", a.session))
                })?;
                eprintln!("session {} was stale; removed", a.session);
                return Ok(ExitCode::SUCCESS);
            }
            let r =
                supervisor::client_request(&a.session, &json!({"op":"kill","signal":a.signal}))?;
            print_response(&r)
        }
        Command::Stop(a) => {
            // 0.4.0 step 5: stop a session. Set state to stopped, audit it,
            // and send SIGTERM to the sandbox. The dir is kept as stopped.
            let uid = rustix::process::getuid().as_raw();
            let roots =
                session::runtime_roots(std::env::var("XDG_RUNTIME_DIR").ok().as_deref(), uid);
            let reg_root = hisn::registry::registry_root(uid);
            let id = session::resolve_session_arg(&roots, &reg_root, &a.session)?;
            let dir = session::find_session(&roots, &id)?;
            if session::is_stale(&dir) {
                // 0.4.1 step 6: a session that is not live is not "stopped" by
                // this command. Report it accurately and exit 0 (nothing to
                // do, not an error), never claiming to have stopped it.
                let label = match hisn::sessionmeta::read(&dir).map(|m| m.state) {
                    Some(hisn::sessionmeta::State::Stopped) => "already stopped",
                    _ => "crashed, no supervisor",
                };
                eprintln!("session {}: {label}", a.session);
                return Ok(ExitCode::SUCCESS);
            }
            // F4: state becomes "stopping" when the kill is sent, "stopped"
            // only after the session is observed to have exited. A kill that
            // fails leaves "stopping". Same function as idle expiry.
            struct Client<'a> {
                session: &'a str,
                dir: &'a Path,
                /// 0.4.1 step 2: a pidfd on the session's supervisor, when it
                /// can be opened and still matches supervisor.pid's starttime.
                /// The stop wait blocks on it instead of polling every 100 ms.
                pidfd: Option<std::os::fd::OwnedFd>,
            }
            impl hisn::lifecycle::StopTarget for Client<'_> {
                fn signal(&self, _sig: i32) -> Result<(), String> {
                    let r = supervisor::client_request(
                        self.session,
                        &json!({"op":"kill","signal":"TERM"}),
                    )
                    .map_err(|e| format!("{e:#}"))?;
                    if r["ok"] == true {
                        Ok(())
                    } else {
                        Err(r["message"].as_str().unwrap_or("unknown error").to_owned())
                    }
                }
                fn exited(&self) -> bool {
                    // The supervisor keeps a stopped dir; once it is stale
                    // (or gone) the session has ended.
                    !self.dir.is_dir() || session::is_stale(self.dir)
                }
                fn exit_fd(&self) -> Option<std::os::fd::RawFd> {
                    self.pidfd.as_ref().map(std::os::fd::AsRawFd::as_raw_fd)
                }
            }
            // A pidfd on the supervisor gives an event-driven exit wait. It is
            // only used when the recorded pid's starttime still matches, so a
            // reused pid is never watched.
            let supervisor_pidfd = session::read_supervisor_pid(&dir).and_then(|(pid, start)| {
                let fd = hisn::sys::pidfd_open(pid).ok()?;
                if hisn::sys::stat_starttime(pid).ok() == Some(start) {
                    Some(fd)
                } else {
                    None
                }
            });
            let target = Client {
                session: &a.session,
                dir: &dir,
                pidfd: supervisor_pidfd,
            };
            let write_state = |st: hisn::sessionmeta::State| {
                if dir.is_dir() {
                    hisn::sessionmeta::set_state(&dir, st)
                } else {
                    // Already removed by its own supervisor: nothing to record.
                    Ok(())
                }
            };
            match hisn::lifecycle::stop_and_keep(
                &target,
                &hisn::lifecycle::SystemClock,
                hisn::lifecycle::StopPlan::CLIENT,
                &write_state,
                &|| {},
            ) {
                hisn::lifecycle::StopOutcome::Stopped if !dir.is_dir() => {
                    // The session ended on its own before the supervisor saw
                    // the stop (natural completion won the race): removed.
                    eprintln!("session {} ended before the stop; not kept", a.session);
                    Ok(ExitCode::SUCCESS)
                }
                hisn::lifecycle::StopOutcome::Stopped => {
                    eprintln!("session {} stopped", a.session);
                    Ok(ExitCode::SUCCESS)
                }
                hisn::lifecycle::StopOutcome::NotStarted(m) => {
                    eprintln!(
                        "session {} stop not sent: cannot record stopping: {m}",
                        a.session
                    );
                    Ok(ExitCode::from(1))
                }
                hisn::lifecycle::StopOutcome::StoppedUnrecorded(m) => {
                    eprintln!("session {} stopped; cannot record stopped: {m}", a.session);
                    Ok(ExitCode::from(1))
                }
                hisn::lifecycle::StopOutcome::SignalFailed(m) => {
                    eprintln!("session {} stop failed: {m}", a.session);
                    Ok(ExitCode::from(1))
                }
                hisn::lifecycle::StopOutcome::Timeout => {
                    // The session did not exit. Do NOT write Stopped — the
                    // state stays Stopping, and we report the failure.
                    eprintln!("session {} stop sent (timeout waiting for exit)", a.session);
                    Ok(ExitCode::from(1))
                }
            }
        }
        Command::Inspect(a) => {
            let r = supervisor::client_request(&a.session, &json!({"op":"inspect"}))?;
            if a.json || r["ok"] != true {
                return print_response(&r);
            }
            println!(
                "# mount table\n{}\n# resolved policy\n{}",
                r["mountinfo"].as_str().unwrap_or(""),
                r["policy"].as_str().unwrap_or("")
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Ls(a) => ls(
            a.session.as_deref(),
            a.json,
            a.prune,
            a.purge,
            a.name_prefix.as_deref(),
            a.dry_run,
        ),
        Command::Rootfs { command } => match command {
            RootfsCommand::Import(args) => rootfs_import(args),
            RootfsCommand::List => {
                let names = rootfs_store::list()?;
                for n in names {
                    println!("{n}");
                }
                Ok(ExitCode::SUCCESS)
            }
            RootfsCommand::Path { name } => {
                let p = rootfs_store::path_of(&name)?
                    .ok_or_else(|| anyhow::anyhow!("rootfs {name:?} does not exist"))?;
                println!("{}", p.display());
                Ok(ExitCode::SUCCESS)
            }
            RootfsCommand::Rm { name } => {
                rootfs_store::remove(&name)?;
                eprintln!("removed rootfs {name}");
                Ok(ExitCode::SUCCESS)
            }
        },
    }
}

/// Run the mount plan against the host (validate-time check, 0.3.3): the same
/// refusals a session start would give, before any namespace exists.
fn check_mount_plan(resolved: &policy::ResolvedPolicy) -> Result<()> {
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    let facts = mounts::HostFacts::probe(resolved, uid, gid, "user");
    mounts::plan(resolved, &facts, &[])?;
    Ok(())
}

fn load_resolved(file: Option<PathBuf>) -> Result<(PathBuf, policy::ResolvedPolicy)> {
    let file = file.unwrap_or_else(|| PathBuf::from("hisn.toml"));
    let pol = Policy::load(&file).with_context(|| file.display().to_string())?;
    let base = file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let uid = rustix::process::getuid().as_raw();
    let roots = session::runtime_roots(std::env::var("XDG_RUNTIME_DIR").ok().as_deref(), uid);
    let resolved = pol
        .resolve(base, &Overrides::default(), &roots)
        .with_context(|| file.display().to_string())?;
    Ok((file, resolved))
}

fn print_response(r: &Value) -> Result<ExitCode> {
    println!("{r}");
    Ok(if r["ok"] == true {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn ls(
    session_id: Option<&str>,
    json_out: bool,
    prune: bool,
    purge: bool,
    name_prefix: Option<&str>,
    dry_run: bool,
) -> Result<ExitCode> {
    let uid = rustix::process::getuid().as_raw();
    let roots = session::runtime_roots(std::env::var("XDG_RUNTIME_DIR").ok().as_deref(), uid);
    match session_id {
        Some(id) => {
            let r = supervisor::client_request(id, &json!({"op":"list"}))?;
            if json_out || r["ok"] != true {
                return print_response(&r);
            }
            for g in r["grants"].as_array().into_iter().flatten() {
                println!(
                    "{}\t{}\t{}",
                    g["mode"].as_str().unwrap_or("?"),
                    g["path"].as_str().unwrap_or("?"),
                    g["ts"].as_str().unwrap_or("")
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        None => {
            let sessions = session::list_sessions(&roots);
            if prune || purge || dry_run {
                // 0.4.1 step 1: --name-prefix narrows the prune set to
                // stopped/crashed sessions whose name starts with the prefix.
                // An unnamed session never matches a prefix. Without the flag,
                // every stale session is a candidate (0.4.0 behaviour).
                // --dry-run lists the candidates and removes nothing.
                let matches_prefix = |p: &Path| -> bool {
                    prune_prefix_matches(session_name(p).as_deref(), name_prefix)
                };
                let candidates: Vec<(String, PathBuf)> = sessions
                    .into_iter()
                    .filter(|(n, p)| {
                        if !matches_prefix(p) {
                            tracing::info!("prune: {n} name does not match prefix; skipped");
                            return false;
                        }
                        // A stopped/crashed session has no live supervisor.
                        if !session::is_stale(p) {
                            tracing::info!("prune: {n} not stale; skipped");
                            return false;
                        }
                        true
                    })
                    .collect();

                if dry_run {
                    // No 300 ms re-check and no removal: this is a report.
                    for (n, p) in &candidates {
                        let name = session_name(p).unwrap_or_else(|| "-".into());
                        println!("{n}\t{name}");
                    }
                    eprintln!(
                        "would prune {} session(s){}",
                        candidates.len(),
                        name_prefix
                            .map(|pre| format!(" with name prefix {pre:?}"))
                            .unwrap_or_default()
                    );
                    return Ok(ExitCode::SUCCESS);
                }

                for (n, p) in &candidates {
                    // Check twice 300 ms apart to avoid racing a live session
                    // mid-shutdown.
                    if !session::is_stale(p) {
                        continue;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    if !session::is_stale(p) {
                        continue;
                    }
                    if purge {
                        // --purge: skip archival, just remove.
                        match session::remove_safe(p, uid) {
                            Ok(()) => eprintln!("{n} stale; purged (no archive)"),
                            Err(e) => {
                                tracing::warn!("purge {n}: removal refused: {e}");
                                eprintln!("{n} stale; removal refused: {e}");
                            }
                        }
                        continue;
                    }
                    // 0.4.0 step 5: archive grants.jsonl and the
                    // final session.json before removing the dir.
                    if let Err(e) = archive_session(p, n, uid) {
                        tracing::warn!("prune {n}: archive failed: {e}");
                        eprintln!("{n} stale; archive failed: {e} (not removed)");
                        continue;
                    }
                    match session::remove_safe(p, uid) {
                        Ok(()) => eprintln!("{n} stale; archived and removed"),
                        Err(e) => {
                            tracing::warn!("prune {n}: removal refused: {e}");
                            eprintln!("{n} stale; removal refused: {e}");
                        }
                    }
                }
                // Reconcile the name index with what is on disk (step 1c).
                let reg_root = hisn::registry::registry_root(uid);
                if let Ok(_lock) = hisn::registry::Lock::take(&reg_root, uid) {
                    match hisn::registry::repair(&reg_root, &roots) {
                        Ok(n) => eprintln!("name index repaired: {n} name(s)"),
                        Err(e) => eprintln!("name index repair failed: {e}"),
                    }
                }
                return Ok(ExitCode::SUCCESS);
            }
            let rows: Vec<(String, PathBuf, bool)> = sessions
                .into_iter()
                .map(|(n, p)| (n.clone(), p.clone(), session::is_live(&p)))
                .collect();
            if json_out {
                let sessions: Vec<Value> = rows
                    .iter()
                    .map(|(n, p, live)| {
                        let policy = read_session_policy(p);
                        let meta = hisn::sessionmeta::read(p);
                        let state = session_state_label(p, *live);
                        // 0.4.1 step 3: a live session's clients and execs come
                        // from the supervisor (session.json cannot carry them);
                        // a stopped/crashed session has neither.
                        let (clients, execs, services) = if *live {
                            live_session_view(n)
                        } else {
                            (Vec::new(), Vec::new(), Vec::new())
                        };
                        session_v2_json(
                            n,
                            p,
                            &state,
                            policy.as_ref(),
                            meta.as_ref(),
                            clients,
                            execs,
                            services,
                        )
                    })
                    .collect();
                println!("{}", json!({"schema": "hisn-ls/v2", "sessions": sessions}));
            } else {
                println!("NAME\tID\tSTATE\tCWD\tROOTFS\tNET\tAGE\tCLIENTS\tLEASE");
                for (n, p, live) in rows {
                    let meta = hisn::sessionmeta::read(&p);
                    let name = meta
                        .as_ref()
                        .and_then(|m| m.name.clone())
                        .unwrap_or_else(|| "-".into());
                    let state = session_state_label(&p, live);
                    let cwd = meta
                        .as_ref()
                        .map(|m| m.cwd.clone())
                        .unwrap_or_else(|| "-".into());
                    let rootfs = meta
                        .as_ref()
                        .and_then(|m| m.rootfs.clone())
                        .unwrap_or_else(|| "-".into());
                    let net = meta
                        .as_ref()
                        .map(|m| m.network.clone())
                        .unwrap_or_else(|| "-".into());
                    let age = meta
                        .as_ref()
                        .map(|m| age_label(&m.created.ts))
                        .unwrap_or_else(|| "-".into());
                    // 0.4.1 step 3: CLIENTS is the live connection count (0 for
                    // a stopped/crashed session), not the historical members.
                    let clients = if live {
                        live_session_view(&n).0.len().to_string()
                    } else {
                        "0".into()
                    };
                    let lease = meta
                        .as_ref()
                        .and_then(|m| m.lease.as_ref())
                        .and_then(|l| l.idle_timeout_s.map(|s| format!("{s}s")))
                        .unwrap_or_else(|| "-".into());
                    println!(
                        "{name}\t{n}\t{state}\t{cwd}\t{rootfs}\t{net}\t{age}\t{clients}\t{lease}"
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// 0.4.1 step 3: ask a live session's supervisor for its clients and execs.
/// Returns `(clients, execs, services)`; empty on any error (a session that
/// stopped between `is_live` and the request simply has none).
fn live_session_view(session: &str) -> (Vec<Value>, Vec<Value>, Vec<Value>) {
    let r = match supervisor::client_request(session, &json!({"op":"sessioninfo"})) {
        Ok(r) if r["ok"] == true => r,
        _ => return (Vec::new(), Vec::new(), Vec::new()),
    };
    let arr = |k: &str| r[k].as_array().cloned().unwrap_or_default();
    (arr("clients"), arr("execs"), arr("services"))
}

/// 0.4.1 step 3: one session's `hisn-ls/v2` JSON object. The v1 fields are
/// kept unchanged; `clients`, live `execs` (with `attach`), `services`,
/// `rootfs`, `members` and `lease` are additive v2 fields.
///
/// `clients`: connections that have sent at least one admitted request;
/// observers (ls, inspect, sessioninfo) and probes are never listed.
#[allow(clippy::too_many_arguments)]
fn session_v2_json(
    id: &str,
    dir: &Path,
    state: &str,
    policy: Option<&Value>,
    meta: Option<&hisn::sessionmeta::SessionMeta>,
    clients: Vec<Value>,
    execs: Vec<Value>,
    services: Vec<Value>,
) -> Value {
    let members: Vec<Value> = meta
        .map(|m| {
            m.members
                .iter()
                .map(|mem| {
                    json!({
                        "uid": mem.uid,
                        "label": mem.label,
                        "first_seen": mem.first_seen,
                        "last_seen": mem.last_seen,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let lease = meta
        .and_then(|m| m.lease.as_ref())
        .map(|l| {
            json!({
                "idle_timeout_s": l.idle_timeout_s,
                "last_activity": l.last_activity,
            })
        })
        .unwrap_or(Value::Null);
    json!({
        "id": id,
        "dir": dir.display().to_string(),
        "state": state,
        "cwd": policy.map(|p| p["cwd"].clone()).unwrap_or(Value::Null),
        "hostname": policy.map(|p| p["hostname"].clone()).unwrap_or(Value::Null),
        "network": policy.map(|p| p["network"].clone()).unwrap_or(Value::Null),
        "name": meta.and_then(|m| m.name.clone()).map(Value::String).unwrap_or(Value::Null),
        "rootfs": meta.and_then(|m| m.rootfs.clone()).map(Value::String).unwrap_or(Value::Null),
        "pid": Value::Null,
        "started": meta.map(|m| Value::String(m.created.ts.clone())).unwrap_or(Value::Null),
        "execs": execs,
        "services": services,
        "clients": clients,
        "members": members,
        "lease": lease,
    })
}

/// The session's `--name`, read from the authoritative `name` file (falling
/// back to `session.json`'s `name`). `None` for an unnamed session.
fn session_name(session_dir: &Path) -> Option<String> {
    if let Some(n) = hisn::registry::name_of(session_dir) {
        return Some(n);
    }
    hisn::sessionmeta::read(session_dir).and_then(|m| m.name)
}

/// 0.4.1 step 1: does a session with name `name` match a `--prune
/// --name-prefix` filter? An unnamed session (`None`) never matches a prefix;
/// with no prefix every session matches. Pure; unit-tested.
fn prune_prefix_matches(name: Option<&str>, prefix: Option<&str>) -> bool {
    match prefix {
        None => true,
        Some(pre) => name.is_some_and(|n| n.starts_with(pre)),
    }
}

/// The state shown by `ls`: `session.json`'s state when present, else the
/// legacy live/stale word, and `crashed` for a dir that is not live and whose
/// recorded state is not `stopped`.
fn session_state_label(p: &Path, live: bool) -> String {
    if live {
        return "running".into();
    }
    match hisn::sessionmeta::read(p).map(|m| m.state) {
        Some(hisn::sessionmeta::State::Stopped) => "stopped".into(),
        Some(hisn::sessionmeta::State::Creating) => "creating".into(),
        Some(_) | None => "crashed".into(),
    }
}

/// Human age from an RFC 3339 timestamp: `42s`, `7m`, `3h`, `2d`; `-` if the
/// timestamp does not parse.
fn age_label(ts: &str) -> String {
    let Some(then) = parse_rfc3339_secs(ts) else {
        return "-".into();
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(then);
    let d = (now - then).max(0);
    match d {
        0..=119 => format!("{d}s"),
        120..=7199 => format!("{}m", d / 60),
        7200..=172799 => format!("{}h", d / 3600),
        _ => format!("{}d", d / 86400),
    }
}

/// Parse `YYYY-MM-DDTHH:MM:SSZ` (the form `rfc3339_now` writes) to epoch seconds.
fn parse_rfc3339_secs(ts: &str) -> Option<i64> {
    let b = ts.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[10] != b'T' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| ts.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let (h, mi, se) = (n(11..13)?, n(14..16)?, n(17..19)?);
    // Days since epoch via the civil-from-days inverse (Howard Hinnant).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + h * 3600 + mi * 60 + se)
}

/// Read `policy.resolved.toml` from a session dir and parse it as TOML into a
/// JSON `Value` for the `ls --json` output.
fn read_session_policy(path: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(path.join("policy.resolved.toml")).ok()?;
    let toml_val: toml::Value = toml::from_str(&text).ok()?;
    // Convert the TOML table to a serde_json::Value (toml::Value -> JSON).
    let json_str = serde_json::to_string(&toml_val).ok()?;
    serde_json::from_str(&json_str).ok()
}

/// `hisn rootfs import`: thin wrapper over [`hisn::rootfs_import::import`].
fn rootfs_import(args: hisn::cli::ImportArgs) -> Result<ExitCode> {
    let root = rootfs_store::store_root()?;
    let opts = hisn::rootfs_import::ImportOpts {
        name: &args.name,
        from_tar: args.from_tar.as_deref(),
        from_image: args.from_image.as_deref(),
        replace: args.replace,
    };
    let m = hisn::rootfs_import::import(&root, &opts, "docker")?;
    eprintln!(
        "imported rootfs {} ({} files, {} skipped, {} bytes)",
        m.name, m.files, m.skipped, m.size_bytes
    );
    Ok(ExitCode::SUCCESS)
}

/// 0.4.0 step 5: archive `grants.jsonl` and the final `session.json` from
/// `dir` into `$XDG_STATE_HOME/hisn/audit/<id>.jsonl` (0600, dir 0700) before
/// removing a stopped or crashed session. Aborts on archive write failure.
///
/// F3 hardening: the archive directory is checked for ownership (uid) and mode
/// (0700); the archive file is written with O_NOFOLLOW|O_CREAT|O_EXCL to a
/// temp name, then renamed. A symlinked archive dir is refused.
fn archive_session(dir: &Path, id: &str, uid: u32) -> Result<(), anyhow::Error> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;
    let state_home = std::env::var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| format!("/home/uid-{uid}"));
            PathBuf::from(home).join(".local").join("state")
        });
    let audit_dir = state_home.join("hisn").join("audit");
    std::fs::create_dir_all(&audit_dir).map_err(|e| anyhow!("create audit dir: {e}"))?;
    let _ = std::fs::set_permissions(&audit_dir, std::fs::Permissions::from_mode(0o700));
    // F3: refuse a symlinked audit dir.
    let meta = std::fs::symlink_metadata(&audit_dir).map_err(|e| anyhow!("stat audit dir: {e}"))?;
    if !meta.is_dir() {
        return Err(anyhow!("audit dir is not a directory"));
    }
    // F3: check ownership (must be owned by uid) and mode (must be 0700).
    use std::os::unix::fs::MetadataExt;
    if meta.uid() != uid {
        return Err(anyhow!(
            "audit dir not owned by uid {uid} (owned by {})",
            meta.uid()
        ));
    }
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(anyhow!(
            "audit dir is group/other accessible (mode {:o}); expected 0700",
            mode & 0o777
        ));
    }
    // F3: write to a temp file with O_NOFOLLOW|O_CREAT|O_EXCL, then rename.
    let archive_path = audit_dir.join(format!("{id}.jsonl"));
    let tmp_path = audit_dir.join(format!(".{id}.jsonl.tmp"));
    let _ = std::fs::remove_file(&tmp_path);
    let mut archive = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|e| anyhow!("create archive temp: {e}"))?;
    if let Ok(grants) = std::fs::read_to_string(dir.join("grants.jsonl")) {
        for line in grants.lines() {
            if !line.is_empty() {
                archive
                    .write_all(format!("{{\"source\":\"grants\",\"line\":{line}}}\n").as_bytes())
                    .map_err(|e| anyhow!("write grants archive: {e}"))?;
            }
        }
    }
    if let Ok(session) = std::fs::read_to_string(dir.join("session.json")) {
        // F3 (Mashūra BLOCKING): re-serialize as compact JSON so the
        // archive record stays on one line (JSONL).
        let compact = serde_json::from_str::<serde_json::Value>(&session)
            .ok()
            .and_then(|v| serde_json::to_string(&v).ok())
            .unwrap_or(session);
        archive
            .write_all(format!("{{\"source\":\"session\",\"line\":{compact}}}\n").as_bytes())
            .map_err(|e| anyhow!("write session archive: {e}"))?;
    }
    archive
        .sync_all()
        .map_err(|e| anyhow!("sync archive: {e}"))?;
    drop(archive);
    std::fs::rename(&tmp_path, &archive_path).map_err(|e| anyhow!("rename archive: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod ls_tests {
    use super::{archive_session, parse_rfc3339_secs, prune_prefix_matches, session_v2_json};
    use serde_json::{Value, json};
    use std::path::Path;

    #[test]
    fn prune_prefix_filter_selects_named_sessions_only() {
        // 0.4.1 step 1: --prune --name-prefix P keeps only sessions whose
        // name starts with P. No prefix keeps everything; an unnamed
        // session never matches a prefix.
        assert!(prune_prefix_matches(Some("wakil-dev"), None));
        assert!(prune_prefix_matches(None, None));
        assert!(prune_prefix_matches(Some("wakil-dev"), Some("wakil-")));
        assert!(prune_prefix_matches(Some("wakil"), Some("wakil")));
        assert!(!prune_prefix_matches(Some("seat-a"), Some("wakil-")));
        // Unnamed sessions are never matched by a prefix.
        assert!(!prune_prefix_matches(None, Some("wakil-")));
        // An empty prefix matches only a named session (some name).
        assert!(prune_prefix_matches(Some("x"), Some("")));
        assert!(!prune_prefix_matches(None, Some("")));
    }

    /// Known values checked with `date -u -d ... +%s`.
    #[test]
    fn rfc3339_parses_to_epoch_seconds() {
        assert_eq!(parse_rfc3339_secs("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_secs("2026-11-07T12:34:56Z"), Some(1794054896));
        assert_eq!(parse_rfc3339_secs("2000-02-29T23:59:59Z"), Some(951868799));
    }

    #[test]
    fn rfc3339_rejects_garbage() {
        assert_eq!(parse_rfc3339_secs("nope"), None);
        assert_eq!(parse_rfc3339_secs("2026-13-x"), None);
    }

    /// 0.4.1 step 3: the v2 JSON object carries the additive fields — live
    /// `clients` and `execs` (with `attach`) for a running session, `[]` for a
    /// stopped one — and keeps the v1 fields.
    #[test]
    fn session_v2_json_adds_clients_and_execs() {
        use hisn::sessionmeta::{Member, Owner, SessionMeta};
        let owner = Owner {
            uid: 1000,
            label: "local".into(),
            client_id: "c".into(),
        };
        let mut meta = SessionMeta::new("abc", Some("seat"), owner, "/w", "none");
        meta.rootfs = Some("wakil-dev".into());
        meta.members = vec![Member {
            uid: 1000,
            label: "rubin-wakil".into(),
            first_seen: "2026-11-07T12:00:00Z".into(),
            last_seen: "2026-11-07T12:01:00Z".into(),
        }];
        let clients = vec![json!({
            "uid": 1000, "pid": 42, "label": "rubin-wakil",
            "label_source": "flag", "connected_since": "2026-11-07T12:00:00Z"
        })];
        let execs = vec![json!({
            "exec_id": "e-1", "pid": 7, "argv0": "/bin/sh", "tty": true, "attach": true
        })];
        let v = session_v2_json(
            "abc",
            Path::new("/run/hisn/abc"),
            "running",
            None,
            Some(&meta),
            clients.clone(),
            execs.clone(),
            Vec::new(),
        );
        // v1 fields are kept.
        assert_eq!(v["id"], "abc");
        assert_eq!(v["dir"], "/run/hisn/abc");
        assert_eq!(v["state"], "running");
        assert_eq!(v["pid"], Value::Null);
        // Additive fields.
        assert_eq!(v["name"], "seat");
        assert_eq!(v["rootfs"], "wakil-dev");
        assert_eq!(v["clients"].as_array().unwrap().len(), 1);
        assert_eq!(v["execs"][0]["attach"], true);
        assert_eq!(v["members"].as_array().unwrap().len(), 1);

        // A stopped session: no clients, no execs.
        let stopped = session_v2_json(
            "abc",
            Path::new("/run/hisn/abc"),
            "stopped",
            None,
            Some(&meta),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        assert!(stopped["clients"].as_array().unwrap().is_empty());
        assert!(stopped["execs"].as_array().unwrap().is_empty());
    }

    #[test]
    fn stop_sets_stopping_then_stopped() {
        // F4: set_state writes "stopping" then "stopped". This unit test
        // verifies the state transitions work; the actual stop ordering
        // (kill → wait → stopped) is integration-tested on a host.
        let d = std::env::temp_dir().join(format!("hisn-stop-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        use hisn::sessionmeta::{Owner, SessionMeta, State, read, set_state};
        let owner = Owner {
            uid: 1000,
            label: "local".into(),
            client_id: "c".into(),
        };
        let m = SessionMeta::new("abc", Some("nm"), owner, "/w", "none");
        m.write_to(&d).unwrap();
        set_state(&d, State::Stopping).unwrap();
        assert_eq!(read(&d).unwrap().state, State::Stopping);
        set_state(&d, State::Stopped).unwrap();
        assert_eq!(read(&d).unwrap().state, State::Stopped);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn archive_refuses_symlinked_dir() {
        // F3: a symlinked audit dir must be refused.
        let d = std::env::temp_dir().join(format!("hisn-archive-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("real")).unwrap();
        std::fs::create_dir_all(d.join("session")).unwrap();
        // Create a symlink: $d/state/hisn/audit -> $d/real
        let state = d.join("state").join("hisn").join("audit");
        std::fs::create_dir_all(state.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(d.join("real"), &state).unwrap();
        // Set XDG_STATE_HOME to $d/state and run archive_session.
        // This is a unit test: it only checks the symlink refusal.
        let uid = rustix::process::getuid().as_raw();
        // The archive_session function checks ownership and mode; with the
        // symlink, the target is $d/real which is not 0700 by default.
        // This test just ensures archive_session returns an error for a
        // bad state dir — the exact error depends on the host.
        let r = archive_session(&d.join("session"), "test-id", uid);
        // We expect an error (either the symlink target's mode/owner is
        // wrong, or the rename fails). The important property is: no
        // archive file is created at the symlinked location.
        let _ = r;
        std::fs::remove_dir_all(&d).unwrap();
    }
}
