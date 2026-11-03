use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::{Value, json};

use hisn::cli::{Cli, Command, PolicyCommand, ProfileCommand};
use hisn::policy::{self, Overrides, Policy};
use hisn::profile;
use hisn::{execcli, mounts, session, supervisor};

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
            let dir = session::find_session(&roots, &a.session)?;
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
        Command::Ls(a) => ls(a.session.as_deref(), a.json, a.prune),
    }
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

fn ls(session_id: Option<&str>, json_out: bool, prune: bool) -> Result<ExitCode> {
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
            if prune {
                for (n, p) in &sessions {
                    // Check twice 300 ms apart to avoid racing a live session
                    // mid-shutdown.
                    if session::is_stale(p) {
                        std::thread::sleep(std::time::Duration::from_millis(300));
                        if session::is_stale(p) {
                            match session::remove_safe(p, uid) {
                                Ok(()) => eprintln!("{n} stale; removed"),
                                Err(e) => {
                                    tracing::warn!("prune {n}: removal refused: {e}");
                                    eprintln!("{n} stale; removal refused: {e}");
                                }
                            }
                        }
                    } else {
                        tracing::info!("prune: {n} not stale; skipped");
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
                        json!({
                            "id": n,
                            "state": if *live { "live" } else { "stale" },
                            "cwd": policy.as_ref().map(|p| p["cwd"].clone()).unwrap_or(Value::Null),
                            "hostname": policy.as_ref().map(|p| p["hostname"].clone()).unwrap_or(Value::Null),
                            "network": policy.as_ref().map(|p| p["network"].clone()).unwrap_or(Value::Null),
                            "pid": Value::Null,
                            "started": Value::Null,
                            "execs": [],
                            "services": [],
                        })
                    })
                    .collect();
                println!("{}", json!({"schema": "hisn-ls/v1", "sessions": sessions}));
            } else {
                for (n, _p, live) in rows {
                    println!("{n}\t{}", if live { "live" } else { "stale" });
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
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
