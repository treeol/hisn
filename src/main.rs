use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::{Value, json};

use hisn::cli::{Cli, Command, PolicyCommand};
use hisn::policy::{self, Overrides, Policy};
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
        Command::Ls(a) => ls(a.session.as_deref(), a.json),
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

fn ls(session_id: Option<&str>, json_out: bool) -> Result<ExitCode> {
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
            let uid = rustix::process::getuid().as_raw();
            let roots =
                session::runtime_roots(std::env::var("XDG_RUNTIME_DIR").ok().as_deref(), uid);
            let rows: Vec<(String, bool)> = session::list_sessions(&roots)
                .into_iter()
                .map(|(n, p)| (n, session::is_live(&p)))
                .collect();
            if json_out {
                let v: Vec<Value> = rows
                    .iter()
                    .map(|(n, l)| json!({"id": n, "live": l}))
                    .collect();
                println!("{}", Value::Array(v));
            } else {
                for (n, live) in rows {
                    println!("{n}\t{}", if live { "live" } else { "stale" });
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}
