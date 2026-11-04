use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::{Value, json};

use hisn::cli::{Cli, Command, PolicyCommand, ProfileCommand, RootfsCommand};
use hisn::policy::{self, Overrides, Policy};
use hisn::profile;
use hisn::{execcli, mounts, rootfs_store, session, supervisor};

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

/// `hisn rootfs import`: import a rootfs from a tar archive or Docker image.
fn rootfs_import(args: hisn::cli::ImportArgs) -> Result<ExitCode> {
    use std::io::Read;
    use std::process::Command;

    if !hisn::rootfs_store::is_valid_name(&args.name) {
        anyhow::bail!("invalid rootfs name {:?}", args.name);
    }
    let store_path = hisn::rootfs_store::resolve_name(&args.name)?;
    if store_path.exists() && !args.replace {
        anyhow::bail!(
            "rootfs {} already exists (use --replace to overwrite)",
            args.name
        );
    }
    if args.replace && store_path.exists() {
        hisn::rootfs_store::remove(&args.name)?;
    }
    // Staging directory.
    let staging = store_path.with_extension("staging");
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    std::fs::create_dir_all(&staging)?;
    // Get the tar input.
    let (tar_data, source_label) = match (&args.from_tar, &args.from_image) {
        (Some(path), None) if path == &PathBuf::from("-") => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            (buf, "stdin".to_string())
        }
        (Some(path), None) => {
            let buf =
                std::fs::read(path).with_context(|| format!("reading tar {}", path.display()))?;
            (buf, format!("file:{}", path.display()))
        }
        (None, Some(image)) => {
            // docker create + export + rm.
            if !Command::new("docker").arg("--version").output().is_ok() {
                anyhow::bail!("docker CLI not found (required for --from-image)");
            }
            let create_out = Command::new("docker")
                .args(["create", "--name", &format!("hisn-rootfs-{}", args.name)])
                .arg(image)
                .output()
                .context("docker create")?;
            if !create_out.status.success() {
                anyhow::bail!(
                    "docker create failed: {}",
                    String::from_utf8_lossy(&create_out.stderr)
                );
            }
            let export_out = Command::new("docker")
                .args(["export", &format!("hisn-rootfs-{}", args.name)])
                .output()
                .context("docker export")?;
            // Always rm the container.
            let _ = Command::new("docker")
                .args(["rm", &format!("hisn-rootfs-{}", args.name)])
                .output();
            if !export_out.status.success() {
                anyhow::bail!(
                    "docker export failed: {}",
                    String::from_utf8_lossy(&export_out.stderr)
                );
            }
            (export_out.stdout, format!("docker:{}", image))
        }
        _ => {
            anyhow::bail!("--from-tar or --from-image is required");
        }
    };
    // Compute sha256 of the tar.
    let sha = {
        let mut child = Command::new("sha256sum")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()?;
        {
            use std::io::Write;
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(&tar_data)?;
        }
        let out = child.wait_with_output()?;
        let line = String::from_utf8_lossy(&out.stdout);
        line.split_whitespace()
            .next()
            .unwrap_or("unknown")
            .to_string()
    };
    // Extract the tar into the staging directory.
    let (files, skipped, size_bytes) = extract_tar(&staging, &tar_data)?;
    // Write the manifest.
    let manifest = hisn::rootfs_store::Manifest {
        name: args.name.clone(),
        source: source_label,
        source_digest: None,
        import_timestamp: hisn::session::rfc3339_now(),
        hisn_version: env!("CARGO_PKG_VERSION").to_string(),
        sha256: Some(sha),
        files,
        skipped,
        size_bytes,
    };
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    std::fs::write(staging.join("manifest.json"), manifest_json)?;
    // Atomic rename to the final name.
    std::fs::rename(&staging, &store_path)?;
    eprintln!(
        "imported rootfs {} ({} files, {} skipped, {} bytes)",
        args.name, files, skipped, size_bytes
    );
    Ok(ExitCode::SUCCESS)
}

/// Extract a tar archive into `dest` with hardening (0.3.2).
/// Returns (files, skipped, size_bytes).
fn extract_tar(dest: &Path, tar_data: &[u8]) -> Result<(u64, u64, u64)> {
    use std::io::{Cursor, Read};
    use std::os::unix::fs::PermissionsExt;

    // Parse the tar manually for hardening.
    let mut cursor = Cursor::new(tar_data);
    let mut files: u64 = 0;
    let mut skipped: u64 = 0;
    let mut size_bytes: u64 = 0;
    let mut buf = [0u8; 512];
    loop {
        // Read a 512-byte header.
        let n = cursor.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if n < 512 {
            anyhow::bail!("truncated tar header (read {} of 512 bytes)", n);
        }
        // Check for end-of-archive (two zero blocks).
        if buf.iter().all(|&b| b == 0) {
            // Check the next block too.
            let mut next = [0u8; 512];
            let n2 = cursor.read(&mut next)?;
            if n2 == 0 || next.iter().all(|&b| b == 0) {
                break;
            }
            // Not a double-zero; continue with the next block as the header.
            buf = next;
        }
        // Parse the header.
        let name = parse_tar_string(&buf[0..100]);
        if name.is_empty() {
            // Skip empty name entries.
            continue;
        }
        let mode = parse_tar_octal(&buf[100..108]);
        let size = parse_tar_octal(&buf[124..136]);
        let typeflag = buf[156];
        // Resolve the path: reject absolute, .., etc.
        let rel = normalize_tar_path(&name);
        if rel.is_empty() {
            skipped += 1;
            // Skip the data blocks.
            let data_blocks = size.div_ceil(512);
            cursor.set_position(cursor.position() + data_blocks * 512);
            continue;
        }
        let target = dest.join(&rel);
        // Reject if the path escapes the dest directory.
        if !target.starts_with(dest) {
            skipped += 1;
            let data_blocks = size.div_ceil(512);
            cursor.set_position(cursor.position() + data_blocks * 512);
            continue;
        }
        // Read the data.
        let mut data = vec![0u8; size as usize];
        cursor.read_exact(&mut data)?;
        // Skip padding.
        let pad = (512 - (size % 512)) % 512;
        if pad > 0 {
            let mut pad_buf = vec![0u8; pad as usize];
            cursor.read_exact(&mut pad_buf)?;
        }
        match typeflag {
            b'0' | 0 => {
                // Regular file. Strip setuid/setgid bits.
                let mode = mode & !0o6000;
                // Create parent directories.
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&target, &data)?;
                std::fs::set_permissions(
                    &target,
                    std::fs::Permissions::from_mode((mode & 0o777) as u32),
                )?;
                files += 1;
                size_bytes += size;
            }
            b'5' => {
                // Directory.
                let mode = mode & !0o6000;
                std::fs::create_dir_all(&target)?;
                std::fs::set_permissions(
                    &target,
                    std::fs::Permissions::from_mode((mode & 0o777) as u32),
                )?;
                files += 1;
            }
            b'2' => {
                // Symlink. Store as-is.
                let link_target = parse_tar_string(&buf[157..257]);
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::os::unix::fs::symlink(&link_target, &target)?;
                files += 1;
            }
            b'1' => {
                // Hard link. Reject if the target is outside dest.
                let link_target = parse_tar_string(&buf[157..257]);
                let lt = dest.join(normalize_tar_path(&link_target));
                if !lt.starts_with(dest) {
                    skipped += 1;
                    continue;
                }
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                // Create a hard link. This may fail if the target doesn't exist yet.
                let _ = std::fs::hard_link(&lt, &target);
                files += 1;
            }
            b'3' | b'4' | b'6' => {
                // Device nodes or fifo: skip and count.
                skipped += 1;
            }
            _ => {
                // Unknown type: skip and count.
                skipped += 1;
            }
        }
    }
    Ok((files, skipped, size_bytes))
}

/// Parse a null-terminated string from a tar header field.
fn parse_tar_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Parse an octal number from a tar header field (null-terminated, space-padded).
fn parse_tar_octal(buf: &[u8]) -> u64 {
    let s = parse_tar_string(buf);
    u64::from_str_radix(s.trim(), 8).unwrap_or(0)
}

/// Normalize a tar member path: strip leading '/', reject '..'.
fn normalize_tar_path(name: &str) -> String {
    let mut out = String::new();
    let stripped = name.strip_prefix('/').unwrap_or(name);
    for part in stripped.split('/') {
        if part == ".." {
            return String::new(); // signal rejection
        }
        if part == "." || part.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(part);
    }
    out
}
