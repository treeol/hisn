use std::io::Read;
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
///
/// Streams the tar into the staging directory — never buffers the archive.
/// `--from-tar -` reads from stdin; `--from-image` pipes `docker export`
/// stdout straight into the extractor. SHA-256 is computed in-process via a
/// `HasherReader` wrapper that hashes as it reads.
fn rootfs_import(args: hisn::cli::ImportArgs) -> Result<ExitCode> {
    use sha2::Digest;
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

    // Build the streaming reader + source label. The reader is consumed by
    // extract_tar_streaming; the SHA-256 is computed by a HasherReader
    // wrapper that tees the bytes into sha2 as they pass through.
    let (source_label, sha, files, skipped, size_bytes) = match (&args.from_tar, &args.from_image) {
        (Some(path), None) if path == &PathBuf::from("-") => {
            let mut hasher = sha2::Sha256::new();
            let (f, s, sb) = {
                let mut hr = HasherReader::new(std::io::stdin(), &mut hasher);
                extract_tar_streaming(&staging, &mut hr)?
            };
            (
                "stdin".to_string(),
                format!("{:x}", hasher.finalize()),
                f,
                s,
                sb,
            )
        }
        (Some(path), None) => {
            let file = std::fs::File::open(path)
                .with_context(|| format!("reading tar {}", path.display()))?;
            let mut hasher = sha2::Sha256::new();
            let (f, s, sb) = {
                let mut hr = HasherReader::new(file, &mut hasher);
                extract_tar_streaming(&staging, &mut hr)?
            };
            (
                format!("file:{}", path.display()),
                format!("{:x}", hasher.finalize()),
                f,
                s,
                sb,
            )
        }
        (None, Some(image)) => {
            if !Command::new("docker").arg("--version").output().is_ok() {
                anyhow::bail!("docker CLI not found (required for --from-image)");
            }
            let container_name = format!("hisn-rootfs-{}", args.name);
            let create_out = Command::new("docker")
                .args(["create", "--name", &container_name])
                .arg(image)
                .output()
                .context("docker create")?;
            if !create_out.status.success() {
                anyhow::bail!(
                    "docker create failed: {}",
                    String::from_utf8_lossy(&create_out.stderr)
                );
            }
            // docker export with piped stdout — stream straight into the
            // extractor, no temp file, no Vec<u8>.
            let mut export_child = Command::new("docker")
                .args(["export", &container_name])
                .stdout(std::process::Stdio::piped())
                .spawn()
                .context("docker export")?;
            let export_stdout = export_child
                .stdout
                .take()
                .ok_or_else(|| anyhow::anyhow!("docker export: no stdout"))?;
            let mut hasher = sha2::Sha256::new();
            let (f, s, sb) = {
                let mut hr = HasherReader::new(export_stdout, &mut hasher);
                extract_tar_streaming(&staging, &mut hr)?
            };
            let sha = format!("{:x}", hasher.finalize());
            // Wait for docker export to finish, then always rm the container.
            let _ = export_child.wait();
            let _ = Command::new("docker")
                .args(["rm", &container_name])
                .output();
            (format!("docker:{image}"), sha, f, s, sb)
        }
        _ => {
            anyhow::bail!("--from-tar or --from-image is required");
        }
    };
    finish_import(
        staging,
        store_path,
        args.name,
        source_label,
        sha,
        files,
        skipped,
        size_bytes,
    )?;
    Ok(ExitCode::SUCCESS)
}

/// Write the manifest and atomically rename staging → store_path.
#[allow(clippy::too_many_arguments)]
fn finish_import(
    staging: PathBuf,
    store_path: PathBuf,
    name: String,
    source: String,
    sha: String,
    files: u64,
    skipped: u64,
    size_bytes: u64,
) -> Result<()> {
    let manifest = hisn::rootfs_store::Manifest {
        name: name.clone(),
        source,
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
    std::fs::rename(&staging, &store_path)?;
    eprintln!(
        "imported rootfs {} ({} files, {} skipped, {} bytes)",
        name, files, skipped, size_bytes
    );
    Ok(())
}

/// Reader wrapper that feeds bytes into a SHA-256 hasher as they are read.
struct HasherReader<'h, R> {
    inner: R,
    hasher: &'h mut sha2::Sha256,
}

impl<'h, R: Read> HasherReader<'h, R> {
    fn new(inner: R, hasher: &'h mut sha2::Sha256) -> Self {
        Self { inner, hasher }
    }
}

impl<R: Read> Read for HasherReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            use sha2::Digest;
            self.hasher.update(&buf[..n]);
        }
        Ok(n)
    }
}

/// Extract a tar archive from a `Read` stream into `dest` with hardening
/// (0.3.2). Uses the `tar` crate for streaming entry iteration — the archive
/// is never buffered in memory. Returns (files, skipped, size_bytes).
fn extract_tar_streaming<R: Read>(dest: &Path, reader: &mut R) -> Result<(u64, u64, u64)> {
    use std::os::unix::fs::PermissionsExt;

    let mut archive = tar::Archive::new(reader);
    let mut files: u64 = 0;
    let mut skipped: u64 = 0;
    let mut size_bytes: u64 = 0;
    // Track extracted symlinks to detect traversal through them (S1 fix).
    let mut extracted_symlinks: std::collections::HashSet<PathBuf> =
        std::collections::HashSet::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let header = entry.header();
        let entry_path = header.path()?.to_path_buf();
        // Normalize: strip leading '/', reject "..".
        let rel = match normalize_entry_path(&entry_path) {
            Some(p) => p,
            None => {
                skipped += 1;
                continue;
            }
        };
        let target = dest.join(&rel);
        // Reject if the path escapes the dest directory.
        if !target.starts_with(dest) {
            skipped += 1;
            continue;
        }
        // S1 fix: reject if any ancestor of the target (below dest) is a
        // symlink extracted earlier.
        if path_traverses_symlink(dest, &target, &extracted_symlinks) {
            skipped += 1;
            continue;
        }
        let entry_type = header.entry_type();
        let mode = header.mode().unwrap_or(0);
        match entry_type {
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                // Strip setuid/setgid bits.
                let mode = mode & !0o6000;
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                // Verify the target is not already a symlink (defense in depth).
                let meta = std::fs::symlink_metadata(&target);
                if let Ok(m) = &meta
                    && m.file_type().is_symlink()
                {
                    skipped += 1;
                    continue;
                }
                let size = entry.size();
                let mut file = std::fs::File::create(&target)?;
                std::io::copy(&mut entry, &mut file)?;
                drop(file);
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode & 0o777))?;
                files += 1;
                size_bytes += size;
            }
            tar::EntryType::Directory => {
                let mode = mode & !0o6000;
                std::fs::create_dir_all(&target)?;
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode & 0o777))?;
                files += 1;
            }
            tar::EntryType::Symlink => {
                let link_target = header
                    .link_name()?
                    .ok_or_else(|| anyhow::anyhow!("symlink entry has no link name"))?
                    .into_owned();
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::os::unix::fs::symlink(&link_target, &target)?;
                extracted_symlinks.insert(target.clone());
                files += 1;
            }
            // Hardlink: byte '1'. The tar crate may not export a named
            // constant for this, so match on the byte value.
            t if t == tar::EntryType::hard_link() => {
                // Reject if the link target resolves outside dest or
                // passes through an extracted symlink.
                let link_name = header
                    .link_name()?
                    .ok_or_else(|| anyhow::anyhow!("hardlink entry has no link name"))?
                    .into_owned();
                let lt_rel = match normalize_entry_path(&link_name) {
                    Some(p) => p,
                    None => {
                        skipped += 1;
                        continue;
                    }
                };
                let lt = dest.join(&lt_rel);
                if !lt.starts_with(dest) {
                    skipped += 1;
                    continue;
                }
                if path_traverses_symlink(dest, &lt, &extracted_symlinks) {
                    skipped += 1;
                    continue;
                }
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let _ = std::fs::hard_link(&lt, &target);
                files += 1;
            }
            // Device nodes, fifos, and unknown types: skip and count.
            _ => {
                skipped += 1;
            }
        }
    }
    Ok((files, skipped, size_bytes))
}

/// Normalize a tar entry path: strip leading '/', reject "..".
/// Returns None if the path should be skipped (contains "..").
fn normalize_entry_path(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                // Strip leading '/' — make relative.
            }
            std::path::Component::ParentDir => {
                return None;
            }
            std::path::Component::CurDir => {}
            std::path::Component::Normal(s) => {
                out.push(s);
            }
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Check if `path` (inside `base`) traverses through any of the extracted
/// symlinks. Returns true if any ancestor of `path` (below `base`) is in
/// the symlink set.
fn path_traverses_symlink(
    base: &Path,
    path: &Path,
    symlinks: &std::collections::HashSet<PathBuf>,
) -> bool {
    let rel = match path.strip_prefix(base) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let mut current = base.to_path_buf();
    for component in rel.components() {
        current.push(component);
        if symlinks.contains(&current) {
            return true;
        }
    }
    false
}
