//! Command-line interface definition (clap derive).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "hisn",
    version,
    about = "Rootless, daemonless sandbox for AI coding agents"
)]
pub struct Cli {
    /// Log to stderr (repeat for more detail).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run a command inside a new sandbox session.
    Run(RunArgs),
    /// Add a host path to a running session (supervisor-side mount).
    Grant(GrantArgs),
    /// Remove a previously granted path from a running session.
    Revoke(RevokeArgs),
    /// List sessions, or the grants of one session.
    Ls(LsArgs),
    /// Dump the mount table and resolved policy of a session.
    Inspect(InspectArgs),
    /// Run a command inside a running session (same namespaces and confinement).
    Exec(ExecArgs),
    /// Signal the sandbox of a session.
    Kill(KillArgs),
    /// Report host capabilities required by hisn.
    Check(CheckArgs),
    /// Policy utilities.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Profile utilities (hisn-profile/v1).
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Rootfs store management (0.3.2).
    Rootfs {
        #[command(subcommand)]
        command: RootfsCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum RootfsCommand {
    /// Import a rootfs from a tar archive or Docker image.
    Import(ImportArgs),
    /// List rootfs images in the store.
    List,
    /// Print the path of a named rootfs.
    Path { name: String },
    /// Remove a rootfs from the store.
    Rm { name: String },
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Rootfs store name (validated: [A-Za-z0-9._-]{1,64}).
    pub name: String,
    /// Import from a tar archive (file or - for stdin).
    #[arg(long)]
    pub from_tar: Option<PathBuf>,
    /// Import from a Docker image (execs docker create + export + rm).
    #[arg(long)]
    pub from_image: Option<String>,
    /// Overwrite an existing rootfs with the same name.
    #[arg(long)]
    pub replace: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum NetworkArg {
    None,
    Host,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Policy file (hisn-policy/v1 TOML). Built-in defaults if omitted.
    #[arg(long)]
    pub policy: Option<PathBuf>,
    /// Profile file or built-in name (hisn-profile/v1 envelope). Mutually
    /// exclusive with `--policy`.
    #[arg(long)]
    pub profile: Option<String>,
    /// Working directory (mounted rw at the identical path). Overrides the policy.
    #[arg(long)]
    pub cwd: Option<PathBuf>,
    /// Session id (default: random).
    #[arg(long)]
    pub session_id: Option<String>,
    /// Network mode override.
    #[arg(long, value_enum)]
    pub network: Option<NetworkArg>,
    /// Accept `network = "host"` even without Landlock abstract-socket scoping.
    #[arg(long)]
    pub allow_host_abstract_sockets: bool,
    /// Suppress risk label output on start.
    #[arg(long)]
    pub quiet_risk: bool,
    /// Persistent home directory (absolute path; ~ allowed). Overrides the
    /// profile's `[home] persist`.
    #[arg(long, value_name = "PATH")]
    pub home_persist: Option<String>,
    /// Rootfs directory (absolute path). Overrides the profile's `[rootfs] path`.
    #[arg(long, value_name = "DIR")]
    pub rootfs_path: Option<PathBuf>,
    /// Initial grant, `PATH[:ro|rw]` (default ro). Repeatable.
    #[arg(long = "grant", value_name = "PATH[:ro|rw]")]
    pub grants: Vec<String>,
    /// Start the session without a command: PID 1 only reaps, and the
    /// session lives until `hisn kill` / SIGTERM. Use `hisn exec` to run things in it.
    #[arg(long)]
    pub detach: bool,
    /// After the session is ready, write "ready\n" to this fd and close it.
    /// For programmatic readiness (Wakil); works with and without --detach.
    #[arg(long, value_name = "FD")]
    pub ready_fd: Option<i32>,
    /// Command and arguments (required unless `--detach`).
    #[arg(last = true, value_name = "CMD")]
    pub command: Vec<String>,
}

impl RunArgs {
    /// `--detach` and a command are mutually exclusive; one of them is required.
    /// `--profile` and `--policy` are mutually exclusive.
    pub fn check_command(&self) -> Result<(), String> {
        match (self.detach, self.command.is_empty()) {
            (true, false) => return Err(
                "--detach starts a session without a command; run commands in it with `hisn exec`"
                    .to_string(),
            ),
            (false, true) => return Err("a command is required (or use --detach)".to_string()),
            _ => {}
        }
        if self.profile.is_some() && self.policy.is_some() {
            return Err(
                "E_PROFILE_POLICY: --profile and --policy are mutually exclusive".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct ExecArgs {
    #[arg(long)]
    pub session: String,
    /// Working directory inside the sandbox (default: the session's cwd).
    #[arg(long)]
    pub cwd: Option<PathBuf>,
    /// `K=V`, repeatable. Only keys the policy lists in `env.pass` are accepted;
    /// anything else rejects the request.
    #[arg(long = "env", value_name = "K=V")]
    pub env: Vec<String>,
    /// Run on a pty (allocated here, never the caller's own terminal).
    #[arg(long, conflicts_with = "no_tty")]
    pub tty: bool,
    /// Non-interactive: no pty, stdin from /dev/null, stdout and stderr passed
    /// through as pipes even when the caller's descriptors are terminals.
    #[arg(long = "no-tty", conflicts_with = "tty")]
    pub no_tty: bool,
    /// Command and arguments.
    #[arg(last = true, required = true, value_name = "CMD")]
    pub command: Vec<String>,
}

/// Parse `K=V` (the value may contain `=`; the name must be non-empty).
pub fn parse_env_spec(spec: &str) -> Result<(String, String), String> {
    match spec.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_owned(), v.to_owned())),
        _ => Err(format!("expected K=V, got {spec:?}")),
    }
}

#[derive(Debug, Args)]
pub struct InspectArgs {
    #[arg(long)]
    pub session: String,
    /// Print the raw control-socket response (JSON) instead of text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct GrantArgs {
    #[arg(long)]
    pub session: String,
    /// Absolute host path.
    pub path: PathBuf,
    /// Grant read-write (default read-only).
    #[arg(long)]
    pub rw: bool,
    /// Also expose mounts below the directory.
    #[arg(long)]
    pub recursive: bool,
}

#[derive(Debug, Args)]
pub struct RevokeArgs {
    #[arg(long)]
    pub session: String,
    pub path: PathBuf,
    /// Kill every sandbox process except init after detaching (hard guarantee).
    #[arg(long)]
    pub hard: bool,
    /// Kill processes found holding the mount open (soft revoke only).
    #[arg(long)]
    pub kill_holders: bool,
}

#[derive(Debug, Args)]
pub struct LsArgs {
    #[arg(long)]
    pub session: Option<String>,
    /// Print JSON instead of text.
    #[arg(long)]
    pub json: bool,
    /// Remove stale session directories (no live supervisor).
    #[arg(long)]
    pub prune: bool,
}

#[derive(Debug, Args)]
pub struct KillArgs {
    #[arg(long)]
    pub session: String,
    #[arg(long, default_value = "TERM")]
    pub signal: String,
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Emit machine-readable JSON instead of the table.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Validate a policy file (default ./hisn.toml).
    Validate { file: Option<PathBuf> },
    /// Print the JSON Schema of hisn-policy/v1.
    Schema,
    /// Print the mount targets the policy will produce (JSON array); used by
    /// the leak tests to check `hisn inspect` against the plan.
    Plan { file: Option<PathBuf> },
}

/// `PATH[:ro|rw]` (the mode suffix is optional; default ro).
pub fn parse_grant_spec(spec: &str) -> Result<(String, crate::control::Mode), String> {
    use crate::control::Mode;
    let (path, mode) = match spec.rsplit_once(':') {
        Some((p, "ro")) => (p, Mode::Ro),
        Some((p, "rw")) => (p, Mode::Rw),
        _ => (spec, Mode::Ro),
    };
    if path.is_empty() {
        return Err(format!("empty path in grant {spec:?}"));
    }
    Ok((path.to_owned(), mode))
}

#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// List the profile search path and built-in profiles.
    List,
    /// Explain a profile's capabilities and risk labels (default: base).
    Explain { name: Option<String> },
    /// Validate a profile file (default: the built-in base).
    Validate { file: Option<PathBuf> },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::Mode;
    use clap::Parser;

    #[test]
    fn grant_specs() {
        assert_eq!(parse_grant_spec("/a").unwrap(), ("/a".into(), Mode::Ro));
        assert_eq!(parse_grant_spec("/a:ro").unwrap(), ("/a".into(), Mode::Ro));
        assert_eq!(parse_grant_spec("/a:rw").unwrap(), ("/a".into(), Mode::Rw));
        // a colon that is not a mode suffix belongs to the path
        assert_eq!(parse_grant_spec("/a:b").unwrap(), ("/a:b".into(), Mode::Ro));
        assert!(parse_grant_spec(":rw").is_err());
    }

    #[test]
    fn run_command_parses_like_the_brief() {
        let c = Cli::try_parse_from([
            "hisn",
            "run",
            "--policy",
            "p.toml",
            "--cwd",
            "/w",
            "--session-id",
            "s1",
            "--network",
            "host",
            "--grant",
            "/x:rw",
            "--grant",
            "/y",
            "--",
            "ls",
            "-la",
        ])
        .unwrap();
        let Command::Run(r) = c.command else {
            panic!("not run")
        };
        assert_eq!(r.command, ["ls", "-la"]);
        assert_eq!(r.grants, ["/x:rw", "/y"]);
        assert_eq!(r.network, Some(NetworkArg::Host));
        assert!(
            Cli::try_parse_from(["hisn", "run"]).is_ok_and(|c| match c.command {
                Command::Run(r) => r.check_command().is_err(),
                _ => false,
            }),
            "a command (or --detach) is required"
        );
        assert!(Cli::try_parse_from(["hisn", "run", "--network", "bridge", "--", "ls"]).is_err());
    }

    #[test]
    fn detach_and_command_are_mutually_exclusive() {
        let run = |argv: &[&str]| match Cli::try_parse_from(argv).unwrap().command {
            Command::Run(r) => r,
            _ => panic!("not run"),
        };
        assert!(run(&["hisn", "run", "--detach"]).check_command().is_ok());
        assert!(run(&["hisn", "run", "--", "ls"]).check_command().is_ok());
        assert!(
            run(&["hisn", "run", "--detach", "--", "ls"])
                .check_command()
                .is_err()
        );
        assert!(run(&["hisn", "run"]).check_command().is_err());
    }

    #[test]
    fn exec_command_parses() {
        let c = Cli::try_parse_from([
            "hisn",
            "exec",
            "--session",
            "s1",
            "--cwd",
            "/w",
            "--env",
            "A=1",
            "--env",
            "B=x=y",
            "--tty",
            "--",
            "sh",
            "-c",
            "true",
        ])
        .unwrap();
        let Command::Exec(e) = c.command else {
            panic!("not exec")
        };
        assert_eq!(e.session, "s1");
        assert_eq!(e.cwd.as_deref(), Some(std::path::Path::new("/w")));
        assert_eq!(e.env, ["A=1", "B=x=y"]);
        assert!(e.tty);
        assert_eq!(e.command, ["sh", "-c", "true"]);
        assert!(
            Cli::try_parse_from(["hisn", "exec", "--session", "s"]).is_err(),
            "command required"
        );
        assert!(
            Cli::try_parse_from(["hisn", "exec", "--", "ls"]).is_err(),
            "session required"
        );
    }

    #[test]
    fn env_specs() {
        assert_eq!(parse_env_spec("A=1").unwrap(), ("A".into(), "1".into()));
        assert_eq!(parse_env_spec("A=").unwrap(), ("A".into(), "".into()));
        assert_eq!(parse_env_spec("A=b=c").unwrap(), ("A".into(), "b=c".into()));
        assert!(parse_env_spec("=x").is_err());
        assert!(parse_env_spec("nothing").is_err());
    }

    #[test]
    fn other_commands_parse() {
        for argv in [
            &["hisn", "grant", "--session", "s", "/p", "--rw"][..],
            &["hisn", "revoke", "--session", "s", "/p", "--hard"],
            &["hisn", "ls"],
            &["hisn", "ls", "--session", "s"],
            &["hisn", "inspect", "--session", "s"],
            &["hisn", "kill", "--session", "s", "--signal", "KILL"],
            &["hisn", "check", "--json"],
            &["hisn", "policy", "validate"],
            &["hisn", "policy", "schema"],
        ] {
            assert!(Cli::try_parse_from(argv).is_ok(), "{argv:?}");
        }
    }
}
