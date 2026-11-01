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
    /// Signal the sandbox of a session.
    Kill(KillArgs),
    /// Report host capabilities required by hisn.
    Check(CheckArgs),
    /// Policy utilities.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
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
    /// Initial grant, `PATH[:ro|rw]` (default ro). Repeatable.
    #[arg(long = "grant", value_name = "PATH[:ro|rw]")]
    pub grants: Vec<String>,
    /// Command and arguments.
    #[arg(last = true, required = true, value_name = "CMD")]
    pub command: Vec<String>,
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

/// Parse `PATH[:ro|rw]` (the mode suffix is optional; default ro).
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
            Cli::try_parse_from(["hisn", "run"]).is_err(),
            "command is required"
        );
        assert!(Cli::try_parse_from(["hisn", "run", "--network", "bridge", "--", "ls"]).is_err());
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
