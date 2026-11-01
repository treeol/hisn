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
    Inspect(SessionArg),
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
    /// Initial grant, `PATH[:ro|rw]` (default ro). Repeatable.
    #[arg(long = "grant", value_name = "PATH[:ro|rw]")]
    pub grants: Vec<String>,
    /// Command and arguments.
    #[arg(last = true, required = true, value_name = "CMD")]
    pub command: Vec<String>,
}

#[derive(Debug, Args)]
pub struct SessionArg {
    #[arg(long)]
    pub session: String,
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
}

#[derive(Debug, Args)]
pub struct RevokeArgs {
    #[arg(long)]
    pub session: String,
    pub path: PathBuf,
}

#[derive(Debug, Args)]
pub struct LsArgs {
    #[arg(long)]
    pub session: Option<String>,
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
}
