use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use hisn::cli::{Cli, Command, PolicyCommand};
use hisn::policy::{self, Overrides, Policy};

/// Exit code for hisn-internal errors (policy, host); distinct from a
/// command's own exit status.
const EXIT_INTERNAL: u8 = 125;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Check(args) => {
            let report = hisn::check::run_checks();
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("report serializes")
                );
            } else {
                print!("{}", report.render());
            }
            if report.ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Command::Policy { command } => match command {
            PolicyCommand::Schema => {
                println!("{}", policy::schema_json());
                ExitCode::SUCCESS
            }
            PolicyCommand::Validate { file } => validate(file),
        },
        other => {
            eprintln!("hisn: {other:?} is not implemented yet");
            ExitCode::from(70)
        }
    }
}

/// Syntax + filesystem validation of a policy file. Prints the resolved
/// policy to stdout on success.
fn validate(file: Option<PathBuf>) -> ExitCode {
    let file = file.unwrap_or_else(|| PathBuf::from("hisn.toml"));
    let result = (|| -> Result<String, Box<dyn std::error::Error>> {
        let pol = Policy::load(&file)?;
        let base = file
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let resolved = pol.resolve(base, &Overrides::default(), &[])?;
        Ok(resolved.to_toml())
    })();
    match result {
        Ok(toml) => {
            print!("{toml}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("hisn: {}: {e}", file.display());
            ExitCode::from(EXIT_INTERNAL)
        }
    }
}
