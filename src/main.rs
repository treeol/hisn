use std::process::ExitCode;

use clap::Parser;
use hisn::cli::{Cli, Command};

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
        other => {
            eprintln!("hisn: {other:?} is not implemented yet");
            ExitCode::from(70)
        }
    }
}
