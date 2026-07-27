mod commands;
mod render;

use std::process::ExitCode;

use clap::Parser;
use commands::Cli;

fn main() -> ExitCode {
    match commands::run(Cli::parse()) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("rsi-scan: {error}");
            ExitCode::FAILURE
        }
    }
}
