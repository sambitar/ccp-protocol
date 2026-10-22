//! Print the conformance summary for one vector directory.
//!
//! Usage: cargo run --bin conformance -- <vectors-dir>

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(directory) = std::env::args().nth(1).map(PathBuf::from) else {
        eprintln!("usage: conformance <vectors-dir>");
        return ExitCode::from(2);
    };
    match ccp_runtime::vectors::run_directory(&directory) {
        Ok(summary) => {
            match ccp_kernel::serialize(&summary) {
                Ok(text) => println!("{text}"),
                Err(error) => {
                    eprintln!("serialize summary: {error}");
                    return ExitCode::FAILURE;
                }
            }
            if ccp_runtime::vectors::total_failed(&summary) == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
