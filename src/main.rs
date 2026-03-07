//! Main application entry point (CLI binary).
//!
//! All CLI parsing and command execution lives in the library so it can be tested
//! without mirroring the binary-only clap types.

use anyhow::Result;
use std::process;

#[tokio::main]
async fn main() -> Result<()> {
    let exit_code = match domain_status::cli::run_cli_from_args(std::env::args_os()).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("domain_status error: {:#}", e);
            1
        }
    };
    process::exit(exit_code);
}
