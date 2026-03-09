//! Main application entry point (CLI binary).
//!
//! All CLI parsing and command execution lives in the library so it can be tested
//! without mirroring the binary-only clap types.

#![deny(clippy::enum_glob_use, unsafe_code)]

use anyhow::Result;
use std::process;

#[tokio::main]
async fn main() -> Result<()> {
    let exit_code = match domain_status::cli::run_cli_from_args(std::env::args_os()).await {
        Ok(code) => code,
        Err(e) => {
            use domain_status::ErrorExt;
            eprintln!("domain_status: {}", e.display_chain());
            domain_status::log_error_chain(&e);
            domain_status::print_io_error_hint_if_applicable(&e);
            domain_status::exit_codes::EXIT_RUNTIME_ERROR
        }
    };
    process::exit(exit_code);
}
