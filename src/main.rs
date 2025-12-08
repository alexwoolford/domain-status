//! Main application entry point (CLI binary).
//!
//! This is a thin wrapper around the `domain_status` library that handles:
//! - Command-line argument parsing
//! - Environment variable loading (.env file)
//! - Logger initialization
//! - User-facing output formatting
//!
//! All core functionality is implemented in the library crate.

use anyhow::{Context, Result};
use clap::Parser;
use std::process;

use domain_status::initialization::{init_crypto_provider, init_logger_with};
use domain_status::{run_scan, Config};

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from .env file (if it exists)
    // This allows setting MAXMIND_LICENSE_KEY in .env without exporting it manually
    // Try loading from current directory first, then from the executable's directory
    if dotenvy::dotenv().is_err() {
        // If .env not found in current dir, try next to the executable
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let env_path = exe_dir.join(".env");
                if env_path.exists() {
                    let _ = dotenvy::from_path(&env_path);
                }
            }
        }
    }

    // Parse command-line arguments into Config
    let config = Config::parse();

    // Initialize logger based on config
    let log_level = config.log_level.clone();
    let log_format = config.log_format.clone();
    init_logger_with(log_level.into(), log_format).context("Failed to initialize logger")?;

    // Initialize crypto provider for TLS operations
    init_crypto_provider();

    // Run the scan using the library
    match run_scan(config).await {
        Ok(report) => {
            // Print user-friendly summary
            println!(
                "✅ Processed {} URL{} ({} succeeded, {} failed) in {:.1}s - see database for details",
                report.total_urls,
                if report.total_urls == 1 { "" } else { "s" },
                report.successful,
                report.failed,
                report.elapsed_seconds
            );
            println!("Results saved in {}", report.db_path.display());
            Ok(())
        }
        Err(e) => {
            eprintln!("domain_status error: {:#}", e);
            process::exit(1);
        }
    }
}
