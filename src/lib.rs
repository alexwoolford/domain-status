//! `domain_status` library: core URL scanning functionality
//!
//! This library provides high-level APIs for scanning URLs and capturing comprehensive
//! metadata including HTTP status, TLS certificates, DNS information, technology
//! fingerprints, and more.
//!
//! # Example
//!
//! ```no_run
//! use domain_status::{Config, run_scan};
//! use tokio;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config {
//!     file: std::path::PathBuf::from("urls.txt"),
//!     max_concurrency: 50,
//!     rate_limit_rps: 20,
//!     ..Default::default()
//! };
//!
//! let report = run_scan(config).await?;
//! println!("Processed {} URLs: {} succeeded, {} failed",
//!          report.total_urls, report.successful, report.failed);
//! # Ok(())
//! # }
//! ```
//!
//! # Requirements
//!
//! This library requires a Tokio runtime. Use `#[tokio::main]` in your application
//! or ensure you're calling library functions within an async context.
//!
//! # Stability and API guarantees
//!
//! - **Stable:** Exit codes (see project docs), [`Config`] validation rules, and public function signatures and types follow `SemVer`.
//! - **May change:** Exact wording of error messages, the internal error chain and downcasting behavior, and default config values (e.g. timeouts, limits) may change in patch or minor releases to improve safety or diagnostics.

#![deny(
    clippy::enum_glob_use,
    missing_debug_implementations,
    missing_docs,
    unsafe_code
)]

mod adaptive_rate_limiter;
mod app;
pub mod cli;
mod clock;
pub mod config;
mod database;
mod dns;
mod domain;
mod error_handling;
pub mod exit_codes;
pub mod export;
mod fetch;
mod fingerprint;
mod geoip;
pub mod initialization;
mod models;
mod parse;
mod per_domain_limiter;
mod run;
mod runtime_metrics;
mod security;
mod status_server;
mod storage;
mod tls;
mod user_agent;
mod utils;
pub mod whois;

// Re-export public API
pub use cli::evaluate_exit_code;
pub use config::{Config, FailOn, LogFormat, LogLevel, ScanDependencyOverrides};
pub use error_handling::{DatabaseError, FingerprintError, ReqwestErrorExt};
pub use exit_codes::{EXIT_NO_URLS_PCT, EXIT_POLICY_FAILURE, EXIT_RUNTIME_ERROR, EXIT_SUCCESS};
pub use geoip::GeoIpService;
pub use models::{KeyAlgorithm, TlsVersion};
pub use run::{run_scan, ScanReport};
pub use storage::{
    init_db_pool_with_path, query_run_history, run_migrations, RunSummary, UrlRecord,
};
// Re-export insert types for testing
pub use storage::insert::{insert_url_record, UrlRecordInsertParams};
// Re-export whois types for testing
pub use whois::{lookup_whois, WhoisResult};
