//! domain_status library: core URL scanning functionality
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

#![warn(missing_docs)]

mod adaptive_rate_limiter;
mod app;
pub mod config;
mod database;
mod dns;
mod domain;
mod error_handling;
pub mod export;
mod fetch;
mod fingerprint;
mod geoip;
pub mod initialization;
mod models;
mod parse;
mod run;
mod security;
mod status_server;
mod storage;
mod tls;
mod user_agent;
mod utils;
pub mod whois;

// Re-export public API
pub use config::{Config, FailOn, LogFormat, LogLevel};
pub use error_handling::{DatabaseError, FingerprintError};
pub use models::{KeyAlgorithm, TlsVersion};
pub use run::{run_scan, ScanReport};
pub use storage::{
    init_db_pool_with_path, query_run_history, run_migrations, RunSummary, UrlRecord,
};
// Re-export insert types for testing
pub use storage::insert::{insert_url_record, UrlRecordInsertParams};
// Re-export whois types for testing
pub use whois::{lookup_whois, WhoisResult};
