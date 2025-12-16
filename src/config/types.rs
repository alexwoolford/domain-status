//! Configuration types and CLI options.
//!
//! This module defines enums and structs used for command-line argument parsing
//! and configuration.

use std::path::PathBuf;

use clap::ValueEnum;

use crate::config::constants::DEFAULT_USER_AGENT;

/// Exit code policy for handling failures.
///
/// Controls when the CLI should exit with a non-zero code based on scan results.
#[derive(Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum FailOn {
    /// Never exit with error code (always return 0)
    ///
    /// Useful for monitoring scenarios where you want to log failures but not
    /// trigger alerts. The scan may have failures, but the command succeeds.
    Never,

    /// Exit with error if any URL failed
    ///
    /// Strict mode: any failure causes exit code 2. Useful for CI pipelines
    /// where any failure should be treated as a build failure.
    AnyFailure,

    /// Exit with error if failure percentage exceeds threshold
    ///
    /// Format: `pct>X` where X is a number between 0 and 100.
    /// Example: `pct>10` means exit with error if more than 10% of URLs failed.
    /// Useful for large scans where some failures are expected but excessive
    /// failures indicate a problem.
    #[value(name = "pct>")]
    PctGreaterThan,

    /// Exit with error only on critical errors (timeouts, DNS failures, etc.)
    ///
    /// Warnings and non-critical failures (like 404s) don't trigger exit codes.
    /// This is a future enhancement - currently behaves like `AnyFailure`.
    ErrorsOnly,
}

/// Logging level for the application.
///
/// Controls the verbosity of log output, from most restrictive (Error) to most
/// verbose (Trace).
#[derive(Clone, Debug, ValueEnum)]
pub enum LogLevel {
    /// Only error messages
    Error,
    /// Error and warning messages
    Warn,
    /// Error, warning, and informational messages
    Info,
    /// All messages except trace
    Debug,
    /// All messages including trace
    Trace,
}

impl From<LogLevel> for log::LevelFilter {
    fn from(l: LogLevel) -> Self {
        match l {
            LogLevel::Error => log::LevelFilter::Error,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Debug => log::LevelFilter::Debug,
            LogLevel::Trace => log::LevelFilter::Trace,
        }
    }
}

/// Log output format.
///
/// Controls how log messages are formatted:
/// - `Plain`: Human-readable format with colors (default)
/// - `Json`: Structured JSON format for machine parsing
#[derive(Clone, Debug, ValueEnum)]
pub enum LogFormat {
    /// Human-readable format with colors (default)
    Plain,
    /// Structured JSON format for machine parsing
    Json,
}

/// Library configuration (no CLI dependencies).
///
/// This is the core configuration struct used by the library. It can be
/// constructed programmatically without any CLI dependencies.
///
/// # Examples
///
/// ```no_run
/// use domain_status::Config;
/// use std::path::PathBuf;
///
/// let config = Config {
///     file: PathBuf::from("urls.txt"),
///     max_concurrency: 50,
///     rate_limit_rps: 20,
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone)]
pub struct Config {
    /// File to read URLs from
    pub file: PathBuf,

    /// Log level
    pub log_level: LogLevel,

    /// Log format
    pub log_format: LogFormat,

    /// Database path (SQLite file)
    pub db_path: PathBuf,

    /// Maximum concurrent requests
    pub max_concurrency: usize,

    /// Per-request timeout in seconds
    pub timeout_seconds: u64,

    /// HTTP User-Agent header value
    pub user_agent: String,

    /// Initial requests per second (adaptive rate limiting always enabled)
    pub rate_limit_rps: u32,

    /// Error rate threshold for adaptive rate limiting (0.0-1.0, default: 0.2 = 20%)
    pub adaptive_error_threshold: f64,

    /// Fingerprints source URL or local path
    pub fingerprints: Option<String>,

    /// GeoIP database path or download URL
    pub geoip: Option<String>,

    /// HTTP status server port (optional, disabled by default)
    pub status_port: Option<u16>,

    /// Enable WHOIS/RDAP lookup for domain registration information
    pub enable_whois: bool,

    /// Show detailed timing metrics at the end of the run
    pub show_timing: bool,

    /// Exit code policy for handling failures
    pub fail_on: FailOn,

    /// Failure percentage threshold (used with `fail_on: FailOn::PctGreaterThan`)
    ///
    /// A number between 0 and 100. If failure percentage exceeds this value,
    /// exit with code 2. Only used when `fail_on` is `PctGreaterThan`.
    pub fail_on_pct_threshold: u8,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            file: PathBuf::from("urls.txt"),
            log_level: LogLevel::Info,
            log_format: LogFormat::Plain,
            db_path: PathBuf::from("./domain_status.db"),
            max_concurrency: 30,
            timeout_seconds: 10,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            rate_limit_rps: 15,
            adaptive_error_threshold: 0.2,
            fingerprints: None,
            geoip: None,
            status_port: None,
            enable_whois: false,
            show_timing: false,
            fail_on: FailOn::Never,
            fail_on_pct_threshold: 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_conversion() {
        // Test all LogLevel variants convert correctly to log::LevelFilter
        assert_eq!(
            log::LevelFilter::from(LogLevel::Error),
            log::LevelFilter::Error
        );
        assert_eq!(
            log::LevelFilter::from(LogLevel::Warn),
            log::LevelFilter::Warn
        );
        assert_eq!(
            log::LevelFilter::from(LogLevel::Info),
            log::LevelFilter::Info
        );
        assert_eq!(
            log::LevelFilter::from(LogLevel::Debug),
            log::LevelFilter::Debug
        );
        assert_eq!(
            log::LevelFilter::from(LogLevel::Trace),
            log::LevelFilter::Trace
        );
    }

    #[test]
    fn test_log_level_ordering() {
        // Verify that log levels are ordered correctly (Error < Warn < Info < Debug < Trace)
        let error = log::LevelFilter::from(LogLevel::Error);
        let warn = log::LevelFilter::from(LogLevel::Warn);
        let info = log::LevelFilter::from(LogLevel::Info);
        let debug = log::LevelFilter::from(LogLevel::Debug);
        let trace = log::LevelFilter::from(LogLevel::Trace);

        // Each level should be more restrictive than the next
        assert!(error < warn);
        assert!(warn < info);
        assert!(info < debug);
        assert!(debug < trace);
    }

    #[test]
    fn test_config_default_values() {
        // Test that Config::default() provides sensible defaults
        // This is critical - incorrect defaults could break production usage
        let config = Config::default();

        // Verify critical defaults
        assert_eq!(config.max_concurrency, 30);
        assert_eq!(config.timeout_seconds, 10);
        assert_eq!(config.rate_limit_rps, 15);
        assert!((config.adaptive_error_threshold - 0.2).abs() < f64::EPSILON);
        assert_eq!(config.fail_on, FailOn::Never);
        assert_eq!(config.fail_on_pct_threshold, 10);
        assert!(!config.enable_whois);
        assert!(!config.show_timing);
        assert!(config.fingerprints.is_none());
        assert!(config.geoip.is_none());
        assert!(config.status_port.is_none());
    }

    #[test]
    fn test_config_default_paths() {
        // Test that default paths are correct
        let config = Config::default();
        assert_eq!(config.file, PathBuf::from("urls.txt"));
        assert_eq!(config.db_path, PathBuf::from("./domain_status.db"));
    }

    #[test]
    fn test_config_default_user_agent() {
        // Test that default user agent is set correctly
        // The default mimics a real browser to avoid bot detection
        let config = Config::default();
        assert!(!config.user_agent.is_empty());
        assert!(config.user_agent.contains("Mozilla"));
    }

    #[test]
    fn test_fail_on_variants() {
        // Test that all FailOn variants are distinct
        assert_ne!(FailOn::Never, FailOn::AnyFailure);
        assert_ne!(FailOn::AnyFailure, FailOn::PctGreaterThan);
        assert_ne!(FailOn::PctGreaterThan, FailOn::ErrorsOnly);
        assert_ne!(FailOn::ErrorsOnly, FailOn::Never);
    }

    #[test]
    fn test_config_clone() {
        // Test that Config can be cloned correctly
        let config = Config {
            max_concurrency: 100,
            rate_limit_rps: 50,
            enable_whois: true,
            ..Default::default()
        };

        let cloned = config.clone();
        assert_eq!(cloned.max_concurrency, 100);
        assert_eq!(cloned.rate_limit_rps, 50);
        assert!(cloned.enable_whois);
    }
}
