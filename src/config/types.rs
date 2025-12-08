//! Configuration types and CLI options.
//!
//! This module defines enums and structs used for command-line argument parsing
//! and configuration.

use std::path::PathBuf;

use clap::ValueEnum;

use crate::config::constants::DEFAULT_USER_AGENT;

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
    fn test_log_format_variants() {
        // Test that LogFormat enum variants can be created and compared
        let plain = LogFormat::Plain;
        let json = LogFormat::Json;

        // Both should be valid variants
        match plain {
            LogFormat::Plain => {}
            LogFormat::Json => panic!("Plain should not match Json"),
        }

        match json {
            LogFormat::Plain => panic!("Json should not match Plain"),
            LogFormat::Json => {}
        }
    }

    #[test]
    fn test_log_format_debug() {
        // Test Debug trait implementation
        let plain = LogFormat::Plain;
        let json = LogFormat::Json;

        // Should not panic when formatting
        let plain_str = format!("{:?}", plain);
        let json_str = format!("{:?}", json);

        assert_eq!(plain_str, "Plain");
        assert_eq!(json_str, "Json");
    }

    #[test]
    fn test_log_level_debug() {
        // Test Debug trait implementation for LogLevel
        let error = LogLevel::Error;
        let warn = LogLevel::Warn;
        let info = LogLevel::Info;
        let debug = LogLevel::Debug;
        let trace = LogLevel::Trace;

        // Should not panic when formatting
        assert_eq!(format!("{:?}", error), "Error");
        assert_eq!(format!("{:?}", warn), "Warn");
        assert_eq!(format!("{:?}", info), "Info");
        assert_eq!(format!("{:?}", debug), "Debug");
        assert_eq!(format!("{:?}", trace), "Trace");
    }

    #[test]
    fn test_log_level_clone() {
        // Test Clone trait implementation
        let original = LogLevel::Info;
        let cloned = original.clone();

        // Both should convert to the same LevelFilter
        assert_eq!(
            log::LevelFilter::from(original),
            log::LevelFilter::from(cloned)
        );
    }

    #[test]
    fn test_log_format_clone() {
        // Test Clone trait implementation
        let original = LogFormat::Plain;
        let cloned = original.clone();

        // Both should be the same variant
        match (original, cloned) {
            (LogFormat::Plain, LogFormat::Plain) => {}
            (LogFormat::Json, LogFormat::Json) => {}
            _ => panic!("Cloned value should match original"),
        }
    }

    #[test]
    fn test_config_default() {
        // Test Config default values
        let config = Config::default();
        assert_eq!(config.max_concurrency, 30);
        assert_eq!(config.timeout_seconds, 10);
        assert_eq!(config.rate_limit_rps, 15);
        assert_eq!(config.adaptive_error_threshold, 0.2);
        assert!(!config.enable_whois);
        assert!(!config.show_timing);
        assert_eq!(config.db_path, PathBuf::from("./domain_status.db"));
    }
}
