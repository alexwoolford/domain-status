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

/// Configuration validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigValidationError {
    /// The field that failed validation
    pub field: String,
    /// Description of the validation failure
    pub message: String,
}

impl std::fmt::Display for ConfigValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid config '{}': {}", self.field, self.message)
    }
}

impl std::error::Error for ConfigValidationError {}

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
#[derive(Clone)]
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

    /// Exit code policy for handling failures
    pub fail_on: FailOn,

    /// Failure percentage threshold (used with `fail_on: FailOn::PctGreaterThan`)
    ///
    /// A number between 0 and 100. If failure percentage exceeds this value,
    /// exit with code 2. Only used when `fail_on` is `PctGreaterThan`.
    pub fail_on_pct_threshold: u8,

    /// Log file path for detailed logging (always used in CLI)
    pub log_file: Option<PathBuf>,

    /// Progress callback for external progress tracking.
    ///
    /// Called with (completed, failed, total) after each URL is processed.
    /// This allows external code (like CLI) to update progress bars.
    ///
    /// **Important**: The callback is invoked synchronously from async tasks.
    /// Keep callback execution fast (microseconds) to avoid blocking URL processing.
    /// For slow operations, spawn a separate task inside the callback.
    ///
    /// **Thread Safety**: The callback may be invoked concurrently from multiple
    /// tokio tasks. If the callback maintains state, use `Arc<Mutex<_>>` or atomic
    /// operations. The `completed` and `failed` counters are already `Arc<AtomicUsize>`,
    /// so they can be safely read from multiple threads.
    #[doc(hidden)]
    #[allow(clippy::type_complexity)]
    pub progress_callback: Option<std::sync::Arc<dyn Fn(usize, usize, usize) + Send + Sync>>,
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
            fail_on: FailOn::Never,
            fail_on_pct_threshold: 10,
            log_file: None,
            progress_callback: None,
        }
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("file", &self.file)
            .field("log_level", &self.log_level)
            .field("log_format", &self.log_format)
            .field("db_path", &self.db_path)
            .field("max_concurrency", &self.max_concurrency)
            .field("timeout_seconds", &self.timeout_seconds)
            .field("user_agent", &self.user_agent)
            .field("rate_limit_rps", &self.rate_limit_rps)
            .field("adaptive_error_threshold", &self.adaptive_error_threshold)
            .field("fingerprints", &self.fingerprints)
            .field("geoip", &self.geoip)
            .field("status_port", &self.status_port)
            .field("enable_whois", &self.enable_whois)
            .field("fail_on", &self.fail_on)
            .field("fail_on_pct_threshold", &self.fail_on_pct_threshold)
            .field("log_file", &self.log_file)
            .field(
                "progress_callback",
                &self.progress_callback.as_ref().map(|_| "<callback>"),
            )
            .finish()
    }
}

impl Config {
    /// Maximum allowed concurrency to prevent resource exhaustion.
    pub const MAX_CONCURRENCY: usize = 500;

    /// Maximum allowed rate limit (requests per second).
    pub const MAX_RATE_LIMIT_RPS: u32 = 100;

    /// Validates the configuration and returns any validation errors.
    ///
    /// # Returns
    ///
    /// `Ok(())` if configuration is valid, or `Err(ConfigValidationError)` with
    /// details about the first validation failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use domain_status::Config;
    ///
    /// let mut config = Config::default();
    /// assert!(config.validate().is_ok());
    ///
    /// config.max_concurrency = 0;
    /// assert!(config.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        // Validate max_concurrency
        if self.max_concurrency == 0 {
            return Err(ConfigValidationError {
                field: "max_concurrency".to_string(),
                message: "must be greater than 0".to_string(),
            });
        }
        if self.max_concurrency > Self::MAX_CONCURRENCY {
            return Err(ConfigValidationError {
                field: "max_concurrency".to_string(),
                message: format!(
                    "must be <= {} to prevent resource exhaustion",
                    Self::MAX_CONCURRENCY
                ),
            });
        }

        // Validate rate_limit_rps (0 means disabled, which is valid)
        if self.rate_limit_rps > Self::MAX_RATE_LIMIT_RPS {
            return Err(ConfigValidationError {
                field: "rate_limit_rps".to_string(),
                message: format!(
                    "must be <= {} to prevent overwhelming targets",
                    Self::MAX_RATE_LIMIT_RPS
                ),
            });
        }

        // Validate timeout_seconds
        if self.timeout_seconds == 0 {
            return Err(ConfigValidationError {
                field: "timeout_seconds".to_string(),
                message: "must be greater than 0".to_string(),
            });
        }

        // Validate adaptive_error_threshold
        if self.adaptive_error_threshold < 0.0 || self.adaptive_error_threshold > 1.0 {
            return Err(ConfigValidationError {
                field: "adaptive_error_threshold".to_string(),
                message: "must be between 0.0 and 1.0".to_string(),
            });
        }

        // Validate fail_on_pct_threshold
        if self.fail_on_pct_threshold > 100 {
            return Err(ConfigValidationError {
                field: "fail_on_pct_threshold".to_string(),
                message: "must be between 0 and 100".to_string(),
            });
        }

        // Validate user_agent is not empty
        if self.user_agent.trim().is_empty() {
            return Err(ConfigValidationError {
                field: "user_agent".to_string(),
                message: "cannot be empty".to_string(),
            });
        }

        Ok(())
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

    // Config validation tests

    #[test]
    fn test_config_validate_default_is_valid() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_max_concurrency_zero() {
        let config = Config {
            max_concurrency: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert_eq!(err.field, "max_concurrency");
        assert!(err.message.contains("greater than 0"));
    }

    #[test]
    fn test_config_validate_max_concurrency_too_high() {
        let config = Config {
            max_concurrency: Config::MAX_CONCURRENCY + 1,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert_eq!(err.field, "max_concurrency");
        assert!(err.message.contains("resource exhaustion"));
    }

    #[test]
    fn test_config_validate_max_concurrency_at_limit() {
        let config = Config {
            max_concurrency: Config::MAX_CONCURRENCY,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_rate_limit_zero_is_valid() {
        // 0 means "disabled" which is valid for tests and special use cases
        let config = Config {
            rate_limit_rps: 0,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_rate_limit_too_high() {
        let config = Config {
            rate_limit_rps: Config::MAX_RATE_LIMIT_RPS + 1,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert_eq!(err.field, "rate_limit_rps");
        assert!(err.message.contains("overwhelming"));
    }

    #[test]
    fn test_config_validate_rate_limit_at_limit() {
        let config = Config {
            rate_limit_rps: Config::MAX_RATE_LIMIT_RPS,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_timeout_zero() {
        let config = Config {
            timeout_seconds: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert_eq!(err.field, "timeout_seconds");
        assert!(err.message.contains("greater than 0"));
    }

    #[test]
    fn test_config_validate_adaptive_error_threshold_negative() {
        let config = Config {
            adaptive_error_threshold: -0.1,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert_eq!(err.field, "adaptive_error_threshold");
        assert!(err.message.contains("between 0.0 and 1.0"));
    }

    #[test]
    fn test_config_validate_adaptive_error_threshold_over_one() {
        let config = Config {
            adaptive_error_threshold: 1.1,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert_eq!(err.field, "adaptive_error_threshold");
    }

    #[test]
    fn test_config_validate_adaptive_error_threshold_boundary() {
        // Test boundary values (0.0 and 1.0 should be valid)
        let config_zero = Config {
            adaptive_error_threshold: 0.0,
            ..Default::default()
        };
        assert!(config_zero.validate().is_ok());

        let config_one = Config {
            adaptive_error_threshold: 1.0,
            ..Default::default()
        };
        assert!(config_one.validate().is_ok());
    }

    #[test]
    fn test_config_validate_fail_on_pct_threshold_over_100() {
        let config = Config {
            fail_on_pct_threshold: 101,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert_eq!(err.field, "fail_on_pct_threshold");
        assert!(err.message.contains("between 0 and 100"));
    }

    #[test]
    fn test_config_validate_fail_on_pct_threshold_boundary() {
        // 0 and 100 should be valid
        let config_zero = Config {
            fail_on_pct_threshold: 0,
            ..Default::default()
        };
        assert!(config_zero.validate().is_ok());

        let config_hundred = Config {
            fail_on_pct_threshold: 100,
            ..Default::default()
        };
        assert!(config_hundred.validate().is_ok());
    }

    #[test]
    fn test_config_validate_empty_user_agent() {
        let config = Config {
            user_agent: "".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert_eq!(err.field, "user_agent");
        assert!(err.message.contains("empty"));
    }

    #[test]
    fn test_config_validate_whitespace_user_agent() {
        let config = Config {
            user_agent: "   ".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert_eq!(err.field, "user_agent");
    }

    #[test]
    fn test_config_validation_error_display() {
        let err = ConfigValidationError {
            field: "test_field".to_string(),
            message: "test message".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("test_field"));
        assert!(display.contains("test message"));
    }

    #[test]
    fn test_config_validation_error_error_trait() {
        // Test that ConfigValidationError implements std::error::Error
        let err = ConfigValidationError {
            field: "test_field".to_string(),
            message: "test message".to_string(),
        };
        // Verify it can be used as Error trait object
        let error_ref: &dyn std::error::Error = &err;
        let error_msg = error_ref.to_string();
        assert!(error_msg.contains("test_field") || error_msg.contains("test message"));
    }

    #[test]
    fn test_config_debug_formatting() {
        // Test that Config Debug implementation works correctly
        let config = Config {
            max_concurrency: 50,
            rate_limit_rps: 25,
            enable_whois: true,
            status_port: Some(8080),
            ..Default::default()
        };
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("Config"));
        assert!(debug_str.contains("max_concurrency"));
        assert!(debug_str.contains("50"));
        // Progress callback should be shown as "<callback>" not actual function pointer
        assert!(debug_str.contains("<callback>") || !debug_str.contains("0x"));
    }

    #[test]
    fn test_config_debug_with_callback() {
        // Test Debug formatting when progress_callback is set
        use std::sync::Arc;
        let callback = Arc::new(|_completed: usize, _failed: usize, _total: usize| {});
        let config = Config {
            progress_callback: Some(callback),
            ..Default::default()
        };
        let debug_str = format!("{:?}", config);
        // Should show "<callback>" not expose the actual function pointer
        assert!(debug_str.contains("<callback>") || !debug_str.contains("0x"));
    }

    #[test]
    fn test_config_validate_all_fields_valid() {
        // Test validation with all fields at valid boundary values
        let config = Config {
            max_concurrency: Config::MAX_CONCURRENCY,
            rate_limit_rps: Config::MAX_RATE_LIMIT_RPS,
            timeout_seconds: 1,
            adaptive_error_threshold: 1.0,
            fail_on_pct_threshold: 100,
            user_agent: "Valid User Agent".to_string(),
            ..Default::default()
        };
        assert!(
            config.validate().is_ok(),
            "All valid boundary values should pass"
        );
    }

    #[test]
    fn test_config_validate_multiple_errors_first_one_returned() {
        // Test that validation returns the first error encountered
        // This is important - validation order matters for error messages
        let config = Config {
            max_concurrency: 0,         // First validation check
            timeout_seconds: 0,         // Would be second, but first error is returned
            user_agent: "".to_string(), // Would be third, but first error is returned
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        // Should return max_concurrency error (first check)
        assert_eq!(err.field, "max_concurrency");
    }

    // Property-based tests using proptest
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_config_validation_concurrency(n in 1u32..=500) {
            let config = Config {
                max_concurrency: n as usize,
                ..Default::default()
            };
            prop_assert!(config.validate().is_ok(),
                "Concurrency 1-500 should be valid");
        }

        #[test]
        fn test_config_validation_concurrency_invalid(n in 501u32..1000) {
            let config = Config {
                max_concurrency: n as usize,
                ..Default::default()
            };
            prop_assert!(config.validate().is_err(),
                "Concurrency > 500 should be invalid");
        }

        #[test]
        fn test_config_validation_rate_limit(n in 0u32..=100) {
            let config = Config {
                rate_limit_rps: n,
                ..Default::default()
            };
            prop_assert!(config.validate().is_ok(),
                "Rate limit 0-100 should be valid");
        }

        #[test]
        fn test_config_validation_rate_limit_invalid(n in 101u32..1000) {
            let config = Config {
                rate_limit_rps: n,
                ..Default::default()
            };
            prop_assert!(config.validate().is_err(),
                "Rate limit > 100 should be invalid");
        }

        #[test]
        fn test_config_validation_error_threshold(threshold in 0.0f64..=1.0) {
            let config = Config {
                adaptive_error_threshold: threshold,
                ..Default::default()
            };
            prop_assert!(config.validate().is_ok(),
                "Error threshold 0.0-1.0 should be valid");
        }

        #[test]
        fn test_config_validation_error_threshold_invalid_high(threshold in 1.01f64..10.0) {
            let config = Config {
                adaptive_error_threshold: threshold,
                ..Default::default()
            };
            prop_assert!(config.validate().is_err(),
                "Error threshold > 1.0 should be invalid");
        }

        #[test]
        fn test_config_validation_error_threshold_invalid_low(threshold in -10.0f64..-0.01) {
            let config = Config {
                adaptive_error_threshold: threshold,
                ..Default::default()
            };
            prop_assert!(config.validate().is_err(),
                "Error threshold < 0.0 should be invalid");
        }

        #[test]
        fn test_config_validation_fail_on_pct(pct in 0u8..=100) {
            let config = Config {
                fail_on_pct_threshold: pct,
                ..Default::default()
            };
            prop_assert!(config.validate().is_ok(),
                "Fail on pct 0-100 should be valid");
        }

        #[test]
        fn test_config_validation_fail_on_pct_invalid(pct in 101u8..=255) {
            let config = Config {
                fail_on_pct_threshold: pct,
                ..Default::default()
            };
            prop_assert!(config.validate().is_err(),
                "Fail on pct > 100 should be invalid");
        }

        #[test]
        fn test_config_validation_timeout(timeout in 1u64..3600) {
            let config = Config {
                timeout_seconds: timeout,
                ..Default::default()
            };
            prop_assert!(config.validate().is_ok(),
                "Timeout >= 1 should be valid");
        }

        #[test]
        fn test_config_validation_user_agent_nonempty(agent in "[a-zA-Z0-9]+( [a-zA-Z0-9]+){0,10}") {
            let config = Config {
                user_agent: agent.clone(),
                ..Default::default()
            };
            // Ensure the agent is not just whitespace after trimming
            if !agent.trim().is_empty() {
                prop_assert!(config.validate().is_ok(),
                    "Non-empty user agent should be valid");
            }
        }
    }
}
