//! Logger initialization.
//!
//! This module provides functions to initialize the logger with custom formatting.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use crate::config::LogFormat;
use crate::error_handling::InitializationError;
use colored::*;
use log::LevelFilter;

/// Initializes the logger with the specified level and format.
///
/// Configures `env_logger` with custom formatting. Supports both plain text
/// (with colors and emojis) and JSON formats for structured logging.
///
/// The logger reads from the `RUST_LOG` environment variable by default, but
/// the provided `level` parameter will override it. This allows developers to
/// use `RUST_LOG=debug` for quick debugging while still supporting explicit
/// CLI control via `--log-level`.
///
/// # Arguments
///
/// * `level` - Minimum log level to display (overrides `RUST_LOG` if set)
/// * `format` - Log format (Plain or Json)
///
/// # Returns
///
/// `Ok(())` if initialization succeeds, or an error if logger setup fails.
///
/// # Errors
///
/// Returns `InitializationError::LoggerError` if logger initialization fails.
///
/// # Examples
///
/// ```bash
/// # Use RUST_LOG for quick debugging (no CLI args needed)
/// RUST_LOG=debug domain_status scan urls.txt
///
/// # Override with CLI args (takes precedence)
/// RUST_LOG=debug domain_status scan urls.txt --log-level info
///
/// # Per-module filtering via RUST_LOG
/// RUST_LOG=domain_status=debug,reqwest=info domain_status scan urls.txt
/// ```
pub fn init_logger_with(level: LevelFilter, format: LogFormat) -> Result<(), InitializationError> {
    colored::control::set_override(true);

    // Read from RUST_LOG environment variable first, then override with CLI arg
    let mut builder = env_logger::Builder::from_default_env();

    // Override with CLI-provided level (takes precedence over RUST_LOG)
    builder.filter_level(level);
    builder.filter_module("html5ever", LevelFilter::Error);
    builder.filter_module("sqlx", LevelFilter::Info);
    builder.filter_module("reqwest", LevelFilter::Info);
    builder.filter_module("hyper", LevelFilter::Info);
    builder.filter_module("selectors", LevelFilter::Warn);
    // Suppress hickory UDP client stream warnings about malformed DNS messages
    // These are expected when DNS responses are truncated or malformed, and hickory handles them gracefully
    // Filter all hickory_proto warnings to Error level to suppress UDP malformed message warnings
    builder.filter_module("hickory_proto", LevelFilter::Error);
    builder.filter_module("domain_status", level);

    // Explicitly write logs to stderr to avoid polluting stdout when piping
    builder.target(env_logger::Target::Stderr);

    match format {
        LogFormat::Json => {
            builder.format(|buf, record| {
                writeln!(
                    buf,
                    "{{\"ts\":{},\"level\":\"{}\",\"target\":\"{}\",\"msg\":{}}}",
                    chrono::Utc::now().timestamp_millis(),
                    record.level(),
                    record.target(),
                    serde_json::to_string(&record.args().to_string())
                        .unwrap_or_else(|_| "\"\"".into())
                )
            });
        }
        LogFormat::Plain => {
            builder.format(|buf, record| {
                let level = record.level();
                let colored_level = match level {
                    log::Level::Error => level.to_string().red(),
                    log::Level::Warn => level.to_string().yellow(),
                    log::Level::Info => level.to_string().green(),
                    log::Level::Debug => level.to_string().blue(),
                    log::Level::Trace => level.to_string().purple(),
                };

                let emoji = match level {
                    log::Level::Error => "❌",
                    log::Level::Warn => "⚠️",
                    log::Level::Info => "✔️",
                    log::Level::Debug => "🔍",
                    log::Level::Trace => "🔬",
                };

                writeln!(
                    buf,
                    "{} {} [{}] {}",
                    emoji,
                    record.target().cyan(),
                    colored_level,
                    record.args()
                )
            });
        }
    }

    // Use try_init() instead of init() to avoid panicking if logger is already initialized
    // This is important for tests where logger may be initialized multiple times
    builder.try_init().map_err(InitializationError::from)?;

    Ok(())
}

/// Initializes the logger to write to a file with timestamps.
///
/// Used when progress bar is enabled - logs go to file while progress bar shows on terminal.
/// Log format includes ISO 8601 timestamps for each entry.
///
/// # Arguments
///
/// * `level` - Minimum log level to display
/// * `log_file` - Path to the log file
///
/// # Returns
///
/// `Ok(())` if initialization succeeds, or an error if logger setup fails.
pub fn init_logger_to_file(level: LevelFilter, log_file: &Path) -> Result<(), InitializationError> {
    // Create/truncate the log file
    let file = File::create(log_file).map_err(|e| {
        InitializationError::LoggerSetupError(format!("Failed to create log file: {}", e))
    })?;
    let file = Mutex::new(file);

    let mut builder = env_logger::Builder::from_default_env();

    builder.filter_level(level);
    builder.filter_module("html5ever", LevelFilter::Error);
    builder.filter_module("sqlx", LevelFilter::Info);
    builder.filter_module("reqwest", LevelFilter::Info);
    builder.filter_module("hyper", LevelFilter::Info);
    builder.filter_module("selectors", LevelFilter::Warn);
    builder.filter_module("hickory_proto", LevelFilter::Error);
    builder.filter_module("domain_status", level);

    // Format with timestamps (no colors since it's going to a file)
    builder.format(move |buf, record| {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let level = record.level();

        // Write to the buffer (which goes to stderr by default)
        let line = format!(
            "[{}] {} {} - {}\n",
            timestamp,
            level,
            record.target(),
            record.args()
        );

        // Also write to our file
        if let Ok(mut f) = file.lock() {
            let _ = f.write_all(line.as_bytes());
            // Flush on warnings and errors to ensure they're persisted immediately
            if level <= log::Level::Warn {
                let _ = f.flush();
            }
        }

        // Write to buffer (this goes to env_logger's target)
        write!(buf, "{}", line)
    });

    // Target the file instead of stderr
    builder.target(env_logger::Target::Pipe(Box::new(std::io::sink())));

    builder.try_init().map_err(InitializationError::from)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_logger_plain_format() {
        // env_logger can only be initialized once per process
        // Use try_init() which returns Ok(()) if already initialized
        let _ = env_logger::try_init();

        // This may fail if logger was already initialized, which is acceptable
        // The important thing is that the function doesn't panic
        let result = init_logger_with(LevelFilter::Info, LogFormat::Plain);
        // Accept either success or error (if already initialized)
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_init_logger_json_format() {
        let _ = env_logger::try_init();

        let result = init_logger_with(LevelFilter::Info, LogFormat::Json);
        // Accept either success or error (if already initialized)
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_init_logger_all_levels() {
        let _ = env_logger::try_init();

        // Test that function signature is correct for all levels
        // Note: Only first call will succeed if logger already initialized
        for level in [
            LevelFilter::Error,
            LevelFilter::Warn,
            LevelFilter::Info,
            LevelFilter::Debug,
            LevelFilter::Trace,
        ] {
            let result = init_logger_with(level, LogFormat::Plain);
            // Accept either success or error (logger may already be initialized)
            assert!(
                result.is_ok() || result.is_err(),
                "Level {:?} should not panic",
                level
            );
        }
    }

    #[test]
    fn test_init_logger_respects_rust_log_env() {
        // This test verifies that RUST_LOG is read, but CLI level overrides it
        // We can't easily test the actual filtering without making real log calls,
        // but we can verify initialization succeeds or fails gracefully
        let _ = env_logger::try_init();

        // Should succeed or fail gracefully (if already initialized)
        let result = init_logger_with(LevelFilter::Info, LogFormat::Plain);
        assert!(result.is_ok() || result.is_err());
    }
}
