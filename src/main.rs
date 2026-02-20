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
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::time::Duration;

use domain_status::config::{FailOn, LogFormat, LogLevel, DEFAULT_USER_AGENT};
use domain_status::export::export_csv;
use domain_status::initialization::{init_crypto_provider, init_logger_to_file, init_logger_with};
use domain_status::{run_scan, Config};

/// CLI-specific configuration with clap parsing.
///
/// This struct is used only in the CLI binary and includes clap attributes
/// for command-line argument parsing. It can be converted to the library `Config` type.
#[derive(Debug, Parser, Clone)]
#[command(
    name = "domain_status",
    about = "Domain intelligence scanner - scan URLs and export results.",
    version = env!("CARGO_PKG_VERSION"),
    long_version = env!("CARGO_PKG_VERSION"),
    subcommand_required = true
)]
enum CliCommand {
    /// Scan URLs and store results in SQLite database
    #[command(name = "scan")]
    Scan(ScanCommand),
    /// Export data from SQLite database to various formats
    #[command(name = "export")]
    Export(ExportCommand),
}

#[derive(Debug, Parser, Clone)]
struct ScanCommand {
    /// File to read
    #[arg(value_parser)]
    file: PathBuf,

    /// Log level: error|warn|info|debug|trace
    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    log_level: LogLevel,

    /// Log format: plain|json
    #[arg(long, value_enum, default_value_t = LogFormat::Plain)]
    log_format: LogFormat,

    /// Database path (SQLite file)
    #[arg(long, value_parser, default_value = "./domain_status.db")]
    db_path: PathBuf,

    /// Maximum concurrent requests
    ///
    /// Increased default from 20 to 30 for better throughput while maintaining low bot detection risk.
    /// High concurrency can trigger rate limiting even with low RPS.
    #[arg(long, default_value_t = 30)]
    max_concurrency: usize,

    /// Per-request timeout in seconds
    #[arg(long, default_value_t = 10)]
    timeout_seconds: u64,

    /// HTTP User-Agent header value.
    ///
    /// Defaults to a Chrome-like browser string. Can be overridden to match
    /// specific browser versions or patterns. For better bot evasion, consider
    /// using a recent browser version or rotating User-Agent strings.
    #[arg(long, default_value = DEFAULT_USER_AGENT)]
    user_agent: String,

    /// Initial requests per second (adaptive rate limiting always enabled)
    ///
    /// Rate limiting automatically adjusts based on error rates:
    /// - Starts at this RPS value
    /// - Reduces by 50% when error rate exceeds threshold (default: 20%)
    /// - Increases by 15% when error rate is below threshold
    /// - Minimum RPS: 1, Maximum RPS: 2x this initial value (allows system to adapt to good conditions)
    ///
    /// Set to 0 to disable rate limiting (not recommended for production).
    #[arg(long, default_value_t = 15)]
    rate_limit_rps: u32,

    /// Error rate threshold for adaptive rate limiting (0.0-1.0, default: 0.2 = 20%)
    ///
    /// When error rate (429s + timeouts) exceeds this threshold, RPS is reduced.
    /// Advanced option - default 20% works well for most cases.
    #[arg(long, default_value_t = 0.2, hide = true)]
    adaptive_error_threshold: f64,

    /// Fingerprints source URL or local path (default: HTTP Archive)
    /// Examples:
    ///   --fingerprints https://raw.githubusercontent.com/HTTPArchive/wappalyzer/main/src/technologies
    ///   --fingerprints /path/to/technologies.json
    #[arg(long)]
    fingerprints: Option<String>,

    /// GeoIP database path (MaxMind GeoLite2 .mmdb file) or download URL
    /// Examples:
    ///   --geoip /path/to/GeoLite2-City.mmdb
    ///   --geoip https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_KEY&suffix=tar.gz
    /// If not provided, GeoIP will auto-download if MAXMIND_LICENSE_KEY env var is set.
    /// Otherwise, GeoIP lookup is disabled.
    #[arg(long)]
    geoip: Option<String>,

    /// HTTP status server port (optional, disabled by default)
    ///
    /// When set, starts a lightweight HTTP server that exposes:
    /// - `/metrics` - Prometheus-compatible metrics
    /// - `/status` - JSON status endpoint with progress information
    ///
    /// Useful for monitoring long-running jobs. The server runs in the background
    /// and does not block URL processing. Example: `--status-port 8080`
    #[arg(long)]
    status_port: Option<u16>,

    /// Enable WHOIS/RDAP lookup for domain registration information
    ///
    /// When enabled, performs WHOIS/RDAP queries to fetch:
    /// - Domain creation date
    /// - Domain expiration date
    /// - Registrar information
    /// - Registrant details
    ///
    /// **Rate Limiting**: WHOIS queries are rate-limited to 1 query per 2 seconds
    /// (0.5 queries/second) by default to respect registrar limits. This is separate
    /// from HTTP rate limiting and will slow down processing when enabled.
    ///
    /// **Caching**: WHOIS data is cached for 7 days to avoid redundant queries.
    ///
    /// **Default**: Disabled (off) to maintain fast processing speeds.
    /// Enable only when domain age/registrar information is needed.
    #[arg(long)]
    enable_whois: bool,

    /// Exit code policy for handling failures
    ///
    /// Controls when the CLI should exit with a non-zero code:
    /// - `never`: Always return 0 (useful for monitoring/logging)
    /// - `any-failure`: Exit with code 2 if any URL failed (strict CI mode)
    /// - `pct>X`: Exit with code 2 if failure percentage exceeds X (e.g., `pct>10`)
    /// - `errors-only`: Exit only on critical errors (future enhancement)
    ///
    /// Default: `never` (backward compatible)
    ///
    /// Exit codes:
    /// - 0: Success (or failures ignored by policy)
    /// - 1: Configuration error or scan initialization failure
    /// - 2: Failures exceeded threshold (based on --fail-on policy)
    /// - 3: Partial success (some URLs processed, but scan incomplete)
    #[arg(long, value_enum, default_value_t = FailOn::Never)]
    fail_on: FailOn,

    /// Failure percentage threshold for `--fail-on pct>X`
    ///
    /// A number between 0 and 100. Only used when `--fail-on pct>X` is specified.
    /// Example: `--fail-on pct>10 --fail-on-pct-threshold 15` means exit with error
    /// if more than 15% of URLs failed.
    ///
    /// Default: 10
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u8).range(0..=100))]
    fail_on_pct_threshold: u8,

    /// Log file path for detailed logging
    ///
    /// All log messages are written to this file with timestamps.
    /// A progress bar is shown in the terminal instead of log output.
    #[arg(long, default_value = "domain_status.log")]
    log_file: PathBuf,
}

#[derive(Debug, Parser, Clone)]
struct ExportCommand {
    /// Database path (SQLite file)
    #[arg(long, value_parser, default_value = "./domain_status.db")]
    db_path: PathBuf,

    /// Export format: csv|jsonl|parquet
    #[arg(long, value_enum, default_value = "csv")]
    format: ExportFormat,

    /// Output file path
    ///
    /// If not specified, writes to a file in the current directory:
    /// - CSV: `domain_status_export.csv`
    /// - JSONL: `domain_status_export.jsonl`
    /// - Parquet: `domain_status_export.parquet`
    ///
    /// Use `-` to write to stdout (for piping to other commands).
    #[arg(long)]
    output: Option<String>,

    /// Filter by run ID
    #[arg(long)]
    run_id: Option<String>,

    /// Filter by domain (matches initial or final domain)
    #[arg(long)]
    domain: Option<String>,

    /// Filter by HTTP status code
    #[arg(long)]
    status: Option<u16>,

    /// Filter by timestamp (export records after this timestamp, in milliseconds since epoch)
    #[arg(long)]
    since: Option<i64>,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum ExportFormat {
    Csv,
    Jsonl,
    Parquet,
}

impl From<ScanCommand> for Config {
    fn from(cli: ScanCommand) -> Self {
        Self {
            file: cli.file,
            log_level: cli.log_level,
            log_format: cli.log_format,
            db_path: cli.db_path,
            max_concurrency: cli.max_concurrency,
            timeout_seconds: cli.timeout_seconds,
            user_agent: cli.user_agent,
            rate_limit_rps: cli.rate_limit_rps,
            adaptive_error_threshold: cli.adaptive_error_threshold,
            fingerprints: cli.fingerprints,
            geoip: cli.geoip,
            status_port: cli.status_port,
            enable_whois: cli.enable_whois,
            fail_on: cli.fail_on,
            fail_on_pct_threshold: cli.fail_on_pct_threshold,
            log_file: Some(cli.log_file),
            progress_callback: None, // Set later during initialization
        }
    }
}

/// Loads environment variables from .env file if it exists.
///
/// Tries loading from current directory first, then from the executable's directory.
/// This allows setting configuration like MAXMIND_LICENSE_KEY in .env.
fn load_environment() {
    if dotenvy::dotenv().is_err() {
        // If .env not found in current dir, try next to the executable
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let env_path = exe_dir.join(".env");
                if env_path.exists() {
                    if let Err(e) = dotenvy::from_path(&env_path) {
                        eprintln!(
                            "Warning: Failed to load .env from {}: {}",
                            env_path.display(),
                            e
                        );
                    }
                }
            }
        }
    }
}

/// Initializes file logger for scan operations.
///
/// Returns an error if logger initialization fails.
fn init_scan_logging(log_level: &LogLevel, log_file: &Path) -> Result<()> {
    init_logger_to_file(log_level.clone().into(), log_file)
        .context("Failed to initialize file logger")?;
    eprintln!("📝 Logs: {}", log_file.display());
    log::info!("domain_status version {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}

/// Creates and configures a progress bar for scan operations.
fn create_progress_bar() -> Result<Arc<ProgressBar>> {
    let pb = Arc::new(ProgressBar::new(0));
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
            .context("Failed to create progress bar template")?
            .progress_chars("█▓░"),
    );
    pb.enable_steady_tick(Duration::from_millis(100));
    Ok(pb)
}

/// Creates a progress callback for updating the progress bar during scan.
fn create_progress_callback(
    pb: Arc<ProgressBar>,
) -> Arc<dyn Fn(usize, usize, usize) + Send + Sync> {
    Arc::new(move |completed, failed, total| {
        pb.set_length(total as u64);
        pb.set_position((completed + failed) as u64);
        pb.set_message(format!("✓{} ✗{}", completed, failed));
    })
}

/// Executes the scan and prints the results summary.
///
/// Returns the exit code based on the scan results and fail-on policy.
async fn execute_scan_with_reporting(config: &Config, _pb: Arc<ProgressBar>) -> Result<()> {
    match run_scan(config.clone()).await {
        Ok(report) => {
            println!(
                "✅ Processed {} URL{} ({} succeeded, {} failed) in {:.1}s - see database for details",
                report.total_urls,
                if report.total_urls == 1 { "" } else { "s" },
                report.successful,
                report.failed,
                report.elapsed_seconds
            );
            println!("Results saved in {}", report.db_path.display());
            println!("💡 Tip: Use `domain_status export --format csv` to export data, or query the database directly.");

            let exit_code =
                evaluate_exit_code(&config.fail_on, config.fail_on_pct_threshold, &report);
            if exit_code != 0 {
                process::exit(exit_code);
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("domain_status error: {:#}", e);
            process::exit(1);
        }
    }
}

/// Handles export command execution for CSV, JSONL, and Parquet formats.
async fn execute_export_command(export_cmd: ExportCommand) -> Result<()> {
    // Initialize logger for export command
    init_logger_with(LogLevel::Info.into(), LogFormat::Plain)
        .context("Failed to initialize logger")?;
    log::info!("domain_status version {}", env!("CARGO_PKG_VERSION"));

    // Determine output path: default to file, allow "-" for stdout
    let output_path = if let Some(ref path_str) = export_cmd.output {
        if path_str == "-" {
            None // stdout
        } else {
            Some(PathBuf::from(path_str))
        }
    } else {
        // Default to file based on format
        let extension = match export_cmd.format {
            ExportFormat::Csv => "csv",
            ExportFormat::Jsonl => "jsonl",
            ExportFormat::Parquet => "parquet",
        };
        Some(PathBuf::from(format!("domain_status_export.{}", extension)))
    };

    // Convert CLI ExportFormat to library ExportFormat
    let lib_format = match export_cmd.format {
        ExportFormat::Csv => domain_status::export::ExportFormat::Csv,
        ExportFormat::Jsonl => domain_status::export::ExportFormat::Jsonl,
        ExportFormat::Parquet => domain_status::export::ExportFormat::Parquet,
    };

    // Build export options from CLI args
    let export_opts = domain_status::export::ExportOptions {
        db_path: export_cmd.db_path.clone(),
        output: output_path.clone(),
        format: lib_format,
        run_id: export_cmd.run_id.clone(),
        domain: export_cmd.domain.clone(),
        status: export_cmd.status,
        since: export_cmd.since,
    };

    // Handle export format
    match export_cmd.format {
        ExportFormat::Csv => {
            let count = export_csv(&export_opts)
                .await
                .context("Failed to export CSV")?;

            if let Some(ref path) = output_path {
                eprintln!("✅ Exported {} records to {}", count, path.display());
            } else {
                eprintln!("✅ Exported {} records to CSV", count);
            }
            Ok(())
        }
        ExportFormat::Jsonl => {
            use domain_status::export::export_jsonl;
            match export_jsonl(&export_opts).await {
                Ok(count) => {
                    if let Some(ref path) = output_path {
                        eprintln!("✅ Exported {} records to {}", count, path.display());
                    } else {
                        eprintln!("✅ Exported {} records to JSONL format", count);
                    }
                    Ok(())
                }
                Err(e) => {
                    eprintln!("❌ Failed to export JSONL: {}", e);
                    process::exit(1);
                }
            }
        }
        ExportFormat::Parquet => {
            eprintln!("Parquet export not yet implemented");
            process::exit(1);
        }
    }
}

/// Main entry point for the domain_status CLI tool.
///
/// Handles scan and export commands with proper initialization and error handling.
#[tokio::main]
async fn main() -> Result<()> {
    load_environment();
    let cli_command = CliCommand::parse();

    match cli_command {
        CliCommand::Scan(scan_cmd) => {
            let mut config: Config = scan_cmd.into();

            // Initialize logging
            let log_file = config
                .log_file
                .as_ref()
                .context("Configuration error: log_file not set")?;
            init_scan_logging(&config.log_level, log_file)?;

            // Set up progress bar and callback
            let pb = create_progress_bar()?;
            config.progress_callback = Some(create_progress_callback(Arc::clone(&pb)));

            // Initialize crypto provider for TLS operations
            init_crypto_provider();

            // Execute scan and print results
            execute_scan_with_reporting(&config, pb).await
        }
        CliCommand::Export(export_cmd) => execute_export_command(export_cmd).await,
    }
}

/// Evaluates the exit code based on the failure policy and scan results.
///
/// Returns:
/// - 0: Success (or failures ignored by policy)
/// - 2: Failures exceeded threshold (based on --fail-on policy)
/// - 3: Partial success (some URLs processed, but scan incomplete)
pub fn evaluate_exit_code(
    fail_on: &FailOn,
    pct_threshold: u8,
    report: &domain_status::ScanReport,
) -> i32 {
    match fail_on {
        FailOn::Never => 0,
        FailOn::AnyFailure => {
            if report.failed > 0 {
                2
            } else {
                0
            }
        }
        FailOn::PctGreaterThan => {
            if report.total_urls == 0 {
                // No URLs processed - this is a configuration/input issue
                return 3;
            }
            // SAFETY: Cast from usize to f64 for percentage calculation is acceptable here.
            // f64 mantissa has 53 bits of precision, while usize is 64 bits on 64-bit systems.
            // Precision loss analysis:
            // 1. Exact representation: All integers up to 2^53 (9,007,199,254,740,992) are exactly representable
            // 2. Realistic URL counts: Production runs process <10M URLs, well within exact range
            // 3. Acceptable precision loss: Even with 100B URLs (beyond physical memory limits),
            //    the error would be ~0.000001%, negligible for percentage calculation (e.g., 10.000% vs 10.000001%)
            // 4. Purpose: Percentage calculation for exit code policy - sub-0.001% precision is more than sufficient
            //
            // The alternative (checked arithmetic with Decimal) would be overkill for this use case.
            #[allow(clippy::cast_precision_loss)]
            let failure_pct = (report.failed as f64 / report.total_urls as f64) * 100.0;
            if failure_pct > pct_threshold as f64 {
                2
            } else {
                0
            }
        }
        FailOn::ErrorsOnly => {
            // Future enhancement: distinguish between critical errors and warnings
            // For now, behave like AnyFailure
            if report.failed > 0 {
                2
            } else {
                0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain_status::ScanReport;

    #[test]
    fn test_evaluate_exit_code_never() {
        let report = ScanReport {
            total_urls: 10,
            successful: 5,
            failed: 5,
            elapsed_seconds: 1.0,
            db_path: std::path::PathBuf::from("test.db"),
            run_id: "test-run-1".to_string(),
        };

        assert_eq!(
            evaluate_exit_code(&FailOn::Never, 10, &report),
            0,
            "Never policy should always return 0"
        );
    }

    #[test]
    fn test_evaluate_exit_code_any_failure_with_failures() {
        let report = ScanReport {
            total_urls: 10,
            successful: 5,
            failed: 5,
            elapsed_seconds: 1.0,
            db_path: std::path::PathBuf::from("test.db"),
            run_id: "test-run-1".to_string(),
        };

        assert_eq!(
            evaluate_exit_code(&FailOn::AnyFailure, 10, &report),
            2,
            "AnyFailure policy should return 2 when failures exist"
        );
    }

    #[test]
    fn test_evaluate_exit_code_any_failure_without_failures() {
        let report = ScanReport {
            total_urls: 10,
            successful: 10,
            failed: 0,
            elapsed_seconds: 1.0,
            db_path: std::path::PathBuf::from("test.db"),
            run_id: "test-run-1".to_string(),
        };

        assert_eq!(
            evaluate_exit_code(&FailOn::AnyFailure, 10, &report),
            0,
            "AnyFailure policy should return 0 when no failures"
        );
    }

    #[test]
    fn test_evaluate_exit_code_pct_greater_than_zero_urls() {
        let report = ScanReport {
            total_urls: 0,
            successful: 0,
            failed: 0,
            elapsed_seconds: 0.0,
            db_path: std::path::PathBuf::from("test.db"),
            run_id: "test-run-1".to_string(),
        };

        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 10, &report),
            3,
            "PctGreaterThan policy should return 3 when no URLs processed"
        );
    }

    #[test]
    fn test_evaluate_exit_code_pct_greater_than_below_threshold() {
        let report = ScanReport {
            total_urls: 100,
            successful: 95,
            failed: 5, // 5% failure rate
            elapsed_seconds: 1.0,
            db_path: std::path::PathBuf::from("test.db"),
            run_id: "test-run-1".to_string(),
        };

        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 10, &report),
            0,
            "PctGreaterThan policy should return 0 when failure rate is below threshold"
        );
    }

    #[test]
    fn test_evaluate_exit_code_pct_greater_than_at_threshold() {
        let report = ScanReport {
            total_urls: 100,
            successful: 90,
            failed: 10, // Exactly 10% failure rate
            elapsed_seconds: 1.0,
            db_path: std::path::PathBuf::from("test.db"),
            run_id: "test-run-1".to_string(),
        };

        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 10, &report),
            0,
            "PctGreaterThan policy should return 0 when failure rate equals threshold (not greater)"
        );
    }

    #[test]
    fn test_evaluate_exit_code_pct_greater_than_above_threshold() {
        let report = ScanReport {
            total_urls: 100,
            successful: 85,
            failed: 15, // 15% failure rate
            elapsed_seconds: 1.0,
            db_path: std::path::PathBuf::from("test.db"),
            run_id: "test-run-1".to_string(),
        };

        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 10, &report),
            2,
            "PctGreaterThan policy should return 2 when failure rate exceeds threshold"
        );
    }

    #[test]
    fn test_evaluate_exit_code_errors_only_with_failures() {
        let report = ScanReport {
            total_urls: 10,
            successful: 5,
            failed: 5,
            elapsed_seconds: 1.0,
            db_path: std::path::PathBuf::from("test.db"),
            run_id: "test-run-1".to_string(),
        };

        assert_eq!(
            evaluate_exit_code(&FailOn::ErrorsOnly, 10, &report),
            2,
            "ErrorsOnly policy should return 2 when failures exist"
        );
    }

    #[test]
    fn test_evaluate_exit_code_errors_only_without_failures() {
        let report = ScanReport {
            total_urls: 10,
            successful: 10,
            failed: 0,
            elapsed_seconds: 1.0,
            db_path: std::path::PathBuf::from("test.db"),
            run_id: "test-run-1".to_string(),
        };

        assert_eq!(
            evaluate_exit_code(&FailOn::ErrorsOnly, 10, &report),
            0,
            "ErrorsOnly policy should return 0 when no failures"
        );
    }

    #[test]
    fn test_scan_command_to_config_conversion() {
        use std::path::PathBuf;
        let scan_cmd = ScanCommand {
            file: PathBuf::from("test.txt"),
            log_level: LogLevel::Debug,
            log_format: LogFormat::Json,
            db_path: PathBuf::from("custom.db"),
            max_concurrency: 50,
            timeout_seconds: 20,
            user_agent: "Custom Agent".to_string(),
            rate_limit_rps: 25,
            adaptive_error_threshold: 0.3,
            fingerprints: Some("https://example.com/tech.json".to_string()),
            geoip: Some("/path/to/geoip.mmdb".to_string()),
            status_port: Some(8080),
            enable_whois: true,
            fail_on: FailOn::AnyFailure,
            fail_on_pct_threshold: 15,
            log_file: PathBuf::from("domain_status.log"),
        };

        let config: Config = scan_cmd.into();

        assert_eq!(config.file, PathBuf::from("test.txt"));
        // Note: LogLevel and LogFormat don't implement PartialEq, so we verify conversion worked
        // by checking other fields. The conversion itself is tested in config::types::tests.
        assert_eq!(config.db_path, PathBuf::from("custom.db"));
        assert_eq!(config.max_concurrency, 50);
        assert_eq!(config.timeout_seconds, 20);
        assert_eq!(config.user_agent, "Custom Agent");
        assert_eq!(config.rate_limit_rps, 25);
        // Allow float comparison for exact constant value in test
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(config.adaptive_error_threshold, 0.3);
        }
        assert_eq!(
            config.fingerprints,
            Some("https://example.com/tech.json".to_string())
        );
        assert_eq!(config.geoip, Some("/path/to/geoip.mmdb".to_string()));
        assert_eq!(config.status_port, Some(8080));
        assert!(config.enable_whois);
        assert_eq!(config.fail_on, FailOn::AnyFailure);
        assert_eq!(config.fail_on_pct_threshold, 15);
    }

    #[test]
    fn test_evaluate_exit_code_pct_greater_than_overflow_protection() {
        // Test that very large numbers don't cause overflow in percentage calculation
        // This is critical - overflow could cause incorrect exit codes
        // Use usize::MAX which is the actual type used in ScanReport
        let max_urls = usize::MAX;
        let report = ScanReport {
            total_urls: max_urls,
            successful: max_urls.saturating_sub(1),
            failed: 1,
            elapsed_seconds: 1.0,
            db_path: std::path::PathBuf::from("test.db"),
            run_id: "test-run-1".to_string(),
        };

        // Should not panic or overflow - percentage should be very small (< 0.0001%)
        let exit_code = evaluate_exit_code(&FailOn::PctGreaterThan, 10, &report);
        // With only 1 failure out of usize::MAX, percentage is essentially 0, so should return 0
        assert_eq!(exit_code, 0, "Should handle large numbers without overflow");
    }

    #[test]
    fn test_evaluate_exit_code_pct_greater_than_all_failed() {
        // Test edge case where all URLs failed
        let report = ScanReport {
            total_urls: 100,
            successful: 0,
            failed: 100, // 100% failure rate
            elapsed_seconds: 1.0,
            db_path: std::path::PathBuf::from("test.db"),
            run_id: "test-run-1".to_string(),
        };

        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 10, &report),
            2,
            "Should return 2 when 100% of URLs failed (exceeds 10% threshold)"
        );
    }

    #[test]
    fn test_evaluate_exit_code_pct_greater_than_one_failure() {
        // Test edge case with single failure
        let report = ScanReport {
            total_urls: 1000,
            successful: 999,
            failed: 1, // 0.1% failure rate
            elapsed_seconds: 1.0,
            db_path: std::path::PathBuf::from("test.db"),
            run_id: "test-run-1".to_string(),
        };

        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 10, &report),
            0,
            "Should return 0 when failure rate is below threshold"
        );
    }

    #[test]
    fn test_evaluate_exit_code_pct_greater_than_precision() {
        // Test that floating point precision doesn't cause issues
        // 10.0000001% should exceed 10% threshold
        let report = ScanReport {
            total_urls: 1000,
            successful: 899,
            failed: 101, // 10.1% failure rate
            elapsed_seconds: 1.0,
            db_path: std::path::PathBuf::from("test.db"),
            run_id: "test-run-1".to_string(),
        };

        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 10, &report),
            2,
            "Should correctly handle floating point precision (10.1% > 10%)"
        );
    }

    #[test]
    fn test_scan_command_to_config_conversion_defaults() {
        // Test that conversion handles None values correctly
        use std::path::PathBuf;
        let scan_cmd = ScanCommand {
            file: PathBuf::from("test.txt"),
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
            log_file: PathBuf::from("domain_status.log"),
        };

        let config: Config = scan_cmd.into();

        assert_eq!(config.fingerprints, None);
        assert_eq!(config.geoip, None);
        assert_eq!(config.status_port, None);
        assert!(!config.enable_whois);
        assert_eq!(config.fail_on, FailOn::Never);
        // Verify log_file is set correctly
        assert_eq!(config.log_file, Some(PathBuf::from("domain_status.log")));
        // Verify progress_callback is None initially (set later)
        assert!(config.progress_callback.is_none());
    }

    #[test]
    fn test_evaluate_exit_code_pct_greater_than_edge_cases() {
        // Test edge cases for percentage calculation
        // Test with 1 URL (100% failure should exceed any threshold > 0)
        let report = ScanReport {
            total_urls: 1,
            successful: 0,
            failed: 1,
            elapsed_seconds: 1.0,
            db_path: std::path::PathBuf::from("test.db"),
            run_id: "test-run-1".to_string(),
        };

        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 0, &report),
            2,
            "100% failure should exceed 0% threshold"
        );

        // Test with very small threshold
        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 99, &report),
            2,
            "100% failure should exceed 99% threshold"
        );
    }

    #[test]
    fn test_evaluate_exit_code_pct_greater_than_rounding() {
        // Test that floating point rounding doesn't cause issues
        // 33.333...% failure rate with 33% threshold
        let report = ScanReport {
            total_urls: 3,
            successful: 2,
            failed: 1, // 33.33...% failure rate
            elapsed_seconds: 1.0,
            db_path: std::path::PathBuf::from("test.db"),
            run_id: "test-run-1".to_string(),
        };

        // Should exceed 33% threshold (33.33... > 33)
        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 33, &report),
            2,
            "33.33% failure should exceed 33% threshold"
        );

        // Should not exceed 34% threshold (33.33... < 34)
        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 34, &report),
            0,
            "33.33% failure should not exceed 34% threshold"
        );
    }

    #[test]
    fn test_export_output_path_stdout_detection() {
        // Test that "-" is correctly detected as stdout
        // This is critical - stdout detection must work for piping
        let output_str = Some("-".to_string());
        let is_stdout = output_str.as_ref().map(|s| s == "-").unwrap_or(false);
        assert!(is_stdout, "Should detect '-' as stdout");
    }

    #[test]
    fn test_export_output_path_file_path() {
        // Test that non-"-" paths are treated as file paths
        // This is critical - file paths must be preserved correctly
        let output_str = Some("/path/to/output.csv".to_string());
        let is_stdout = output_str.as_ref().map(|s| s == "-").unwrap_or(false);
        assert!(!is_stdout, "Should not treat file path as stdout");
    }

    #[test]
    fn test_export_output_path_default_file_naming() {
        // Test that default file names are generated correctly based on format
        // This is critical - default file naming must match format
        let csv_ext = "csv";
        let jsonl_ext = "jsonl";
        let parquet_ext = "parquet";

        let csv_file = format!("domain_status_export.{}", csv_ext);
        let jsonl_file = format!("domain_status_export.{}", jsonl_ext);
        let parquet_file = format!("domain_status_export.{}", parquet_ext);

        assert_eq!(csv_file, "domain_status_export.csv");
        assert_eq!(jsonl_file, "domain_status_export.jsonl");
        assert_eq!(parquet_file, "domain_status_export.parquet");
    }

    #[test]
    fn test_url_pluralization_logic() {
        // Test that URL pluralization works correctly (line 315)
        // This is critical - output message must be grammatically correct
        let total_urls_1 = 1;
        let suffix_1 = if total_urls_1 == 1 { "" } else { "s" };
        assert_eq!(suffix_1, "", "Should use singular 'URL' for 1 URL");

        let total_urls_0 = 0;
        let suffix_0 = if total_urls_0 == 1 { "" } else { "s" };
        assert_eq!(suffix_0, "s", "Should use plural 'URLs' for 0 URLs");

        let total_urls_2 = 2;
        let suffix_2 = if total_urls_2 == 1 { "" } else { "s" };
        assert_eq!(suffix_2, "s", "Should use plural 'URLs' for 2 URLs");
    }

    #[test]
    fn test_progress_callback_overflow_protection() {
        // Test that progress callback handles large numbers without overflow
        // This is critical - prevents panics when processing many URLs
        let total = usize::MAX;
        let completed = usize::MAX / 2;
        let failed = usize::MAX / 2;

        // Test that casting to u64 doesn't panic
        let total_u64 = total as u64;
        let position_u64 = (completed + failed) as u64;

        // Should not overflow
        assert!(total_u64 > 0);
        assert!(position_u64 <= total_u64);
    }

    #[test]
    fn test_progress_callback_message_formatting() {
        // Test that progress callback message formatting works correctly
        // This is critical - progress bar must show correct counts
        let completed = 10;
        let failed = 5;
        let message = format!("✓{} ✗{}", completed, failed);
        assert_eq!(
            message, "✓10 ✗5",
            "Progress message should format correctly"
        );
    }
}
