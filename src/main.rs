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
use std::path::PathBuf;
use std::process;

use domain_status::config::{FailOn, LogFormat, LogLevel, DEFAULT_USER_AGENT};
use domain_status::export::export_csv;
use domain_status::initialization::{init_crypto_provider, init_logger_with};
use domain_status::{run_scan, Config};

/// CLI-specific configuration with clap parsing.
///
/// This struct is used only in the CLI binary and includes clap attributes
/// for command-line argument parsing. It can be converted to the library `Config` type.
#[derive(Debug, Parser, Clone)]
#[command(
    name = "domain_status",
    about = "Domain intelligence scanner - scan URLs and export results.",
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

    /// Show detailed timing metrics at the end of the run
    ///
    /// When enabled, displays a breakdown of time spent in each operation:
    /// - HTTP requests
    /// - DNS lookups
    /// - TLS handshakes
    /// - Technology detection
    /// - HTML parsing
    /// - Enrichment operations
    ///
    /// Useful for performance analysis and identifying bottlenecks.
    /// Disabled by default to reduce output noise.
    #[arg(long)]
    show_timing: bool,

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
}

#[derive(Debug, Parser, Clone)]
struct ExportCommand {
    /// Database path (SQLite file)
    #[arg(long, value_parser, default_value = "./domain_status.db")]
    db_path: PathBuf,

    /// Export format: csv|jsonl|parquet
    #[arg(long, value_enum, default_value = "csv")]
    format: ExportFormat,

    /// Output file path (or stdout if not specified)
    #[arg(long, value_parser)]
    output: Option<PathBuf>,

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
            show_timing: cli.show_timing,
            fail_on: cli.fail_on,
            fail_on_pct_threshold: cli.fail_on_pct_threshold,
        }
    }
}

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

    // Parse command-line arguments
    let cli_command = CliCommand::parse();

    match cli_command {
        CliCommand::Scan(scan_cmd) => {
            let config: Config = scan_cmd.into();

            // Initialize logger based on config
            let log_level = config.log_level.clone();
            let log_format = config.log_format.clone();
            init_logger_with(log_level.into(), log_format)
                .context("Failed to initialize logger")?;

            // Initialize crypto provider for TLS operations
            init_crypto_provider();

            // Run the scan using the library
            match run_scan(config.clone()).await {
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

                    // Evaluate exit code based on --fail-on policy
                    let exit_code =
                        evaluate_exit_code(&config.fail_on, config.fail_on_pct_threshold, &report);
                    if exit_code != 0 {
                        process::exit(exit_code);
                    }
                    Ok(())
                }
                Err(e) => {
                    eprintln!("domain_status error: {:#}", e);
                    process::exit(1); // Configuration error or scan initialization failure
                }
            }
        }
        CliCommand::Export(export_cmd) => {
            // Handle export command
            // Initialize logger for export command
            let log_level = LogLevel::Info;
            let log_format = LogFormat::Plain;
            init_logger_with(log_level.into(), log_format)
                .context("Failed to initialize logger")?;

            // Handle export format
            match export_cmd.format {
                ExportFormat::Csv => {
                    let count = export_csv(
                        &export_cmd.db_path,
                        export_cmd.output.as_ref(),
                        export_cmd.run_id.as_deref(),
                        export_cmd.domain.as_deref(),
                        export_cmd.status,
                        export_cmd.since,
                    )
                    .await
                    .context("Failed to export CSV")?;
                    println!("✅ Exported {} records to CSV", count);
                    Ok(())
                }
                ExportFormat::Jsonl => {
                    eprintln!("JSONL export not yet implemented");
                    process::exit(1);
                }
                ExportFormat::Parquet => {
                    eprintln!("Parquet export not yet implemented");
                    process::exit(1);
                }
            }
        }
    }
}

/// Evaluates the exit code based on the failure policy and scan results.
///
/// Returns:
/// - 0: Success (or failures ignored by policy)
/// - 2: Failures exceeded threshold (based on --fail-on policy)
/// - 3: Partial success (some URLs processed, but scan incomplete)
fn evaluate_exit_code(
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
