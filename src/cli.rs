//! CLI parsing and command execution.

use anyhow::{Context, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::config::{FailOn, LogFormat, LogLevel, DEFAULT_USER_AGENT};
use crate::export::{export_csv, ExportOptions};
use crate::initialization::{init_crypto_provider, init_logger_to_file, init_logger_with};
use crate::{run_scan, Config, ScanReport};

/// CLI-specific configuration with clap parsing.
#[derive(Debug, Parser, Clone)]
#[command(
    name = "domain_status",
    about = "Domain intelligence scanner - scan URLs and export results.",
    version = env!("CARGO_PKG_VERSION"),
    long_version = env!("CARGO_PKG_VERSION"),
    subcommand_required = true
)]
pub enum CliCommand {
    /// Scan URLs and store results in `SQLite` database.
    #[command(name = "scan")]
    Scan(ScanCommand),
    /// Export data from `SQLite` database to various formats.
    #[command(name = "export")]
    Export(ExportCommand),
}

/// CLI scan command.
#[derive(Debug, Parser, Clone)]
pub struct ScanCommand {
    /// File to read
    #[arg(value_parser)]
    pub file: PathBuf,

    /// Log level: error|warn|info|debug|trace
    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    /// Log format: plain|json
    #[arg(long, value_enum, default_value_t = LogFormat::Plain)]
    pub log_format: LogFormat,

    /// Database path (`SQLite` file)
    #[arg(long, value_parser, default_value = "./domain_status.db")]
    pub db_path: PathBuf,

    /// Maximum concurrent requests
    #[arg(long, default_value_t = 30)]
    pub max_concurrency: usize,

    /// Per-request timeout in seconds
    #[arg(long, default_value_t = 10)]
    pub timeout_seconds: u64,

    /// HTTP User-Agent header value.
    #[arg(long, default_value = DEFAULT_USER_AGENT)]
    pub user_agent: String,

    /// Initial requests per second (adaptive rate limiting always enabled)
    #[arg(long, default_value_t = 15)]
    pub rate_limit_rps: u32,

    /// Maximum concurrent requests per registered domain.
    #[arg(long, default_value_t = 5)]
    pub max_per_domain: usize,

    /// Error rate threshold for adaptive rate limiting (0.0-1.0, default: 0.2 = 20%)
    #[arg(long, default_value_t = 0.2, hide = true)]
    pub adaptive_error_threshold: f64,

    /// Fingerprints source URL or local path.
    #[arg(long)]
    pub fingerprints: Option<String>,

    /// `GeoIP` database path (`MaxMind` `GeoLite2` .mmdb file) or download URL.
    #[arg(long)]
    pub geoip: Option<String>,

    /// HTTP status server port (optional, disabled by default)
    #[arg(long)]
    pub status_port: Option<u16>,

    /// Enable WHOIS/RDAP lookup for domain registration information.
    #[arg(long)]
    pub enable_whois: bool,

    /// Exit code policy for handling failures.
    #[arg(long, value_enum, default_value_t = FailOn::Never)]
    pub fail_on: FailOn,

    /// Failure percentage threshold for `--fail-on pct>X`.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u8).range(0..=100))]
    pub fail_on_pct_threshold: u8,

    /// Log file path for detailed logging.
    #[arg(long, default_value = "domain_status.log")]
    pub log_file: PathBuf,
}

/// CLI export command.
#[derive(Debug, Parser, Clone)]
pub struct ExportCommand {
    /// Database path (`SQLite` file)
    #[arg(long, value_parser, default_value = "./domain_status.db")]
    pub db_path: PathBuf,

    /// Export format: csv|jsonl|parquet
    #[arg(long, value_enum, default_value = "csv")]
    pub format: ExportFormat,

    /// Output file path
    #[arg(long)]
    pub output: Option<String>,

    /// Filter by run ID
    #[arg(long)]
    pub run_id: Option<String>,

    /// Filter by domain (matches initial or final domain)
    #[arg(long)]
    pub domain: Option<String>,

    /// Filter by HTTP status code
    #[arg(long)]
    pub status: Option<u16>,

    /// Filter by timestamp (export records after this timestamp, in milliseconds since epoch)
    #[arg(long)]
    pub since: Option<i64>,
}

/// CLI export format.
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum ExportFormat {
    /// CSV export.
    Csv,
    /// JSONL export.
    Jsonl,
    /// Parquet export.
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
            max_per_domain: cli.max_per_domain,
            adaptive_error_threshold: cli.adaptive_error_threshold,
            fingerprints: cli.fingerprints,
            geoip: cli.geoip,
            status_port: cli.status_port,
            enable_whois: cli.enable_whois,
            fail_on: cli.fail_on,
            fail_on_pct_threshold: cli.fail_on_pct_threshold,
            log_file: Some(cli.log_file),
            progress_callback: None,
        }
    }
}

/// Parse CLI arguments using the real clap configuration.
///
/// # Errors
/// Returns `Err` when argument parsing fails (e.g. invalid or missing required options).
pub fn parse_cli_command_from<I, T>(args: I) -> Result<CliCommand, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    CliCommand::try_parse_from(args)
}

/// Loads environment variables from `.env` file if it exists.
pub fn load_environment() {
    if dotenvy::dotenv().is_err() {
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let env_path = exe_dir.join(".env");
                if env_path.exists() {
                    if let Err(e) = dotenvy::from_path(&env_path) {
                        let scrubbed_name = crate::security::redaction::scrub_path(&env_path);
                        eprintln!(
                            "Warning: Failed to load {scrubbed_name} near the executable: {e}"
                        );
                    }
                }
            }
        }
    }
}

fn init_scan_logging(log_level: &LogLevel, log_file: &Path) -> Result<()> {
    init_logger_to_file(log_level.clone().into(), log_file)
        .context("Failed to initialize file logger")?;
    eprintln!("📝 Logs: {}", log_file.display());
    log::info!("domain_status version {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}

fn create_progress_bar() -> Result<Arc<ProgressBar>> {
    let pb = Arc::new(ProgressBar::new(0));
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}",
            )
            .context("Failed to create progress bar template")?
            .progress_chars("█▓░"),
    );
    pb.enable_steady_tick(Duration::from_millis(100));
    Ok(pb)
}

fn create_progress_callback(
    pb: Arc<ProgressBar>,
) -> Arc<dyn Fn(usize, usize, usize) + Send + Sync> {
    Arc::new(move |completed, failed, total| {
        pb.set_length(total as u64);
        pb.set_position((completed + failed) as u64);
        pb.set_message(format!("✓{} ✗{}", completed, failed));
    })
}

async fn execute_scan_with_reporting(mut config: Config) -> Result<i32> {
    let log_file = config
        .log_file
        .as_ref()
        .context("Configuration error: log_file not set")?;
    init_scan_logging(&config.log_level, log_file)?;

    let pb = create_progress_bar()?;
    config.progress_callback = Some(create_progress_callback(Arc::clone(&pb)));
    init_crypto_provider();

    let report = run_scan(config.clone()).await?;
    println!(
        "✅ Processed {} URL{} ({} succeeded, {} failed) in {:.1}s - see database for details",
        report.total_urls,
        if report.total_urls == 1 { "" } else { "s" },
        report.successful,
        report.failed,
        report.elapsed_seconds
    );
    println!("Results saved in {}", report.db_path.display());
    println!(
        "💡 Tip: Use `domain_status export --format csv` to export data, or query the database directly."
    );

    Ok(evaluate_exit_code(
        &config.fail_on,
        config.fail_on_pct_threshold,
        &report,
    ))
}

async fn execute_export_command(export_cmd: ExportCommand) -> Result<i32> {
    init_logger_with(LogLevel::Info.into(), LogFormat::Plain)
        .context("Failed to initialize logger")?;
    log::info!("domain_status version {}", env!("CARGO_PKG_VERSION"));

    let output_path = if let Some(ref path_str) = export_cmd.output {
        if path_str == "-" {
            None
        } else {
            Some(PathBuf::from(path_str))
        }
    } else {
        let extension = match export_cmd.format {
            ExportFormat::Csv => "csv",
            ExportFormat::Jsonl => "jsonl",
            ExportFormat::Parquet => "parquet",
        };
        Some(PathBuf::from(format!("domain_status_export.{}", extension)))
    };

    let lib_format = match export_cmd.format {
        ExportFormat::Csv => crate::export::ExportFormat::Csv,
        ExportFormat::Jsonl => crate::export::ExportFormat::Jsonl,
        ExportFormat::Parquet => crate::export::ExportFormat::Parquet,
    };

    let export_opts = ExportOptions {
        db_path: export_cmd.db_path.clone(),
        output: output_path.clone(),
        format: lib_format,
        run_id: export_cmd.run_id.clone(),
        domain: export_cmd.domain.clone(),
        status: export_cmd.status,
        since: export_cmd.since,
    };

    let (count, format_name) = match export_cmd.format {
        ExportFormat::Csv => (
            export_csv(&export_opts)
                .await
                .context("Failed to export CSV")?,
            "CSV",
        ),
        ExportFormat::Jsonl => (
            crate::export::export_jsonl(&export_opts)
                .await
                .context("Failed to export JSONL")?,
            "JSONL",
        ),
        ExportFormat::Parquet => (
            crate::export::export_parquet(&export_opts)
                .await
                .context("Failed to export Parquet")?,
            "Parquet",
        ),
    };

    if let Some(ref path) = output_path {
        eprintln!("✅ Exported {} records to {}", count, path.display());
    } else {
        eprintln!("✅ Exported {} records to {}", count, format_name);
    }

    Ok(0)
}

/// Execute a parsed CLI command and return the intended process exit code.
///
/// # Errors
/// Returns `Err` when scan or export execution fails (I/O, database, or runtime errors).
pub async fn run_cli_command(cli_command: CliCommand) -> Result<i32> {
    match cli_command {
        CliCommand::Scan(scan_cmd) => execute_scan_with_reporting(scan_cmd.into()).await,
        CliCommand::Export(export_cmd) => execute_export_command(export_cmd).await,
    }
}

/// Load environment, parse CLI args, and execute the command.
///
/// # Errors
/// Returns `Err` when argument parsing fails or when the executed command fails.
pub async fn run_cli_from_args<I, T>(args: I) -> Result<i32>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    load_environment();
    let cli_command = parse_cli_command_from(args)?;
    run_cli_command(cli_command).await
}

/// Evaluates the numeric exit code for a completed scan.
///
/// Return values:
///
/// - `0` for success
/// - `2` when the selected failure policy is exceeded
/// - `3` when `FailOn::PctGreaterThan` was selected but zero URLs were processed
///
/// Command/runtime failures that occur before a [`ScanReport`] exists are handled
/// elsewhere and typically surface as process exit code `1`.
///
/// # Examples
///
/// ```
/// use domain_status::{evaluate_exit_code, FailOn, ScanReport};
/// use std::path::PathBuf;
///
/// let report = ScanReport {
///     run_id: "run_1".to_string(),
///     total_urls: 10,
///     successful: 8,
///     failed: 2,
///     elapsed_seconds: 1.5,
///     db_path: PathBuf::from("./domain_status.db"),
/// };
///
/// assert_eq!(evaluate_exit_code(&FailOn::Never, 10, &report), 0);
/// assert_eq!(evaluate_exit_code(&FailOn::AnyFailure, 10, &report), 2);
/// assert_eq!(evaluate_exit_code(&FailOn::PctGreaterThan, 10, &report), 2);
/// ```
#[must_use]
pub fn evaluate_exit_code(fail_on: &FailOn, pct_threshold: u8, report: &ScanReport) -> i32 {
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
                return 3;
            }
            #[allow(clippy::cast_precision_loss)]
            let failure_pct = (report.failed as f64 / report.total_urls as f64) * 100.0;
            if failure_pct > f64::from(pct_threshold) {
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
    use pretty_assertions::assert_eq;

    fn sample_report(total_urls: usize, successful: usize, failed: usize) -> ScanReport {
        ScanReport {
            total_urls,
            successful,
            failed,
            elapsed_seconds: 1.0,
            db_path: PathBuf::from("test.db"),
            run_id: "test-run-1".to_string(),
        }
    }

    #[test]
    fn test_parse_real_scan_command_defaults() {
        let cli = parse_cli_command_from(["domain_status", "scan", "test.txt"]).unwrap();

        match cli {
            CliCommand::Scan(cmd) => {
                assert_eq!(cmd.file, PathBuf::from("test.txt"));
                assert_eq!(cmd.max_concurrency, 30);
                assert_eq!(cmd.fail_on, FailOn::Never);
                assert_eq!(cmd.db_path, PathBuf::from("./domain_status.db"));
            }
            CliCommand::Export(_) => panic!("expected scan command"),
        }
    }

    #[test]
    fn test_parse_real_export_command_filters() {
        let cli = parse_cli_command_from([
            "domain_status",
            "export",
            "--format",
            "jsonl",
            "--run-id",
            "run_123",
            "--domain",
            "example.com",
            "--status",
            "200",
            "--output",
            "out.jsonl",
        ])
        .unwrap();

        match cli {
            CliCommand::Export(cmd) => {
                assert_eq!(cmd.run_id.as_deref(), Some("run_123"));
                assert_eq!(cmd.domain.as_deref(), Some("example.com"));
                assert_eq!(cmd.status, Some(200));
                assert_eq!(cmd.output.as_deref(), Some("out.jsonl"));
                assert!(matches!(cmd.format, ExportFormat::Jsonl));
            }
            CliCommand::Scan(_) => panic!("expected export command"),
        }
    }

    #[test]
    fn test_scan_command_into_config_preserves_fields() {
        let scan_cmd = ScanCommand {
            file: PathBuf::from("test.txt"),
            log_level: LogLevel::Debug,
            log_format: LogFormat::Json,
            db_path: PathBuf::from("custom.db"),
            max_concurrency: 50,
            timeout_seconds: 20,
            user_agent: "Custom Agent".to_string(),
            rate_limit_rps: 25,
            max_per_domain: 3,
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
        assert_eq!(config.db_path, PathBuf::from("custom.db"));
        assert_eq!(config.max_concurrency, 50);
        assert_eq!(config.timeout_seconds, 20);
        assert_eq!(config.user_agent, "Custom Agent");
        assert_eq!(config.rate_limit_rps, 25);
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
    fn test_evaluate_exit_code_real_logic() {
        assert_eq!(
            evaluate_exit_code(&FailOn::Never, 10, &sample_report(10, 5, 5)),
            0
        );
        assert_eq!(
            evaluate_exit_code(&FailOn::AnyFailure, 10, &sample_report(10, 5, 5)),
            2
        );
        assert_eq!(
            evaluate_exit_code(&FailOn::AnyFailure, 10, &sample_report(10, 10, 0)),
            0
        );
        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 10, &sample_report(0, 0, 0)),
            3
        );
        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 10, &sample_report(100, 95, 5)),
            0
        );
        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 10, &sample_report(100, 89, 11)),
            2
        );
    }

    #[test]
    fn test_evaluate_exit_code_large_counts_do_not_overflow() {
        let max_urls = usize::MAX;
        let report = sample_report(max_urls, max_urls.saturating_sub(1), 1);
        assert_eq!(evaluate_exit_code(&FailOn::PctGreaterThan, 10, &report), 0);
    }
}
