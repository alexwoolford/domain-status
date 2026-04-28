//! CLI parsing and command execution.
//!
//! CLI definition lives in the `domain_status_cli` crate (single source of truth
//! for build.rs completions and man page). We parse with that crate and convert to
//! [`Config`] and export types as needed.

use std::io;

use anyhow::{Context, Result};
use clap_complete::Shell;
use clap_mangen::Man;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::parser::ValueSource;
use clap::{FromArgMatches, Parser};
use domain_status_cli::{
    ExportFormat as CliExportFormat, FailOn as CliFailOn, LogFormat as CliLogFormat,
    LogLevel as CliLogLevel,
};

use crate::config::{FailOn, LogFormat, LogLevel};
use crate::export::{export_csv, ExportOptions};
use crate::initialization::{init_crypto_provider, init_logger_to_file, init_logger_with};
use crate::utils::warn_if_world_readable;
use crate::{run_scan, Config, ScanReport};

// Re-export CLI types so existing tests and callers can use the same names.
pub use domain_status_cli::{CliCommand, ExportCommand, ExportFormat, ScanCommand};

fn log_level_cli_to_config(l: &CliLogLevel) -> LogLevel {
    match l {
        CliLogLevel::Error => LogLevel::Error,
        CliLogLevel::Warn => LogLevel::Warn,
        CliLogLevel::Info => LogLevel::Info,
        CliLogLevel::Debug => LogLevel::Debug,
        CliLogLevel::Trace => LogLevel::Trace,
    }
}

fn log_format_cli_to_config(f: CliLogFormat) -> LogFormat {
    match f {
        CliLogFormat::Plain => LogFormat::Plain,
        CliLogFormat::Json => LogFormat::Json,
    }
}

fn fail_on_cli_to_config(f: &CliFailOn) -> FailOn {
    match f {
        CliFailOn::Never => FailOn::Never,
        CliFailOn::AnyFailure => FailOn::AnyFailure,
        CliFailOn::PctGreaterThan => FailOn::PctGreaterThan,
    }
}

fn config_from_scan_command(cli: ScanCommand) -> Config {
    let log_level_filter_override =
        Some(cli.verbosity.log_level_filter()).filter(|f| *f != log::LevelFilter::Info);
    Config {
        file: cli.file,
        log_level: log_level_cli_to_config(&cli.log_level),
        log_format: log_format_cli_to_config(cli.log_format),
        log_level_filter_override,
        db_path: cli.db_path,
        max_concurrency: cli.max_concurrency,
        timeout_seconds: cli.timeout_seconds,
        user_agent: cli.user_agent,
        rate_limit_rps: cli.rate_limit_rps,
        fingerprints: cli.fingerprints,
        geoip: cli.geoip,
        status_port: cli.status_port,
        enable_whois: cli.enable_whois,
        scan_external_scripts: cli.scan_external_scripts,
        fail_on: fail_on_cli_to_config(&cli.fail_on),
        fail_on_pct_threshold: cli.fail_on_pct_threshold,
        log_file: Some(cli.log_file),
        progress_callback: None,
        dependency_overrides: None,
        allow_localhost_for_tests: false,
        drain_timeout_secs: cli.drain_timeout_secs,
    }
}

/// Parse CLI arguments using the shared CLI definition.
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

/// Loads config from optional file and env vars with prefix `DOMAIN_STATUS_`.
///
/// Precedence when merging later: CLI > env > file > defaults.
/// Returns `Ok(None)` when no config file is requested and no default file exists.
///
/// # Errors
/// Fails when a requested config file is missing or invalid.
fn load_file_env_config(
    explicit_config_path: Option<&Path>,
) -> Result<Option<HashMap<String, String>>> {
    let config_name = std::env::var("DOMAIN_STATUS_CONFIG_FILE")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| explicit_config_path.map(Path::to_path_buf));

    let mut builder = config::Config::builder();

    if let Some(ref path) = config_name {
        warn_if_world_readable(path);
        let path_str = path.to_string_lossy();
        builder = builder.add_source(config::File::with_name(path_str.as_ref()).required(true));
    } else if Path::new("domain_status.toml").exists() {
        builder = builder.add_source(config::File::with_name("domain_status").required(false));
    } else {
        // No file source; env-only is still useful
    }

    builder = builder.add_source(config::Environment::with_prefix("DOMAIN_STATUS"));

    match builder.build() {
        Ok(settings) => match settings.try_deserialize::<HashMap<String, String>>() {
            Ok(map) => Ok(Some(map)),
            Err(e) => Err(anyhow::anyhow!("Invalid configuration: {e}")),
        },
        Err(e) => Err(anyhow::anyhow!("Failed to load configuration: {e}")),
    }
}

/// Scan CLI arg ids that correspond to config fields. Used to detect which values
/// were set by the user (command line or env) vs defaulted.
const SCAN_CONFIG_ARG_IDS: &[&str] = &[
    "file",
    "log_level",
    "log_format",
    "db_path",
    "max_concurrency",
    "timeout_seconds",
    "user_agent",
    "rate_limit_rps",
    "fingerprints",
    "geoip",
    "status_port",
    "enable_whois",
    "scan_external_scripts",
    "fail_on",
    "fail_on_pct_threshold",
    "log_file",
];

/// Returns config field names that were explicitly set (command line or env), not defaulted.
fn get_explicit_config_keys(scan_matches: &clap::ArgMatches) -> Vec<&'static str> {
    let mut keys = Vec::new();
    for id in SCAN_CONFIG_ARG_IDS {
        if let Some(src) = scan_matches.value_source(id) {
            if matches!(src, ValueSource::CommandLine | ValueSource::EnvVariable) {
                keys.push(*id);
            }
        }
    }
    // Verbosity (-v/-q) sets log_level_filter_override; check flattened verbosity args.
    for id in ["verbose", "quiet"] {
        if let Some(src) = scan_matches.value_source(id) {
            if matches!(src, ValueSource::CommandLine | ValueSource::EnvVariable) {
                keys.push("log_level_filter_override");
                break;
            }
        }
    }
    keys
}

/// Builds `Config` with precedence: CLI > env > config file > defaults.
/// When `scan_arg_matches` is `Some`, only fields explicitly set by the user (CLI or env)
/// overwrite file+env; others keep file/env values. When `None`, all CLI-derived values
/// overwrite (backward compatible).
fn build_config_from_scan_command(
    scan_cmd: ScanCommand,
    scan_arg_matches: Option<&clap::ArgMatches>,
) -> Result<Config> {
    let file_env_map = load_file_env_config(scan_cmd.config.as_deref())?;
    let cli_config = config_from_scan_command(scan_cmd);
    let cli_explicit = scan_arg_matches.map(get_explicit_config_keys);
    let explicit_slice = cli_explicit.as_deref();
    Ok(crate::config::merge_file_env_and_cli(
        file_env_map.as_ref(),
        cli_config,
        explicit_slice,
    ))
}

/// Loads environment variables from `.env` file if it exists.
pub fn load_environment() {
    if dotenvy::dotenv().is_err() {
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let env_path = exe_dir.join(".env");
                if env_path.exists() {
                    if let Err(e) = dotenvy::from_path(&env_path) {
                        eprintln!("Warning: Failed to load {}: {e}", env_path.display());
                    }
                }
            }
        }
    }
}

fn init_scan_logging(
    log_level: &LogLevel,
    log_file: &Path,
    log_level_override: Option<log::LevelFilter>,
) -> Result<()> {
    let level = log_level_override.unwrap_or_else(|| log_level.clone().into());
    init_logger_to_file(level, log_file).context("Failed to initialize file logger")?;
    eprintln!("📝 Logs: {}", log_file.display());
    log::info!("domain_status version {}", env!("DOMAIN_STATUS_VERSION"));
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
) -> Arc<dyn Fn(usize, usize, usize, usize) + Send + Sync> {
    Arc::new(move |completed, failed, skipped, total| {
        pb.set_length(total as u64);
        pb.set_position((completed + failed + skipped) as u64);
        pb.set_message(format!("✓{completed} ✗{failed} ⊘{skipped}"));
    })
}

async fn execute_scan_with_reporting(mut config: Config) -> Result<i32> {
    let log_file = config
        .log_file
        .as_ref()
        .context("Configuration error: log_file not set")?;
    init_scan_logging(
        &config.log_level,
        log_file,
        config.log_level_filter_override,
    )?;

    let pb = create_progress_bar()?;
    config.progress_callback = Some(create_progress_callback(Arc::clone(&pb)));
    init_crypto_provider();

    let report = run_scan(config.clone())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
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
    log::info!("domain_status version {}", env!("DOMAIN_STATUS_VERSION"));

    let output_path = if let Some(ref path_str) = export_cmd.output {
        if path_str == "-" {
            None
        } else {
            Some(PathBuf::from(path_str))
        }
    } else {
        let extension = match export_cmd.format {
            CliExportFormat::Csv => "csv",
            CliExportFormat::Jsonl => "jsonl",
            CliExportFormat::Parquet => "parquet",
        };
        Some(PathBuf::from(format!("domain_status_export.{extension}")))
    };

    let lib_format = match export_cmd.format {
        CliExportFormat::Csv => crate::export::ExportFormat::Csv,
        CliExportFormat::Jsonl => crate::export::ExportFormat::Jsonl,
        CliExportFormat::Parquet => crate::export::ExportFormat::Parquet,
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
        CliExportFormat::Csv => (
            export_csv(&export_opts)
                .await
                .context("Failed to export CSV")?,
            "CSV",
        ),
        CliExportFormat::Jsonl => (
            crate::export::export_jsonl(&export_opts)
                .await
                .context("Failed to export JSONL")?,
            "JSONL",
        ),
        CliExportFormat::Parquet => (
            crate::export::export_parquet(&export_opts)
                .await
                .context("Failed to export Parquet")?,
            "Parquet",
        ),
    };

    if let Some(ref path) = output_path {
        eprintln!("✅ Exported {} records to {}", count, path.display());
    } else {
        eprintln!("✅ Exported {count} records to {format_name}");
    }

    Ok(0)
}

/// Execute a parsed CLI command and return the intended process exit code.
///
/// When `scan_arg_matches` is `Some`, config merge only overwrites file/env for fields
/// explicitly set by the user (CLI or env). When `None`, all CLI-derived values overwrite.
///
/// # Errors
/// Returns `Err` when scan or export execution fails (I/O, database, or runtime errors).
pub async fn run_cli_command(
    cli_command: CliCommand,
    scan_arg_matches: Option<&clap::ArgMatches>,
) -> Result<i32> {
    match cli_command {
        CliCommand::Scan(scan_cmd) => {
            let config = build_config_from_scan_command(scan_cmd, scan_arg_matches)?;
            execute_scan_with_reporting(config).await
        }
        CliCommand::Export(export_cmd) => execute_export_command(export_cmd).await,
    }
}

/// Load environment, parse CLI args, and execute the command.
///
/// # Errors
/// Returns `Err` when argument parsing fails or when the executed command fails.
///
/// # Panics
/// Panics if the CLI definition has no subcommand (violates `subcommand_required`).
pub async fn run_cli_from_args<I, T>(args: I) -> Result<i32>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    load_environment();
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();

    // Handle --print-completions <shell> and --print-manpage before normal parsing (single source: domain_status_cli)
    if let Some(pos) = args
        .iter()
        .position(|a| a.to_str() == Some("--print-completions"))
    {
        if let Some(shell_arg) = args.get(pos + 1).and_then(|s| s.to_str()) {
            if let Ok(shell) = shell_arg.parse::<Shell>() {
                let mut cmd = domain_status_cli::clap_command(env!("DOMAIN_STATUS_VERSION"));
                clap_complete::generate(shell, &mut cmd, "domain_status", &mut io::stdout());
                return Ok(0);
            }
        }
    }
    if args.iter().any(|a| a.to_str() == Some("--print-manpage")) {
        let cmd = domain_status_cli::clap_command(env!("DOMAIN_STATUS_VERSION"));
        let man = Man::new(cmd);
        man.render(&mut io::stdout())?;
        return Ok(0);
    }

    let matches = match domain_status_cli::clap_command(env!("DOMAIN_STATUS_VERSION"))
        .try_get_matches_from(&args)
    {
        Ok(m) => m,
        Err(e) => {
            let _ = e.print();
            return Ok(e.exit_code());
        }
    };
    let (sub_name, sub_matches) = matches
        .subcommand()
        .expect("subcommand_required and arg_required_else_help guarantee a subcommand");
    let cli_command = match sub_name {
        "scan" => CliCommand::Scan(
            ScanCommand::from_arg_matches(sub_matches).map_err(|e| anyhow::anyhow!("{e}"))?,
        ),
        "export" => CliCommand::Export(
            ExportCommand::from_arg_matches(sub_matches).map_err(|e| anyhow::anyhow!("{e}"))?,
        ),
        _ => unreachable!("only scan and export subcommands exist"),
    };
    let scan_matches = matches.subcommand_matches("scan");
    run_cli_command(cli_command, scan_matches).await
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
///     skipped: 0,
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
    use crate::exit_codes::{EXIT_NO_URLS_PCT, EXIT_POLICY_FAILURE, EXIT_SUCCESS};
    match fail_on {
        FailOn::Never => EXIT_SUCCESS,
        FailOn::AnyFailure => {
            if report.failed > 0 {
                EXIT_POLICY_FAILURE
            } else {
                EXIT_SUCCESS
            }
        }
        FailOn::PctGreaterThan => {
            if report.total_urls == 0 {
                return EXIT_NO_URLS_PCT;
            }
            // URL counts are typically < 10M, well within f64 52-bit mantissa
            #[allow(clippy::cast_precision_loss)]
            let failure_pct = (report.failed as f64 / report.total_urls as f64) * 100.0;
            if failure_pct > f64::from(pct_threshold) {
                EXIT_POLICY_FAILURE
            } else {
                EXIT_SUCCESS
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
            skipped: 0,
            elapsed_seconds: 1.0,
            db_path: PathBuf::from("test.db"),
            run_id: "test-run-1".to_string(),
        }
    }

    #[test]
    fn test_parse_real_scan_command_defaults() {
        use domain_status_cli::FailOn as CliFailOn;

        let cli = parse_cli_command_from(["domain_status", "scan", "test.txt"]).unwrap();

        match cli {
            CliCommand::Scan(cmd) => {
                assert_eq!(cmd.file, PathBuf::from("test.txt"));
                assert_eq!(cmd.max_concurrency, 30);
                assert_eq!(cmd.fail_on, CliFailOn::Never);
                assert_eq!(cmd.db_path, PathBuf::from("./domain_status.db"));
            }
            CliCommand::Export(_) => panic!("expected scan command"),
        }
    }

    #[test]
    fn test_parse_real_export_command_filters() {
        use domain_status_cli::ExportFormat as CliExportFormat;

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
                assert!(matches!(cmd.format, CliExportFormat::Jsonl));
            }
            CliCommand::Scan(_) => panic!("expected export command"),
        }
    }

    #[test]
    fn test_scan_command_into_config_preserves_fields() {
        use domain_status_cli::{
            FailOn as CliFailOn, LogFormat as CliLogFormat, LogLevel as CliLogLevel,
        };

        let scan_cmd = ScanCommand {
            config: None,
            file: PathBuf::from("test.txt"),
            log_level: CliLogLevel::Debug,
            verbosity: clap_verbosity_flag::Verbosity::<clap_verbosity_flag::InfoLevel>::default(),
            log_format: CliLogFormat::Json,
            db_path: PathBuf::from("custom.db"),
            max_concurrency: 50,
            timeout_seconds: 20,
            user_agent: "Custom Agent".to_string(),
            rate_limit_rps: 25,
            fingerprints: Some("https://example.com/tech.json".to_string()),
            geoip: Some("/path/to/geoip.mmdb".to_string()),
            status_port: Some(8080),
            enable_whois: true,
            scan_external_scripts: true,
            fail_on: CliFailOn::AnyFailure,
            fail_on_pct_threshold: 15,
            log_file: PathBuf::from("domain_status.log"),
            drain_timeout_secs: 10,
        };

        let config: Config = config_from_scan_command(scan_cmd);
        assert_eq!(config.file, PathBuf::from("test.txt"));
        assert_eq!(config.db_path, PathBuf::from("custom.db"));
        assert_eq!(config.max_concurrency, 50);
        assert_eq!(config.timeout_seconds, 20);
        assert_eq!(config.user_agent, "Custom Agent");
        assert_eq!(config.rate_limit_rps, 25);
        assert_eq!(
            config.fingerprints,
            Some("https://example.com/tech.json".to_string())
        );
        assert_eq!(config.geoip, Some("/path/to/geoip.mmdb".to_string()));
        assert_eq!(config.status_port, Some(8080));
        assert!(config.enable_whois);
        assert!(config.scan_external_scripts);
        assert_eq!(config.fail_on, FailOn::AnyFailure);
        assert_eq!(config.fail_on_pct_threshold, 15);
    }

    #[test]
    fn test_evaluate_exit_code_real_logic() {
        use crate::exit_codes::{EXIT_NO_URLS_PCT, EXIT_POLICY_FAILURE, EXIT_SUCCESS};
        assert_eq!(
            evaluate_exit_code(&FailOn::Never, 10, &sample_report(10, 5, 5)),
            EXIT_SUCCESS
        );
        assert_eq!(
            evaluate_exit_code(&FailOn::AnyFailure, 10, &sample_report(10, 5, 5)),
            EXIT_POLICY_FAILURE
        );
        assert_eq!(
            evaluate_exit_code(&FailOn::AnyFailure, 10, &sample_report(10, 10, 0)),
            EXIT_SUCCESS
        );
        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 10, &sample_report(0, 0, 0)),
            EXIT_NO_URLS_PCT
        );
        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 10, &sample_report(100, 95, 5)),
            EXIT_SUCCESS
        );
        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 10, &sample_report(100, 89, 11)),
            EXIT_POLICY_FAILURE
        );
    }

    #[test]
    fn test_evaluate_exit_code_large_counts_do_not_overflow() {
        use crate::exit_codes::EXIT_SUCCESS;
        let max_urls = usize::MAX;
        let report = sample_report(max_urls, max_urls.saturating_sub(1), 1);
        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 10, &report),
            EXIT_SUCCESS
        );
    }

    /// Boundary: exactly at threshold must return 0 (condition is `>`, not `>=`).
    #[test]
    fn test_evaluate_exit_code_pct_exactly_at_threshold_returns_zero() {
        use crate::exit_codes::EXIT_SUCCESS;
        // 10% failed, threshold 10: 10.0 > 10 is false → exit 0
        let report = sample_report(100, 90, 10);
        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 10, &report),
            EXIT_SUCCESS,
            "exactly 10% failed with threshold 10 must return 0 (>)"
        );
    }

    /// Boundary: just over threshold must return 2.
    #[test]
    fn test_evaluate_exit_code_pct_just_over_threshold_returns_two() {
        use crate::exit_codes::EXIT_POLICY_FAILURE;
        // 11% failed, threshold 10: 11.0 > 10 is true → exit 2
        let report = sample_report(100, 89, 11);
        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 10, &report),
            EXIT_POLICY_FAILURE,
            "just over 10% failed with threshold 10 must return 2"
        );
    }

    /// Floating-point boundary: 1/10 and 2/20 are 10%; both must yield 0 for threshold 10.
    #[test]
    fn test_evaluate_exit_code_pct_float_boundary() {
        use crate::exit_codes::EXIT_SUCCESS;
        let report_1_10 = sample_report(10, 9, 1);
        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 10, &report_1_10),
            EXIT_SUCCESS,
            "1/10 = 10% with threshold 10 must return 0"
        );
        let report_2_20 = sample_report(20, 18, 2);
        assert_eq!(
            evaluate_exit_code(&FailOn::PctGreaterThan, 10, &report_2_20),
            EXIT_SUCCESS,
            "2/20 = 10% with threshold 10 must return 0"
        );
    }
}
