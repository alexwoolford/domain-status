#![allow(clippy::doc_markdown)] // CLI doc comments appear in --help; backticks look wrong there.
//! CLI definition for domain_status (single source of truth).
//!
//! Used by the main crate for parsing and by build.rs for shell completions and man page.

use std::path::PathBuf;

use clap::CommandFactory;
use clap::Parser;

/// Default User-Agent for HTTP requests when the caller does not override `--user-agent`.
///
/// The main crate may auto-refresh Chrome's version at startup when this default is still in use.
pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// Root CLI command (subcommand required).
#[derive(Debug, Parser, Clone)]
#[command(
    name = "domain_status",
    about = "Domain intelligence scanner - scan URLs and export results.",
    version = "0.0.0", // placeholder — overridden by clap_command() with DOMAIN_STATUS_VERSION
    long_version = "0.0.0", // placeholder — overridden by clap_command() with DOMAIN_STATUS_VERSION
    subcommand_required = true,
    arg_required_else_help = true
)]
pub enum CliCommand {
    /// Scan URLs and store results in SQLite database.
    #[command(name = "scan")]
    Scan(ScanCommand),

    /// Export data from SQLite database to various formats.
    #[command(name = "export")]
    Export(ExportCommand),

    /// Print a summary of the last (or a selected) scan run.
    #[command(name = "summary")]
    Summary(SummaryCommand),
}

/// Scan command arguments.
#[derive(Debug, Parser, Clone)]
pub struct ScanCommand {
    #[arg(long, value_parser, env = "DOMAIN_STATUS_CONFIG_FILE")]
    pub config: Option<PathBuf>,

    #[arg(value_parser)]
    pub file: PathBuf,

    /// Baseline log level; overridden by `-v` / `-q` (preferred for quick changes).
    #[arg(long, value_enum, default_value_t = LogLevel::Info, env = "DOMAIN_STATUS_LOG_LEVEL")]
    pub log_level: LogLevel,

    #[command(flatten)]
    pub verbosity: clap_verbosity_flag::Verbosity<clap_verbosity_flag::InfoLevel>,

    /// Format for the scan log file (`--log-file`). Use `-v`/`-q` for verbosity.
    #[arg(long, value_enum, default_value_t = LogFormat::Plain, env = "DOMAIN_STATUS_LOG_FORMAT")]
    pub log_format: LogFormat,

    #[arg(
        long,
        value_parser,
        default_value = "./domain_status.db",
        env = "DOMAIN_STATUS_DB_PATH"
    )]
    pub db_path: PathBuf,

    #[arg(long, default_value_t = 30, env = "DOMAIN_STATUS_MAX_CONCURRENCY")]
    pub max_concurrency: usize,

    #[arg(long, default_value_t = 10, env = "DOMAIN_STATUS_TIMEOUT_SECONDS")]
    pub timeout_seconds: u64,

    #[arg(long, default_value = DEFAULT_USER_AGENT, env = "DOMAIN_STATUS_USER_AGENT")]
    pub user_agent: String,

    #[arg(long, default_value_t = 15, env = "DOMAIN_STATUS_RATE_LIMIT_RPS")]
    pub rate_limit_rps: u32,

    #[arg(long, env = "DOMAIN_STATUS_FINGERPRINTS")]
    pub fingerprints: Option<String>,

    #[arg(long, env = "DOMAIN_STATUS_GEOIP")]
    pub geoip: Option<String>,

    #[arg(long, env = "DOMAIN_STATUS_STATUS_PORT")]
    pub status_port: Option<u16>,

    #[arg(long, env = "DOMAIN_STATUS_ENABLE_WHOIS")]
    pub enable_whois: bool,

    /// Disable WHOIS even if enabled in TOML / env (`enable_whois = true`).
    #[arg(long, conflicts_with = "enable_whois")]
    pub no_whois: bool,

    /// Shared cache root for fingerprints, GeoIP, WHOIS, and User-Agent data.
    /// Defaults to `$DOMAIN_STATUS_CACHE_DIR` or the platform cache dir +
    /// `domain_status/` (Linux `~/.cache/…`, macOS `~/Library/Caches/…`).
    /// Database and log paths are separate.
    #[arg(long, value_parser, env = "DOMAIN_STATUS_CACHE_DIR")]
    pub cache_dir: Option<PathBuf>,

    /// Fetch first-party external `<script src>` URLs for secret detection and
    /// static technology fingerprints (`scripts` patterns). Off by default because
    /// it expands the threat surface and adds per-URL latency. Only scripts on the
    /// same registrable domain as the page are fetched (known third-party CDNs are
    /// skipped). Fetches are capped at 10 scripts per page, size/timeout limited,
    /// and SSRF-validated like the primary URL.
    #[arg(long, env = "DOMAIN_STATUS_SCAN_EXTERNAL_SCRIPTS")]
    pub scan_external_scripts: bool,

    #[arg(long, value_enum, default_value_t = FailOn::Never, env = "DOMAIN_STATUS_FAIL_ON")]
    pub fail_on: FailOn,

    #[arg(
        long,
        default_value_t = 10,
        value_parser = clap::value_parser!(u8).range(0..=100),
        requires_if("pct>", "fail_on"),
        env = "DOMAIN_STATUS_FAIL_ON_PCT_THRESHOLD"
    )]
    pub fail_on_pct_threshold: u8,

    #[arg(
        long,
        default_value = "domain_status.log",
        env = "DOMAIN_STATUS_LOG_FILE"
    )]
    pub log_file: PathBuf,

    /// Maximum time (seconds) to wait for in-flight tasks to finish after the
    /// input queue is exhausted. Tasks still running after this window are
    /// aborted and recorded in `url_failures` with the timeout reason.
    /// Raise this for WHOIS-heavy small batches if scans report drain timeouts.
    #[arg(long, default_value_t = 10, env = "DOMAIN_STATUS_DRAIN_TIMEOUT_SECS")]
    pub drain_timeout_secs: u64,
}

/// Export command arguments.
#[derive(Debug, Parser, Clone)]
pub struct ExportCommand {
    #[arg(
        long,
        value_parser,
        default_value = "./domain_status.db",
        env = "DOMAIN_STATUS_DB_PATH"
    )]
    pub db_path: PathBuf,

    #[arg(long, value_enum, default_value = "csv")]
    pub format: ExportFormat,

    #[arg(long)]
    pub output: Option<String>,

    #[arg(long)]
    pub run_id: Option<String>,

    #[arg(long)]
    pub domain: Option<String>,

    #[arg(long)]
    pub status: Option<u16>,

    #[arg(long)]
    pub since: Option<i64>,

    /// Include fingerprint technologies with `is_implied = 1` in export output.
    /// Default: only directly observed technologies.
    #[arg(long, default_value_t = false)]
    pub include_implied_tech: bool,
}

/// Summary command arguments.
#[derive(Debug, Parser, Clone)]
pub struct SummaryCommand {
    #[arg(
        long,
        value_parser,
        default_value = "./domain_status.db",
        env = "DOMAIN_STATUS_DB_PATH"
    )]
    pub db_path: PathBuf,

    /// Run id to summarize (default: most recent completed run).
    #[arg(long)]
    pub run_id: Option<String>,

    /// How many top technologies to list (default: 15).
    #[arg(long, default_value_t = 15)]
    pub top: usize,
}

/// Exit code policy for handling failures.
///
/// Marked `#[non_exhaustive]` so adding new policies is not a breaking change.
#[derive(Clone, Debug, Default, clap::ValueEnum, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailOn {
    /// Never exit with error code (always return 0).
    #[default]
    Never,
    /// Exit with error if any URL failed.
    #[value(name = "any-failure")]
    AnyFailure,
    /// Exit with error if failure percentage exceeds threshold (`pct>`).
    #[value(name = "pct>")]
    PctGreaterThan,
}

/// Logging level for the application.
#[derive(Clone, Debug, Default, clap::ValueEnum, PartialEq, Eq)]
pub enum LogLevel {
    /// Only error messages.
    Error,
    /// Error and warning messages.
    Warn,
    /// Error, warning, and informational messages.
    #[default]
    Info,
    /// All messages except trace.
    Debug,
    /// All messages including trace.
    Trace,
}

/// Log output format.
///
/// Marked `#[non_exhaustive]` so adding new formats is not a breaking change.
#[derive(Copy, Clone, Debug, Default, clap::ValueEnum, PartialEq, Eq)]
#[non_exhaustive]
pub enum LogFormat {
    /// Human-readable format with colors (default).
    #[default]
    Plain,
    /// Structured JSON format for machine parsing.
    Json,
}

/// Export output format.
#[derive(Debug, Clone, Default, clap::ValueEnum, PartialEq, Eq)]
pub enum ExportFormat {
    #[default]
    Csv,
    Jsonl,
    Parquet,
}

/// Returns the full CLI `Command` for codegen (completions, man page) and for
/// `--print-completions` / `--print-manpage`. Pass a static version string
/// (e.g. `env!("DOMAIN_STATUS_VERSION")` or `env!("CARGO_PKG_VERSION")`).
#[must_use]
pub fn clap_command(version: &'static str) -> clap::Command {
    CliCommand::command().version(version).long_version(version)
}
