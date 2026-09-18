#![allow(clippy::doc_markdown)] // CLI doc comments appear in --help; backticks look wrong there.
//! CLI definition for domain-status (single source of truth).
//!
//! Used by the main crate for parsing and by build.rs for shell completions and man page.

use std::path::PathBuf;

use clap::CommandFactory;
use clap::Parser;

/// Default User-Agent for HTTP requests when the caller does not override `--user-agent`.
///
/// The main crate may auto-refresh Chrome's version at startup when this default is still in use.
pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// Shown on `--help` so the default scan path stays authorized-use only.
pub const ACCEPTABLE_USE_HELP: &str = "Scan only hosts you are authorized to scan.";

/// Root CLI command (subcommand required).
#[derive(Debug, Parser, Clone)]
#[command(
    name = "domain-status",
    about = "Concurrent URL scanner; results in SQLite.",
    after_help = ACCEPTABLE_USE_HELP,
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
///
/// Everyday flags are on `-h`. All flags (except the legacy `--enable-whois` alias)
/// are on `--help`.
#[derive(Debug, Parser, Clone)]
#[command(after_help = concat!(
    "Everyday flags: -h. All flags: --help. Docs: docs/CLI.md\n\n",
    "Scan only hosts you are authorized to scan."
))]
pub struct ScanCommand {
    /// URL list (one URL per line). Use `-` for stdin.
    #[arg(value_parser, help_heading = "Scan")]
    pub file: PathBuf,

    #[arg(
        long,
        value_parser,
        default_value = "./domain_status.db",
        env = "DOMAIN_STATUS_DB_PATH",
        help_heading = "Scan"
    )]
    pub db_path: PathBuf,

    #[arg(
        long,
        default_value_t = 10,
        env = "DOMAIN_STATUS_TIMEOUT_SECONDS",
        help_heading = "Scan"
    )]
    pub timeout_seconds: u64,

    #[arg(
        long,
        default_value_t = 30,
        env = "DOMAIN_STATUS_MAX_CONCURRENCY",
        help_heading = "Scan"
    )]
    pub max_concurrency: usize,

    /// URL admission rate (tokens per input URL per second). `0` disables
    /// both the global cap and the 2/sec per-host cap.
    ///
    /// Not per-HTTP-request RPS: redirects, favicon, TLS, and WHOIS share one token
    /// per input URL. When enabled, each host is also limited to 2 URL tokens/sec.
    #[arg(
        long,
        default_value_t = 15,
        env = "DOMAIN_STATUS_RATE_LIMIT_RPS",
        help_heading = "Scan"
    )]
    pub rate_limit_rps: u32,

    /// Disable WHOIS/RDAP (on by default).
    ///
    /// Overrides TOML/env `enable_whois = true`.
    #[arg(long, conflicts_with = "enable_whois", help_heading = "Enrichments")]
    pub no_whois: bool,

    /// GeoIP MMDB path or URL. Or set MAXMIND_LICENSE_KEY for GeoLite2 download.
    #[arg(long, env = "DOMAIN_STATUS_GEOIP", help_heading = "Enrichments")]
    pub geoip: Option<String>,

    /// Fetch first-party external script bodies (secrets + static tech). Off by default.
    ///
    /// Only scripts on the same registrable domain as the page are fetched (known
    /// third-party CDNs are skipped). Fetches are capped at 10 scripts per page,
    /// size/timeout limited, and SSRF-validated like the primary URL. Off by default
    /// because it expands the threat surface and adds per-URL latency.
    #[arg(
        long,
        env = "DOMAIN_STATUS_SCAN_EXTERNAL_SCRIPTS",
        help_heading = "Enrichments"
    )]
    pub scan_external_scripts: bool,

    /// CI exit policy when some URLs fail (`never`, `any-failure`, `pct>`).
    #[arg(
        long,
        value_enum,
        default_value_t = FailOn::Never,
        env = "DOMAIN_STATUS_FAIL_ON",
        help_heading = "CI / logging"
    )]
    pub fail_on: FailOn,

    #[command(flatten, next_help_heading = "CI / logging")]
    pub verbosity: clap_verbosity_flag::Verbosity<clap_verbosity_flag::InfoLevel>,

    /// Baseline log level; overridden by `-v` / `-q` (preferred for quick changes).
    #[arg(
        long,
        value_enum,
        default_value_t = LogLevel::Info,
        env = "DOMAIN_STATUS_LOG_LEVEL",
        hide_short_help = true,
        help_heading = "CI / logging"
    )]
    pub log_level: LogLevel,

    /// Format for scan `--log-file` and for export/summary stderr.
    ///
    /// `plain` in the scan file is uncolored; export/summary stderr `plain` uses colors.
    #[arg(
        long,
        value_enum,
        default_value_t = LogFormat::Plain,
        env = "DOMAIN_STATUS_LOG_FORMAT",
        hide_short_help = true,
        help_heading = "CI / logging"
    )]
    pub log_format: LogFormat,

    #[arg(
        long,
        default_value = "domain_status.log",
        env = "DOMAIN_STATUS_LOG_FILE",
        hide_short_help = true,
        help_heading = "CI / logging"
    )]
    pub log_file: PathBuf,

    /// Hide the terminal progress bar (still logs progress to `--log-file`).
    #[arg(
        long,
        env = "DOMAIN_STATUS_NO_PROGRESS",
        hide_short_help = true,
        help_heading = "CI / logging"
    )]
    pub no_progress: bool,

    #[arg(
        long,
        default_value_t = 10,
        value_parser = clap::value_parser!(u8).range(0..=100),
        requires_if("pct>", "fail_on"),
        env = "DOMAIN_STATUS_FAIL_ON_PCT_THRESHOLD",
        hide_short_help = true,
        help_heading = "CI / logging"
    )]
    pub fail_on_pct_threshold: u8,

    #[arg(
        long,
        value_parser,
        env = "DOMAIN_STATUS_CONFIG_FILE",
        hide_short_help = true,
        help_heading = "Advanced"
    )]
    pub config: Option<PathBuf>,

    #[arg(
        long,
        default_value = DEFAULT_USER_AGENT,
        env = "DOMAIN_STATUS_USER_AGENT",
        hide_short_help = true,
        help_heading = "Advanced"
    )]
    pub user_agent: String,

    #[arg(
        long,
        env = "DOMAIN_STATUS_FINGERPRINTS",
        hide_short_help = true,
        help_heading = "Advanced"
    )]
    pub fingerprints: Option<String>,

    #[arg(
        long,
        env = "DOMAIN_STATUS_STATUS_PORT",
        hide_short_help = true,
        help_heading = "Advanced"
    )]
    pub status_port: Option<u16>,

    /// Shared cache root for fingerprints, GeoIP, WHOIS, and User-Agent data.
    /// Defaults to `$DOMAIN_STATUS_CACHE_DIR` or the platform cache dir +
    /// `domain_status/` (Linux `~/.cache/…`, macOS `~/Library/Caches/…`).
    /// Database and log paths are separate.
    #[arg(
        long,
        value_parser,
        env = "DOMAIN_STATUS_CACHE_DIR",
        hide_short_help = true,
        help_heading = "Advanced"
    )]
    pub cache_dir: Option<PathBuf>,

    /// Maximum time (seconds) to wait for in-flight tasks to finish after the
    /// input queue is exhausted. Tasks still running after this window are
    /// aborted and recorded in `url_failures` with the timeout reason.
    /// Raise this for WHOIS-heavy small batches if scans report drain timeouts.
    #[arg(
        long,
        default_value_t = 10,
        env = "DOMAIN_STATUS_DRAIN_TIMEOUT_SECS",
        hide_short_help = true,
        help_heading = "Advanced"
    )]
    pub drain_timeout_secs: u64,

    /// Enable WHOIS/RDAP (on by default). Prefer `--no-whois` to disable.
    /// Kept for backward compatibility with scripts that pass `--enable-whois`.
    #[arg(
        long,
        env = "DOMAIN_STATUS_ENABLE_WHOIS",
        default_value_t = true,
        hide = true
    )]
    pub enable_whois: bool,
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

    /// Exact match on `initial_domain` or `final_domain` (not a substring).
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
    /// Human-readable. Scan `--log-file` is uncolored; export/summary stderr is colored.
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
