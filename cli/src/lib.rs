#![allow(clippy::doc_markdown)] // CLI doc comments appear in --help; backticks look wrong there.
//! CLI definition for domain_status (single source of truth).
//!
//! Used by the main crate for parsing and by build.rs for shell completions and man page.

use std::path::PathBuf;

use clap::CommandFactory;
use clap::Parser;

const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

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
}

/// Scan command arguments.
#[derive(Debug, Parser, Clone)]
pub struct ScanCommand {
    #[arg(long, value_parser, env = "DOMAIN_STATUS_CONFIG_FILE")]
    pub config: Option<PathBuf>,

    #[arg(value_parser)]
    pub file: PathBuf,

    #[arg(long, value_enum, default_value_t = LogLevel::Info, env = "DOMAIN_STATUS_LOG_LEVEL")]
    pub log_level: LogLevel,

    #[command(flatten)]
    pub verbosity: clap_verbosity_flag::Verbosity<clap_verbosity_flag::InfoLevel>,

    #[arg(long, value_enum, default_value_t = LogFormat::Plain, env = "DOMAIN_STATUS_LOG_FORMAT")]
    pub log_format: LogFormat,

    #[arg(
        long,
        value_parser,
        default_value = "./domain_status.db",
        env = "DOMAIN_STATUS_DB_PATH"
    )]
    pub db_path: PathBuf,

    #[arg(long, default_value_t = 30)]
    pub max_concurrency: usize,

    #[arg(long, default_value_t = 10)]
    pub timeout_seconds: u64,

    #[arg(long, default_value = DEFAULT_USER_AGENT)]
    pub user_agent: String,

    #[arg(long, default_value_t = 15)]
    pub rate_limit_rps: u32,

    #[arg(long)]
    pub fingerprints: Option<String>,

    #[arg(long)]
    pub geoip: Option<String>,

    #[arg(long, env = "DOMAIN_STATUS_STATUS_PORT")]
    pub status_port: Option<u16>,

    #[arg(long)]
    pub enable_whois: bool,

    /// Fetch external `<script src>` URLs and scan their content for exposed
    /// secrets. Off by default because it expands the threat surface
    /// (now we make GET requests to arbitrary script URLs the page references)
    /// and adds per-URL latency. When enabled, fetches are bounded by the same
    /// 2 MB body cap and the configured per-request timeout, capped at
    /// 10 scripts per page, and SSRF-validated like the primary URL.
    #[arg(long, env = "DOMAIN_STATUS_SCAN_EXTERNAL_SCRIPTS")]
    pub scan_external_scripts: bool,

    #[arg(long, value_enum, default_value_t = FailOn::Never)]
    pub fail_on: FailOn,

    #[arg(
        long,
        default_value_t = 10,
        value_parser = clap::value_parser!(u8).range(0..=100),
        requires_if("pct>", "fail_on")
    )]
    pub fail_on_pct_threshold: u8,

    #[arg(long, default_value = "domain_status.log")]
    pub log_file: PathBuf,

    /// Maximum time (seconds) to wait for in-flight tasks to finish after the
    /// input queue is exhausted. Tasks still running after this window are
    /// aborted and recorded in `url_failures` with the timeout reason.
    /// Raise this for WHOIS-heavy small batches if scans report drain timeouts.
    #[arg(long, default_value_t = 10)]
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
}

#[derive(Clone, Debug, Default, clap::ValueEnum, PartialEq, Eq)]
pub enum FailOn {
    #[default]
    Never,
    AnyFailure,
    #[value(name = "pct>")]
    PctGreaterThan,
}

#[derive(Clone, Debug, Default, clap::ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

#[derive(Copy, Clone, Debug, Default, clap::ValueEnum)]
pub enum LogFormat {
    #[default]
    Plain,
    Json,
}

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
