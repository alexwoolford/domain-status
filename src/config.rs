use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};

// constants (used as defaults)
pub const SEMAPHORE_LIMIT: usize = 500;
pub const LOGGING_INTERVAL: usize = 5;
pub const URL_PROCESSING_TIMEOUT: Duration = Duration::from_secs(10);
pub const DB_PATH: &str = "./url_checker.db";

#[derive(Clone, Debug, ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
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

#[derive(Clone, Debug, ValueEnum)]
pub enum LogFormat {
    Plain,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "domain_status",
    about = "Checks a list of URLs for their status and redirection."
)]
pub struct Opt {
    /// File to read
    #[arg(value_parser)]
    pub file: PathBuf,

    /// Error rate threshold
    #[arg(long, default_value = "60.0")]
    pub error_rate: f64,

    /// Log level: error|warn|info|debug|trace
    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    /// Log format: plain|json
    #[arg(long, value_enum, default_value_t = LogFormat::Plain)]
    pub log_format: LogFormat,

    /// Database path (SQLite file)
    #[arg(long, value_parser, default_value = "./url_checker.db")]
    pub db_path: PathBuf,

    /// Maximum concurrent requests
    #[arg(long, default_value_t = 500)]
    pub max_concurrency: usize,

    /// Per-request timeout in seconds
    #[arg(long, default_value_t = 10)]
    pub timeout_seconds: u64,

    /// HTTP User-Agent header value
    #[arg(long, default_value = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")]
    pub user_agent: String,

    /// Requests per second rate limit (0 disables limiting)
    #[arg(long, default_value_t = 0)]
    pub rate_limit_rps: u32,

    /// Rate limit burst capacity (tokens), defaults to max concurrency if 0
    #[arg(long, default_value_t = 0)]
    pub rate_burst: usize,
}
