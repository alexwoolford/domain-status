use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};

// constants (used as defaults)
#[allow(dead_code)]
pub const SEMAPHORE_LIMIT: usize = 20;
pub const LOGGING_INTERVAL: usize = 5;
pub const URL_PROCESSING_TIMEOUT: Duration = Duration::from_secs(30);
pub const DB_PATH: &str = "./url_checker.db";

// Network operation timeouts
/// DNS query timeout in seconds
/// Increased from 5s to 10s to reduce timeout errors on TXT/NS/MX lookups
pub const DNS_TIMEOUT_SECS: u64 = 10;
/// TCP connection timeout in seconds
pub const TCP_CONNECT_TIMEOUT_SECS: u64 = 5;
/// TLS handshake timeout in seconds
pub const TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 5;

/// Default User-Agent string for HTTP requests.
///
/// Uses a generic Chrome-like string without a specific version number to avoid
/// becoming outdated. The pattern mimics a modern Chrome browser on Windows.
///
/// **Note:** This should be updated periodically to match current browser patterns.
/// Users can override this via the `--user-agent` CLI flag.
///
/// For better bot evasion, consider:
/// - Using a more recent browser version pattern
/// - Rotating between different User-Agent strings
/// - Customizing per target site
pub const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

// URL validation
pub const URL_SCHEME_PATTERN: &str = r"^https?://";

// Security header names
// These headers are stored in the url_security_headers table
pub const HEADER_CONTENT_SECURITY_POLICY: &str = "Content-Security-Policy";
pub const HEADER_STRICT_TRANSPORT_SECURITY: &str = "Strict-Transport-Security";
pub const HEADER_X_CONTENT_TYPE_OPTIONS: &str = "X-Content-Type-Options";
pub const HEADER_X_FRAME_OPTIONS: &str = "X-Frame-Options";
pub const HEADER_X_XSS_PROTECTION: &str = "X-XSS-Protection";
pub const HEADER_REFERRER_POLICY: &str = "Referrer-Policy";
pub const HEADER_PERMISSIONS_POLICY: &str = "Permissions-Policy";

/// List of security headers to capture.
/// These are stored in the `url_security_headers` table.
/// To add/remove headers, modify this array.
pub const SECURITY_HEADERS: &[&str] = &[
    HEADER_CONTENT_SECURITY_POLICY,
    HEADER_STRICT_TRANSPORT_SECURITY,
    HEADER_X_CONTENT_TYPE_OPTIONS,
    HEADER_X_FRAME_OPTIONS,
    HEADER_X_XSS_PROTECTION,
    HEADER_REFERRER_POLICY,
    HEADER_PERMISSIONS_POLICY,
];

// Other HTTP header names
// These headers are stored in the url_http_headers table
// Infrastructure/Server identification
pub const HEADER_SERVER: &str = "Server";
pub const HEADER_X_POWERED_BY: &str = "X-Powered-By";
pub const HEADER_X_GENERATOR: &str = "X-Generator";

// CDN/Proxy identification
pub const HEADER_CF_RAY: &str = "CF-Ray"; // Cloudflare
pub const HEADER_X_SERVED_BY: &str = "X-Served-By"; // Fastly
pub const HEADER_VIA: &str = "Via";

// Performance/Monitoring
pub const HEADER_SERVER_TIMING: &str = "Server-Timing";
pub const HEADER_X_CACHE: &str = "X-Cache";

// Caching
pub const HEADER_CACHE_CONTROL: &str = "Cache-Control";
pub const HEADER_ETAG: &str = "ETag";
pub const HEADER_LAST_MODIFIED: &str = "Last-Modified";

/// List of other HTTP headers to capture (non-security).
/// These are stored in the `url_http_headers` table.
/// Headers are categorized by use case:
/// - Infrastructure: Server, X-Powered-By, X-Generator (technology detection)
/// - CDN/Proxy: CF-Ray, X-Served-By, Via (infrastructure analysis)
/// - Performance: Server-Timing, X-Cache (performance monitoring)
/// - Caching: Cache-Control, ETag, Last-Modified (cache analysis)
///
/// To add/remove headers, modify this array.
pub const HTTP_HEADERS: &[&str] = &[
    // Infrastructure/Server identification
    HEADER_SERVER,
    HEADER_X_POWERED_BY,
    HEADER_X_GENERATOR,
    // CDN/Proxy identification
    HEADER_CF_RAY,
    HEADER_X_SERVED_BY,
    HEADER_VIA,
    // Performance/Monitoring
    HEADER_SERVER_TIMING,
    HEADER_X_CACHE,
    // Caching
    HEADER_CACHE_CONTROL,
    HEADER_ETAG,
    HEADER_LAST_MODIFIED,
];

// Response and body size limits
/// Maximum response body size in bytes (2MB)
/// Responses larger than this are skipped to prevent memory exhaustion
pub const MAX_RESPONSE_BODY_SIZE: usize = 2 * 1024 * 1024;

// Redirect handling
/// Maximum number of redirect hops to follow
/// Prevents infinite redirect loops and excessive request chains
pub const MAX_REDIRECT_HOPS: usize = 10;

// Retry strategy
/// Initial delay in milliseconds before first retry
pub const RETRY_INITIAL_DELAY_MS: u64 = 1000;
/// Factor by which retry delay is multiplied on each attempt
pub const RETRY_FACTOR: u64 = 2;
/// Maximum delay between retries in seconds
pub const RETRY_MAX_DELAY_SECS: u64 = 20;

/// Logging level for the application.
///
/// Controls the verbosity of log output, from most restrictive (Error) to most
/// verbose (Trace). Used with the `--log-level` CLI option.
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

/// Log output format.
///
/// Controls how log messages are formatted:
/// - `Plain`: Human-readable format with colors (default)
/// - `Json`: Structured JSON format for machine parsing
#[derive(Clone, Debug, ValueEnum)]
pub enum LogFormat {
    Plain,
    Json,
}

/// Command-line options and configuration.
///
/// This struct is automatically generated by `clap` from the field attributes.
/// All options have sensible defaults and can be overridden via command-line flags.
///
/// # Examples
///
/// ```bash
/// # Basic usage
/// domain_status urls.txt
///
/// # With custom concurrency and timeout
/// domain_status urls.txt --max-concurrency 100 --timeout-seconds 5
///
/// # With custom database path
/// domain_status urls.txt --db-path ./custom.db
/// ```
#[derive(Debug, Parser)]
#[command(
    name = "domain_status",
    about = "Checks a list of URLs for their status and redirection."
)]
pub struct Opt {
    /// File to read
    #[arg(value_parser)]
    pub file: PathBuf,

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
    ///
    /// Lower default (20) reduces bot detection risk with Cloudflare and similar services.
    /// High concurrency can trigger rate limiting even with low RPS.
    #[arg(long, default_value_t = 20)]
    pub max_concurrency: usize,

    /// Per-request timeout in seconds
    #[arg(long, default_value_t = 10)]
    pub timeout_seconds: u64,

    /// HTTP User-Agent header value.
    ///
    /// Defaults to a Chrome-like browser string. Can be overridden to match
    /// specific browser versions or patterns. For better bot evasion, consider
    /// using a recent browser version or rotating User-Agent strings.
    #[arg(long, default_value = DEFAULT_USER_AGENT)]
    pub user_agent: String,

    /// Requests per second rate limit (0 disables limiting)
    ///
    /// Default 10 RPS provides reasonable throughput while avoiding bot detection.
    /// Set to 0 to disable rate limiting (not recommended for production).
    #[arg(long, default_value_t = 10)]
    pub rate_limit_rps: u32,

    /// Rate limit burst capacity (tokens)
    ///
    /// If 0, automatically calculated as `min(max_concurrency, rate_limit_rps * 2)`.
    /// This ensures burst doesn't exceed concurrency limits and prevents excessive queuing.
    #[arg(long, default_value_t = 0)]
    pub rate_burst: usize,

    /// Fingerprints source URL or local path (default: HTTP Archive)
    /// Examples:
    ///   --fingerprints https://raw.githubusercontent.com/HTTPArchive/wappalyzer/main/src/technologies
    ///   --fingerprints /path/to/technologies.json
    #[arg(long)]
    pub fingerprints: Option<String>,

    /// GeoIP database path (MaxMind GeoLite2 .mmdb file) or download URL
    /// Examples:
    ///   --geoip /path/to/GeoLite2-City.mmdb
    ///   --geoip https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_KEY&suffix=tar.gz
    /// If not provided, GeoIP will auto-download if MAXMIND_LICENSE_KEY env var is set.
    /// Otherwise, GeoIP lookup is disabled.
    #[arg(long)]
    pub geoip: Option<String>,
}
