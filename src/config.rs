use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};

// constants (used as defaults)
#[allow(dead_code)]
pub const SEMAPHORE_LIMIT: usize = 20;
pub const LOGGING_INTERVAL: usize = 5;
/// Per-URL processing timeout in seconds
/// Increased from 30s to 45s to account for DNS, TLS, and HTTP operations
pub const URL_PROCESSING_TIMEOUT: Duration = Duration::from_secs(45);
pub const DB_PATH: &str = "./url_checker.db";

// Batch writing configuration
/// Maximum number of records to batch before flushing to database
pub const BATCH_SIZE: usize = 100;
/// Interval between automatic batch flushes (in seconds)
pub const BATCH_FLUSH_INTERVAL_SECS: u64 = 5;
/// Channel size multiplier for batch writer
/// The channel size is calculated as `batch_size * CHANNEL_SIZE_MULTIPLIER`
/// This provides a buffer to handle bursts while maintaining backpressure
pub const CHANNEL_SIZE_MULTIPLIER: usize = 10;

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
/// **Note:** This is a fallback value. The actual User-Agent is automatically
/// fetched at startup from Chrome's release API and cached locally for 30 days.
/// This ensures the User-Agent stays current over time without manual updates.
///
/// Users can override this via the `--user-agent` CLI flag.
///
/// The auto-update mechanism:
/// - Fetches latest Chrome version from Chrome's release API at startup
/// - Caches the version locally for 30 days (in `.user_agent_cache/`)
/// - Falls back to this hardcoded value if fetch fails
/// - Only updates if user didn't provide `--user-agent` flag
///
/// For better bot evasion, consider:
/// - Letting the auto-update mechanism keep it current (default behavior)
/// - Rotating between different User-Agent strings
/// - Customizing per target site via `--user-agent` flag
pub const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

// URL validation
// URL_SCHEME_PATTERN removed - URL normalization now handled in validate_and_normalize_url()

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

// Script content size limits
/// Maximum script content size in bytes (100KB per script)
/// Limits the amount of JavaScript we extract per script tag
/// This is enforced in src/fetch/mod.rs when extracting script content
pub const MAX_SCRIPT_CONTENT_SIZE: usize = 100 * 1024; // 100KB per script
/// Maximum total script content size in bytes (500KB total across all scripts)
/// Limits the total amount of JavaScript we execute to prevent DoS attacks
pub const MAX_TOTAL_SCRIPT_CONTENT_SIZE: usize = 500 * 1024; // 500KB total across all scripts

// HTML text extraction limits
/// Maximum HTML text content to extract in characters (50KB)
/// Limits the amount of text we extract from HTML for performance
/// This prevents excessive memory usage on very large pages
pub const MAX_HTML_TEXT_EXTRACTION_CHARS: usize = 50_000;
/// Maximum HTML preview length in characters for debugging (500 chars)
/// Used when logging HTML previews for debugging purposes
pub const MAX_HTML_PREVIEW_CHARS: usize = 500;

// Error message and header size limits
/// Maximum error message length in characters (2000 chars)
/// Prevents database bloat from unbounded error messages
/// Error messages longer than this are truncated with a note about the original length
pub const MAX_ERROR_MESSAGE_LENGTH: usize = 2000;
/// Maximum HTTP header value length in characters (1000 chars)
/// Prevents database bloat from very long header values (e.g., accept-ch headers)
/// Header values longer than this are truncated
pub const MAX_HEADER_VALUE_LENGTH: usize = 1000;
/// Maximum JavaScript execution time in milliseconds (1 second)
/// Prevents infinite loops and CPU exhaustion attacks
pub const MAX_JS_EXECUTION_TIME_MS: u64 = 1000;
/// Maximum memory limit for QuickJS context in bytes (10MB)
/// Prevents memory exhaustion attacks
pub const MAX_JS_MEMORY_LIMIT: usize = 10 * 1024 * 1024;
/// Maximum number of external scripts to fetch per page
/// Set to 0 to disable external script fetching (faster, but may miss some technologies)
/// External script fetching can cause timeouts on slow sites
pub const MAX_EXTERNAL_SCRIPTS: usize = 0;

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
/// Maximum number of retry attempts (including initial attempt)
/// Set to 3 = initial attempt + 2 retries (total 3 attempts)
/// This prevents infinite retries and ensures we don't exceed URL_PROCESSING_TIMEOUT
pub const RETRY_MAX_ATTEMPTS: usize = 3;

// Status server and batch writer timing
/// Status server logging interval in seconds (when status server is enabled)
pub const STATUS_SERVER_LOGGING_INTERVAL_SECS: u64 = 30;
/// Batch writer shutdown sleep duration in milliseconds
/// Brief pause to allow in-flight sends to complete before awaiting batch writer
pub const BATCH_WRITER_SHUTDOWN_SLEEP_MS: u64 = 100;
/// Batch writer shutdown timeout in seconds
/// Maximum time to wait for batch writer to finish before aborting
pub const BATCH_WRITER_SHUTDOWN_TIMEOUT_SECS: u64 = 30;

// HTTP status codes (for clarity and consistency)
pub const HTTP_STATUS_TOO_MANY_REQUESTS: u16 = 429;

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

    /// Initial requests per second (adaptive rate limiting always enabled)
    ///
    /// Rate limiting automatically adjusts based on error rates:
    /// - Starts at this RPS value
    /// - Reduces by 50% when error rate exceeds threshold (default: 20%)
    /// - Increases by 10% when error rate is below threshold
    /// - Minimum RPS: 1, Maximum RPS: this initial value
    ///
    /// Set to 0 to disable rate limiting (not recommended for production).
    #[arg(long, default_value_t = 10)]
    pub rate_limit_rps: u32,

    /// Error rate threshold for adaptive rate limiting (0.0-1.0, default: 0.2 = 20%)
    ///
    /// When error rate (429s + timeouts) exceeds this threshold, RPS is reduced.
    /// Advanced option - default 20% works well for most cases.
    #[arg(long, default_value_t = 0.2, hide = true)]
    pub adaptive_error_threshold: f64,

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

    /// HTTP status server port (optional, disabled by default)
    ///
    /// When set, starts a lightweight HTTP server that exposes:
    /// - `/metrics` - Prometheus-compatible metrics
    /// - `/status` - JSON status endpoint with progress information
    ///
    /// Useful for monitoring long-running jobs. The server runs in the background
    /// and does not block URL processing. Example: `--status-port 8080`
    #[arg(long)]
    pub status_port: Option<u16>,

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
    pub enable_whois: bool,
}
