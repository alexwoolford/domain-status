//! Configuration constants.
//!
//! This module defines all configuration constants used throughout the application,
//! including timeouts, size limits, and other operational parameters.

use std::time::Duration;

// constants (used as defaults)
#[allow(dead_code)]
/// Maximum concurrent requests (semaphore limit)
/// Increased from 20 to 30 for better throughput while maintaining low bot detection risk
pub const SEMAPHORE_LIMIT: usize = 30;
pub const LOGGING_INTERVAL: usize = 5;
/// Per-URL processing timeout in seconds
/// Set to 35s to allow for slow sites while still being reasonable
/// Formula: HTTP timeout (10s) + DNS timeout (3s) + TCP/TLS timeouts (10s) + enrichment (5s) + buffer (7s) = ~35s
/// Note: DNS timeout reduced to 3s helps fail fast on DNS issues, but overall timeout kept at 35s
/// to account for enrichment operations (GeoIP, WHOIS, technology detection, etc.)
pub const URL_PROCESSING_TIMEOUT: Duration = Duration::from_secs(35);
pub const DB_PATH: &str = "./url_checker.db";

// Network operation timeouts
/// DNS query timeout in seconds
/// Reduced to 3s - most DNS queries complete in <1s, 3s provides good buffer while failing fast
/// This significantly reduces time wasted on slow/unresponsive DNS servers
pub const DNS_TIMEOUT_SECS: u64 = 3;
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
/// Reduced from 1000ms to 500ms for faster recovery while still providing backoff benefit
/// This reduces total retry overhead from ~3s to ~1.5s per failed request
pub const RETRY_INITIAL_DELAY_MS: u64 = 500;
/// Factor by which retry delay is multiplied on each attempt
pub const RETRY_FACTOR: u64 = 2;
/// Maximum delay between retries in seconds
/// Reduced from 20s to 15s for faster recovery from transient issues
pub const RETRY_MAX_DELAY_SECS: u64 = 15;
/// Maximum number of retry attempts (including initial attempt)
/// Set to 3 = initial attempt + 2 retries (total 3 attempts)
/// This prevents infinite retries and ensures we don't exceed URL_PROCESSING_TIMEOUT
pub const RETRY_MAX_ATTEMPTS: usize = 3;

// Status server timing
/// Status server logging interval in seconds (when status server is enabled)
pub const STATUS_SERVER_LOGGING_INTERVAL_SECS: u64 = 30;

// HTTP status codes (for clarity and consistency)
pub const HTTP_STATUS_TOO_MANY_REQUESTS: u16 = 429;
