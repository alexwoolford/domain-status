use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use crate::config::Opt;
use hickory_resolver::TokioAsyncResolver;
use publicsuffix::List;
use reqwest::ClientBuilder;
use tokio::sync::Semaphore;
use tokio::sync::Semaphore as TokioSemaphore;
use tokio::time::{interval, Duration as TokioDuration};

use crate::config::LogFormat;
use crate::error_handling::InitializationError;
use colored::*;
use log::LevelFilter;
use rustls::crypto::{ring::default_provider, CryptoProvider};

/// Initializes the logger with the specified level and format.
///
/// Configures `env_logger` with custom formatting. Supports both plain text
/// (with colors and emojis) and JSON formats for structured logging.
///
/// # Arguments
///
/// * `level` - Minimum log level to display
/// * `format` - Log format (Plain or Json)
///
/// # Returns
///
/// `Ok(())` if initialization succeeds, or an error if logger setup fails.
///
/// # Errors
///
/// Returns `InitializationError::LoggerError` if logger initialization fails.
pub fn init_logger_with(level: LevelFilter, format: LogFormat) -> Result<(), InitializationError> {
    colored::control::set_override(true);

    let mut builder = env_logger::Builder::new();

    // Set base level
    builder.filter_level(level);
    builder.filter_module("html5ever", LevelFilter::Error);
    builder.filter_module("sqlx", LevelFilter::Info);
    builder.filter_module("reqwest", LevelFilter::Info);
    builder.filter_module("hyper", LevelFilter::Info);
    builder.filter_module("selectors", LevelFilter::Warn);
    // Suppress hickory UDP client stream warnings about malformed DNS messages
    // These are expected when DNS responses are truncated or malformed, and hickory handles them gracefully
    // Filter all hickory_proto warnings to Error level to suppress UDP malformed message warnings
    builder.filter_module("hickory_proto", LevelFilter::Error);
    builder.filter_module("domain_status", level);

    match format {
        LogFormat::Json => {
            builder.format(|buf, record| {
                writeln!(
                    buf,
                    "{{\"ts\":{},\"level\":\"{}\",\"target\":\"{}\",\"msg\":{}}}",
                    chrono::Utc::now().timestamp_millis(),
                    record.level(),
                    record.target(),
                    serde_json::to_string(&record.args().to_string())
                        .unwrap_or_else(|_| "\"\"".into())
                )
            });
        }
        LogFormat::Plain => {
            builder.format(|buf, record| {
                let level = record.level();
                let colored_level = match level {
                    log::Level::Error => level.to_string().red(),
                    log::Level::Warn => level.to_string().yellow(),
                    log::Level::Info => level.to_string().green(),
                    log::Level::Debug => level.to_string().blue(),
                    log::Level::Trace => level.to_string().purple(),
                };

                let emoji = match level {
                    log::Level::Error => "❌",
                    log::Level::Warn => "⚠️",
                    log::Level::Info => "✔️",
                    log::Level::Debug => "🔍",
                    log::Level::Trace => "🔬",
                };

                writeln!(
                    buf,
                    "{} {} [{}] {}",
                    emoji,
                    record.target().cyan(),
                    colored_level,
                    record.args()
                )
            });
        }
    }

    builder.init();

    Ok(())
}

/// Initializes a semaphore for controlling concurrency.
///
/// Creates a new semaphore with the specified permit count. This semaphore is used
/// to limit the number of concurrent URL processing tasks.
///
/// # Arguments
///
/// * `count` - Maximum number of concurrent operations allowed
///
/// # Returns
///
/// An `Arc<Semaphore>` that can be shared across multiple tasks.
pub fn init_semaphore(count: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(count))
}

/// Initializes the HTTP client with default settings.
///
/// Creates a `reqwest::Client` configured with:
/// - User-Agent header from options
/// - Timeout from options
/// - Redirect following enabled (up to 10 hops)
/// - HTTP/2 support enabled
/// - Rustls TLS backend (no native TLS)
///
/// # Arguments
///
/// * `opt` - Command-line options containing user-agent and timeout settings
///
/// # Returns
///
/// A configured HTTP client ready for making requests.
///
/// # Errors
///
/// Returns a `reqwest::Error` if client creation fails.
pub async fn init_client(opt: &Opt) -> Result<Arc<reqwest::Client>, reqwest::Error> {
    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(opt.timeout_seconds))
        .user_agent(opt.user_agent.clone())
        .build()?;
    Ok(Arc::new(client))
}

/// Initializes a shared HTTP client for redirect resolution.
///
/// Creates a `reqwest::Client` with redirects disabled so we can manually track
/// the redirect chain. This allows us to capture the full redirect path including
/// intermediate URLs.
///
/// # Arguments
///
/// * `opt` - Command-line options containing user-agent and timeout settings
///
/// # Returns
///
/// A configured HTTP client with redirects disabled.
///
/// # Errors
///
/// Returns a `reqwest::Error` if client creation fails.
pub async fn init_redirect_client(opt: &Opt) -> Result<Arc<reqwest::Client>, reqwest::Error> {
    let client = ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(opt.timeout_seconds))
        .user_agent(opt.user_agent.clone())
        .build()?;
    Ok(Arc::new(client))
}

/// Initializes the Public Suffix List extractor.
///
/// Creates a new `publicsuffix::List` instance for extracting registrable domains
/// from URLs. The list is loaded from the built-in data.
///
/// # Returns
///
/// An `Arc<List>` that can be shared across multiple tasks for domain extraction.
pub fn init_extractor() -> Arc<List> {
    Arc::new(List::new())
}

/// Initializes the crypto provider for TLS operations.
///
/// Configures the global crypto provider for `rustls`. This must be called before
/// any TLS connections are established. Uses the default provider which supports
/// all standard TLS features.
pub fn init_crypto_provider() {
    // The return value is ignored because reinstalling the provider is harmless
    let _ = CryptoProvider::install_default(default_provider());
}

/// Initializes the DNS resolver for hostname lookups.
///
/// Creates a DNS resolver using default configuration (Google DNS: 8.8.8.8, 8.8.4.4)
/// with aggressive timeouts to prevent hanging on slow or unresponsive DNS servers.
///
/// The resolver supports both forward lookups (hostname → IP) and reverse lookups
/// (IP → hostname) using PTR records.
///
/// Timeouts are configured to prevent hanging on slow or unresponsive DNS servers.
///
/// # Returns
///
/// A configured `TokioAsyncResolver` wrapped in `Arc` for sharing across tasks,
/// or an error if initialization fails.
///
/// # Errors
///
/// Returns `InitializationError::DnsResolverError` if both system and fallback
/// configurations fail (though fallback should rarely fail).
pub fn init_resolver() -> Result<Arc<TokioAsyncResolver>, InitializationError> {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};

    // Configure DNS resolver with timeouts
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(crate::config::DNS_TIMEOUT_SECS);
    opts.attempts = 2; // Reduce retry attempts to fail faster
                       // Set ndots to 0 to prevent search domain appending (preserved from 0.25 workaround)
    opts.ndots = 0;

    // Use default resolver configuration with timeouts
    // This ensures consistent timeout behavior across all DNS queries
    // In hickory-resolver 0.24, use TokioAsyncResolver::tokio() with ResolverConfig::default()
    // This worked correctly and didn't have the search domain issues of 0.25
    Ok(Arc::new(TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        opts,
    )))
}

/// Token-bucket rate limiter for controlling request rate.
///
/// Implements a token bucket algorithm where tokens are replenished at a fixed
/// rate (requests per second). Each request consumes a token, and requests
/// are blocked when no tokens are available.
///
/// # Behavior
///
/// - Tokens are replenished continuously at the specified rate
/// - Burst capacity allows short bursts above the base rate
/// - Uses a background task for token replenishment
/// - Supports graceful shutdown via `CancellationToken`
/// - Supports dynamic RPS updates (for adaptive rate limiting)
pub struct RateLimiter {
    permits: Arc<TokioSemaphore>,
    #[allow(dead_code)]
    capacity: usize,
    current_rps: Arc<std::sync::atomic::AtomicU32>,
    #[allow(dead_code)] // Used for cancellation token reference
    shutdown: tokio_util::sync::CancellationToken,
}

impl RateLimiter {
    pub async fn acquire(&self) {
        let _ = self.permits.acquire().await;
    }

    /// Updates the current RPS value (for adaptive rate limiting).
    /// The background task will automatically adjust the token replenishment rate.
    pub fn update_rps(&self, new_rps: u32) {
        self.current_rps
            .store(new_rps, std::sync::atomic::Ordering::SeqCst);
    }

    /// Gets the current RPS value.
    ///
    /// Useful for monitoring and debugging. The RPS may be dynamically updated
    /// by adaptive rate limiting, so this value may change between calls.
    #[allow(dead_code)] // Useful for debugging/monitoring, may be used in future
    pub fn current_rps(&self) -> u32 {
        self.current_rps.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Initializes a token-bucket rate limiter.
///
/// Creates a rate limiter that controls request rate using a token bucket algorithm.
/// If `rps` is 0, rate limiting is disabled and `None` is returned.
///
/// # Arguments
///
/// * `rps` - Requests per second (0 disables rate limiting)
/// * `burst` - Burst capacity (maximum tokens in bucket)
///
/// # Returns
///
/// A tuple of `(RateLimiter, CancellationToken)` if rate limiting is enabled,
/// or `None` if disabled. The cancellation token can be used to gracefully shut
/// down the background token replenishment task.
pub fn init_rate_limiter(
    rps: u32,
    burst: usize,
) -> Option<(Arc<RateLimiter>, tokio_util::sync::CancellationToken)> {
    if rps == 0 {
        return None;
    }
    let capacity = burst;
    let shutdown = tokio_util::sync::CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    let current_rps = Arc::new(std::sync::atomic::AtomicU32::new(rps));
    let limiter = Arc::new(RateLimiter {
        permits: Arc::new(TokioSemaphore::new(capacity)),
        capacity,
        current_rps: Arc::clone(&current_rps),
        shutdown: shutdown_clone.clone(),
    });

    let permits = limiter.permits.clone();
    let rps_for_ticker = Arc::clone(&current_rps);
    // Use a fast ticker (every 100ms) and calculate how many permits to add based on current RPS
    let mut ticker = interval(TokioDuration::from_millis(100));
    tokio::spawn(async move {
        let mut last_time = tokio::time::Instant::now();
        let mut fractional_permits = 0.0f64; // Track fractional permits to avoid precision loss
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let now = tokio::time::Instant::now();
                    let elapsed = now.duration_since(last_time);
                    let current_rps_value = rps_for_ticker.load(std::sync::atomic::Ordering::SeqCst);

                    if current_rps_value > 0 {
                        // Calculate how many permits to add based on elapsed time and current RPS
                        // For example, if RPS is 10 and 100ms elapsed, we should add 1 permit (10 * 0.1 = 1)
                        let permits_to_add_f64 = current_rps_value as f64 * elapsed.as_secs_f64() + fractional_permits;
                        let permits_to_add = permits_to_add_f64 as u32;
                        fractional_permits = permits_to_add_f64 - permits_to_add as f64;

                        if permits_to_add > 0 {
                            permits.add_permits(permits_to_add as usize);
                        }
                    }

                    last_time = now;
                }
                _ = shutdown_clone.cancelled() => {
                    log::debug!("Rate limiter background task shutting down");
                    break;
                }
            }
        }
    });

    Some((limiter, shutdown))
}
