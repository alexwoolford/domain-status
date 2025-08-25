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

/// Initializes the logger for the application with the provided configuration.
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

/// Initializes a semaphore with the specified count.
pub fn init_semaphore(count: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(count))
}

/// Initializes the HTTP client with default settings.
pub async fn init_client(opt: &Opt) -> Result<Arc<reqwest::Client>, reqwest::Error> {
    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(opt.timeout_seconds))
        .user_agent(opt.user_agent.clone())
        .build()?;
    Ok(Arc::new(client))
}

/// Initializes a shared HTTP client for redirect resolution.
/// This client has redirects disabled so we can manually track the redirect chain.
pub async fn init_redirect_client(opt: &Opt) -> Result<Arc<reqwest::Client>, reqwest::Error> {
    let client = ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(opt.timeout_seconds))
        .user_agent(opt.user_agent.clone())
        .build()?;
    Ok(Arc::new(client))
}

/// Initializes the TLD extractor.
pub fn init_extractor() -> Arc<List> {
    Arc::new(List::new())
}

/// Installs the default CryptoProvider required by rustls.
pub fn init_crypto_provider() {
    // The return value is ignored because reinstalling the provider is harmless
    let _ = CryptoProvider::install_default(default_provider());
}

/// Initializes a shared DNS resolver from system configuration.
pub fn init_resolver() -> Result<Arc<TokioAsyncResolver>, InitializationError> {
    // Try system configuration first
    match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(resolver) => Ok(Arc::new(resolver)),
        Err(e) => {
            // Fallback: use default resolver configuration
            use hickory_resolver::config::{ResolverConfig, ResolverOpts};
            log::warn!(
                "Failed to initialize DNS resolver from system config ({e}), using defaults"
            );
            Ok(Arc::new(TokioAsyncResolver::tokio(
                ResolverConfig::default(),
                ResolverOpts::default(),
            )))
        }
    }
}

/// Simple token-bucket rate limiter
pub struct RateLimiter {
    permits: Arc<TokioSemaphore>,
    #[allow(dead_code)]
    capacity: usize,
    #[allow(dead_code)] // Used for cancellation token reference
    shutdown: tokio_util::sync::CancellationToken,
}

impl RateLimiter {
    pub async fn acquire(&self) {
        let _ = self.permits.acquire().await;
    }
}

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

    let limiter = Arc::new(RateLimiter {
        permits: Arc::new(TokioSemaphore::new(capacity)),
        capacity,
        shutdown: shutdown_clone.clone(),
    });

    let permits = limiter.permits.clone();
    let mut ticker = interval(TokioDuration::from_millis((1000 / rps.max(1)) as u64));
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    permits.add_permits(1);
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
