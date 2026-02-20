//! Scan resource initialization.
//!
//! This module contains the `init_scan_resources` function which handles
//! all setup and initialization before the main scan loop begins.

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::Utc;
use log::{info, warn};
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::adaptive_rate_limiter::AdaptiveRateLimiter;
use crate::config::{Config, DEFAULT_USER_AGENT};
use crate::error_handling::ProcessingStats;
use crate::fetch::{ConfigContext, DatabaseContext, NetworkContext, ProcessingContext};
use crate::initialization::*;
use crate::storage::{init_db_pool_with_path, insert_run_metadata, RunMetadata};
use crate::utils::TimingStats;

use super::resources::{ScanResources, UrlSource};

/// Type alias for the progress callback function.
pub type ProgressCallback = Option<Arc<dyn Fn(usize, usize, usize) + Send + Sync>>;

/// Initialize all resources needed for a scan.
///
/// This function performs the following initialization steps:
/// 1. Validate and normalize configuration
/// 2. Count URLs in input file (unless stdin)
/// 3. Set up rate limiting and concurrency control
/// 4. Initialize database connection pool
/// 5. Initialize HTTP clients and DNS resolver
/// 6. Run database migrations
/// 7. Initialize fingerprint ruleset and GeoIP database
/// 8. Create run metadata record
/// 9. Set up shared processing context
///
/// # Arguments
///
/// * `config` - The scan configuration
///
/// # Returns
///
/// Returns a tuple of:
/// - `ScanResources` - All initialized resources
/// - `UrlSource` - The URL input source (file or stdin)
/// - `usize` - Total number of URLs (0 for stdin)
/// - `ProgressCallback` - Optional progress callback from config
///
/// # Errors
///
/// Returns an error if any initialization step fails.
#[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
pub async fn init_scan_resources(
    mut config: Config,
) -> Result<(ScanResources, UrlSource, usize, ProgressCallback)> {
    // Validate configuration before starting
    config
        .validate()
        .map_err(|e| anyhow::anyhow!("Configuration validation failed: {}", e))?;

    // Update user agent if using default
    if config.user_agent == DEFAULT_USER_AGENT {
        let updated_ua = crate::user_agent::get_default_user_agent(None).await;
        config.user_agent = updated_ua;
        log::debug!("Using auto-updated User-Agent: {}", config.user_agent);
    }

    // Determine URL source and count
    let (total_lines, is_stdin) = if config.file.as_os_str() == "-" {
        info!("Reading URLs from stdin");
        (0, true)
    } else {
        let file_for_counting = tokio::fs::File::open(&config.file)
            .await
            .context("Failed to open input file for line counting")?;
        let reader = BufReader::new(file_for_counting);
        let mut count = 0usize;
        let mut counting_lines = reader.lines();
        while let Ok(Some(line)) = counting_lines.next_line().await {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                count += 1;
            }
        }
        info!("Total URLs in file: {}", count);
        (count, false)
    };

    // Create URL source
    let url_source = if is_stdin {
        use tokio::io::stdin;
        UrlSource::Stdin(BufReader::new(stdin()).lines())
    } else {
        let file = tokio::fs::File::open(&config.file)
            .await
            .context("Failed to open input file")?;
        UrlSource::File(BufReader::new(file).lines())
    };

    // Initialize rate limiting
    let semaphore = init_semaphore(config.max_concurrency);
    let rate_burst = if config.rate_limit_rps > 0 {
        let rps_doubled = config.rate_limit_rps.saturating_mul(2);
        std::cmp::min(config.max_concurrency, rps_doubled as usize)
    } else {
        config.max_concurrency
    };
    let (request_limiter, rate_limiter_shutdown) =
        match init_rate_limiter(config.rate_limit_rps, rate_burst) {
            Some((limiter, shutdown)) => (Some(limiter), Some(shutdown)),
            None => (None, None),
        };

    // Initialize adaptive rate limiter
    let adaptive_limiter = if config.rate_limit_rps > 0 {
        let max_rps = config.rate_limit_rps.saturating_mul(2);
        let adaptive = Arc::new(AdaptiveRateLimiter::new(
            config.rate_limit_rps,
            Some(1),
            Some(max_rps),
            Some(config.adaptive_error_threshold),
            None,
            None,
        ));

        if let Some(ref rate_limiter) = request_limiter {
            let rate_limiter_clone = Arc::clone(rate_limiter);
            let _shutdown_token = adaptive.start_adaptive_adjustment(
                move |new_rps| {
                    rate_limiter_clone.update_rps(new_rps);
                },
                None,
            );
        }

        Some(adaptive)
    } else {
        None
    };

    // Initialize database -- size the pool to match concurrency so workers don't starve
    #[allow(clippy::cast_possible_truncation)]
    let pool_size = (config.max_concurrency as u32).max(1);
    let pool = init_db_pool_with_path(&config.db_path, pool_size)
        .await
        .context("Failed to initialize database pool")?;

    // Initialize network clients
    let client = init_client(&config)
        .await
        .context("Failed to initialize HTTP client")?;
    let redirect_client = init_redirect_client(&config)
        .await
        .context("Failed to initialize redirect client")?;
    let extractor = init_extractor();
    let resolver = init_resolver().context("Failed to initialize DNS resolver")?;

    // Run migrations
    crate::storage::run_migrations(&pool)
        .await
        .context("Failed to run database migrations")?;

    if config.enable_whois {
        info!("WHOIS/RDAP lookup enabled (rate limit: 1 query per 2 seconds)");
    }

    // Initialize fingerprint ruleset
    let ruleset = crate::fingerprint::init_ruleset(config.fingerprints.as_deref(), None)
        .await
        .context("Failed to initialize fingerprint ruleset")?;

    // Initialize GeoIP database
    let geoip_metadata = match crate::geoip::init_geoip(config.geoip.as_deref(), None).await {
        Ok(metadata) => metadata,
        Err(e) => {
            warn!(
                "Failed to initialize GeoIP database: {}. Continuing without GeoIP lookup.",
                e
            );
            warn!("To enable GeoIP, ensure MAXMIND_LICENSE_KEY in .env is valid and your MaxMind account has GeoLite2 access.");
            None
        }
    };

    // Create run metadata
    let start_time_epoch = Utc::now().timestamp_millis();
    let run_id = format!("run_{}", start_time_epoch);
    info!("Starting run: {}", run_id);

    let meta = RunMetadata {
        run_id: &run_id,
        start_time_ms: start_time_epoch,
        version: env!("CARGO_PKG_VERSION"),
        fingerprints_source: Some(ruleset.metadata.source.as_str()),
        fingerprints_version: Some(ruleset.metadata.version.as_str()),
        geoip_version: geoip_metadata.as_ref().map(|m| m.version.as_str()),
    };
    insert_run_metadata(&pool, &meta)
        .await
        .context("Failed to insert run metadata")?;

    // Initialize timing and statistics
    let start_time = std::time::Instant::now();
    let error_stats = Arc::new(ProcessingStats::new());
    let timing_stats = Arc::new(TimingStats::new());

    // Initialize circuit breaker
    let db_circuit_breaker =
        Arc::new(crate::storage::circuit_breaker::DbWriteCircuitBreaker::new());
    info!("Database write circuit breaker initialized (threshold: 5 failures, cooldown: 60s)");

    // Initialize counters
    let completed_urls = Arc::new(AtomicUsize::new(0));
    let failed_urls = Arc::new(AtomicUsize::new(0));
    let total_urls_attempted = Arc::new(AtomicUsize::new(0));
    let total_urls_in_file = Arc::new(AtomicUsize::new(total_lines));

    // Clone progress callback
    let progress_callback = config.progress_callback.clone();

    // Create shared processing context
    let shared_ctx = Arc::new(ProcessingContext::new(
        NetworkContext::new(
            Arc::clone(&client),
            Arc::clone(&redirect_client),
            Arc::clone(&extractor),
            Arc::clone(&resolver),
        ),
        DatabaseContext::new(Arc::clone(&pool), Arc::clone(&db_circuit_breaker)),
        ConfigContext::new(
            error_stats.clone(),
            Arc::clone(&timing_stats),
            Some(run_id.clone()),
            config.enable_whois,
        ),
    ));

    let resources = ScanResources {
        pool,
        db_circuit_breaker,
        shared_ctx,
        semaphore,
        request_limiter,
        rate_limiter_shutdown,
        adaptive_limiter,
        error_stats,
        timing_stats,
        completed_urls,
        failed_urls,
        total_urls_attempted,
        total_urls_in_file,
        run_id,
        start_time_epoch,
        start_time,
        ruleset,
        geoip_metadata,
        config,
    };

    Ok((resources, url_source, total_lines, progress_callback))
}
