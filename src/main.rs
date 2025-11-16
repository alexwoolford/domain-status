// main.rs
use anyhow::{Context, Result};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use clap::Parser;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use log::info;
use log::warn;
use regex::Regex;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_util::sync::CancellationToken;

use config::*;
use database::*;
use initialization::*;
use strum::IntoEnumIterator;
use utils::*;

use crate::error_handling::{ErrorStats, ErrorType};

mod config;
mod database;
mod dns;
mod domain;
mod error_handling;
mod html;
mod http;
mod initialization;
mod models;
mod tech_detection;
mod tls;
mod utils;

/// Logs progress information about URL processing.
///
/// # Arguments
///
/// * `start_time` - The start time of processing
/// * `completed_urls` - Atomic counter of completed URLs
fn log_progress(start_time: std::time::Instant, completed_urls: &Arc<AtomicUsize>) {
    let elapsed = start_time.elapsed();
    let completed = completed_urls.load(Ordering::SeqCst);
    let elapsed_secs = elapsed.as_secs_f64();
    let rate = if elapsed_secs > 0.0 {
        completed as f64 / elapsed_secs
    } else {
        0.0
    };
    info!(
        "Processed {} lines in {:.2} seconds (~{:.2} lines/sec)",
        completed, elapsed_secs, rate
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    let log_level = opt.log_level.clone();
    let log_format = opt.log_format.clone();
    init_logger_with(log_level.into(), log_format).context("Failed to initialize logger")?;
    init_crypto_provider();

    let file = tokio::fs::File::open(&opt.file)
        .await
        .context("Failed to open input file")?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut tasks = FuturesUnordered::new();

    let semaphore = init_semaphore(opt.max_concurrency);
    let rate_burst = if opt.rate_burst == 0 {
        opt.max_concurrency
    } else {
        opt.rate_burst
    };
    let (request_limiter, rate_limiter_shutdown) =
        match init_rate_limiter(opt.rate_limit_rps, rate_burst) {
            Some((limiter, shutdown)) => (Some(limiter), Some(shutdown)),
            None => (None, None),
        };

    // Override DB path env for init if needed
    std::env::set_var(
        "URL_CHECKER_DB_PATH",
        opt.db_path.to_string_lossy().to_string(),
    );

    let pool = init_db_pool()
        .await
        .context("Failed to initialize database pool")?;
    let client = init_client(&opt)
        .await
        .context("Failed to initialize HTTP client")?;
    let redirect_client = init_redirect_client(&opt)
        .await
        .context("Failed to initialize redirect client")?;
    let extractor = init_extractor();
    let resolver = init_resolver().context("Failed to initialize DNS resolver")?;

    run_migrations(&pool)
        .await
        .context("Failed to run database migrations")?;

    // Initialize technology fingerprint ruleset
    tech_detection::init_ruleset(opt.fingerprints.as_deref(), None)
        .await
        .context("Failed to initialize fingerprint ruleset")?;

    let start_time = std::time::Instant::now();

    let error_stats = Arc::new(ErrorStats::new());

    let completed_urls = Arc::new(AtomicUsize::new(0));

    let url_regex = Regex::new(crate::config::URL_SCHEME_PATTERN)
        .map_err(|e| anyhow::anyhow!("Failed to compile URL regex pattern: {}", e))?;

    loop {
        let line_result = lines.next_line().await;
        let url = match line_result {
            Ok(Some(line)) => {
                if !url_regex.is_match(&line) {
                    format!("https://{line}")
                } else {
                    line
                }
            }
            Ok(None) => break, // EOF reached
            Err(e) => {
                warn!("Failed to read line from input file: {e}");
                continue;
            }
        };

        // Validate URL: only allow http/https and syntactically valid
        match url::Url::parse(&url) {
            Ok(parsed) => match parsed.scheme() {
                "http" | "https" => {}
                _ => {
                    warn!("Skipping unsupported scheme for URL: {url}");
                    continue;
                }
            },
            Err(_) => {
                warn!("Skipping invalid URL: {url}");
                continue;
            }
        }

        let permit = match Arc::clone(&semaphore).acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                warn!("Semaphore closed, skipping URL: {url}");
                continue;
            }
        };

        let client_clone = Arc::clone(&client);
        let redirect_client_clone = Arc::clone(&redirect_client);
        let pool_clone = Arc::clone(&pool);
        let extractor_clone = Arc::clone(&extractor);
        let resolver_clone = Arc::clone(&resolver);

        let completed_urls_clone = Arc::clone(&completed_urls);

        let error_stats_clone = error_stats.clone();

        // Wrap URL in Arc to avoid cloning on retries
        let url_arc = Arc::new(url);

        let request_limiter_clone = request_limiter.as_ref().map(Arc::clone);
        tasks.push(tokio::spawn(async move {
            let _permit = permit;

            if let Some(ref limiter) = request_limiter_clone {
                limiter.acquire().await;
            }

            // Clone Arc for error messages (cheap - just pointer increment)
            let url_for_logging = Arc::clone(&url_arc);

            let result = tokio::time::timeout(
                URL_PROCESSING_TIMEOUT,
                process_url(
                    url_arc,
                    client_clone,
                    redirect_client_clone,
                    pool_clone,
                    extractor_clone,
                    resolver_clone,
                    error_stats_clone.clone(),
                ),
            )
            .await;

            match result {
                Ok(Ok(())) => {
                    completed_urls_clone.fetch_add(1, Ordering::SeqCst);
                }
                Ok(Err(e)) => {
                    log::warn!("Failed to process URL {url_for_logging}: {e}");
                    error_stats_clone.increment(ErrorType::HttpRequestOtherError);
                }
                Err(_) => {
                    log::warn!("Timeout processing URL {url_for_logging}");
                    error_stats_clone.increment(ErrorType::ProcessUrlTimeout);
                }
            }
        }));
    }

    // Cancellation token for graceful shutdown of periodic logging
    let cancel = CancellationToken::new();
    let cancel_logging = cancel.child_token();

    // Clone the Arc before the logging task
    let completed_urls_clone_for_logging = Arc::clone(&completed_urls);

    let logging_task = tokio::task::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(LOGGING_INTERVAL as u64));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    log_progress(start_time, &completed_urls_clone_for_logging);
                }
                _ = cancel_logging.cancelled() => {
                    break;
                }
            }
        }
    });

    while (tasks.next().await).is_some() {}

    // Signal logging task to stop and await it
    cancel.cancel();
    let _ = logging_task.await;

    // Signal rate limiter to stop if it exists
    if let Some(shutdown) = rate_limiter_shutdown {
        shutdown.cancel();
    }

    // Log one final time before printing the error summary
    log_progress(start_time, &completed_urls);

    // Print the error counts
    info!("Error Counts:");
    for error_type in ErrorType::iter() {
        if error_stats.get_count(error_type) > 0 {
            info!(
                "   {}: {}",
                error_type.as_str(),
                error_stats.get_count(error_type)
            );
        }
    }

    Ok(())
}
