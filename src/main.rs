// main.rs
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use log::info;
use log::warn;
use structopt::StructOpt;
use validators::regex::Regex;

use config::*;
use database::*;
use initialization::*;
use strum::IntoEnumIterator;
use utils::*;

use crate::error_handling::{ErrorRateLimiter, ErrorStats, ErrorType};

mod config;
mod initialization;
mod database;
mod utils;
mod error_handling;

fn log_progress(start_time: std::time::Instant, completed_urls: &Arc<AtomicUsize>) {
    let elapsed = start_time.elapsed();
    let completed = completed_urls.load(Ordering::SeqCst);
    info!(
        "Processed {} lines in {:.2} seconds (~{:.2} lines/sec)",
        completed,
        elapsed.as_secs_f64(),
        completed as f64 / elapsed.as_secs_f64()
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logger().context("Failed to initialize logger")?;

    let opt = Opt::from_args();
    let file = File::open(&opt.file).context("Failed to open input file")?;
    let reader = BufReader::new(file);

    let mut tasks = FuturesUnordered::new();

    let semaphore = init_semaphore(SEMAPHORE_LIMIT);

    let pool = init_db_pool().await.context("Failed to initialize database pool")?;
    let client = init_client().await.context("Failed to initialize HTTP client")?;
    let extractor = init_extractor();

    create_table(&pool).await.context("Failed to create table")?;

    let start_time = std::time::Instant::now();

    let error_stats = Arc::new(ErrorStats::new());

    let rate_limiter = ErrorRateLimiter::new(error_stats.clone(), opt.error_rate);

    let completed_urls = Arc::new(AtomicUsize::new(0));

    let url_regex = Regex::new(r"^https?://").unwrap();

    for line in reader.lines() {
        let url = match line {
            Ok(line) => {
                if !url_regex.is_match(&line) {
                    format!("https://{}", line)
                } else {
                    line
                }
            }
            Err(e) => {
                warn!("Failed to read line from input file: {}", e);
                continue;
            }
        };

        rate_limiter.allow_operation().await;

        let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();

        let client_clone = Arc::clone(&client);
        let pool_clone = Arc::clone(&pool);
        let extractor_clone = Arc::clone(&extractor);

        let completed_urls_clone = Arc::clone(&completed_urls);

        let error_stats_clone = error_stats.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = permit;

            let result = tokio::time::timeout(URL_PROCESSING_TIMEOUT, process_url(
                url,
                client_clone,
                pool_clone,
                extractor_clone,
                error_stats_clone.clone(),
            )).await;

            match result {
                Ok(()) => {
                    completed_urls_clone.fetch_add(1, Ordering::SeqCst);
                }
                Err(_) => {
                    error_stats_clone.increment(ErrorType::ProcessUrlTimeout);
                }
            }
        }));
    }

    // Clone the Arc before the logging task
    let completed_urls_clone_for_logging = Arc::clone(&completed_urls);

    let logging_task = tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(LOGGING_INTERVAL as u64));
        loop {
            interval.tick().await;
            log_progress(start_time, &completed_urls_clone_for_logging);
        }
    });

    while let Some(_) = tasks.next().await {}

    // Ensure the logging task is done before exiting
    drop(logging_task);

    // Log one final time before printing the error summary
    log_progress(start_time, &completed_urls);

    // Print the error counts
    info!("Error Counts:");
    for error_type in ErrorType::iter() {
        if error_stats.get_count(error_type) > 0 {
            info!(
                "   {}: {}",
                error_type.to_string(),
                error_stats.get_count(error_type)
            );
        }
    }

    Ok(())
}
