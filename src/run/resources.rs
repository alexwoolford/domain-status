//! Scan resources and state management.
//!
//! This module defines the `ScanResources` struct which holds all initialized
//! resources needed for a URL scan operation.

use std::collections::HashSet;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

/// Type alias for progress callback function (completed, failed, skipped, total).
pub type ProgressCallback = Option<Arc<dyn Fn(usize, usize, usize, usize) + Send + Sync>>;

use tokio::io::Lines;
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::fetch::ProcessingContext;
use crate::geoip::GeoIpMetadata;
use crate::initialization::RateLimiter;

/// All resources initialized for a scan operation.
///
/// Shared pool / stats / ruleset live on [`ProcessingContext`] (`shared_ctx`).
/// This struct keeps loop-level state: concurrency controls, counters, and
/// run metadata needed after the scan completes.
pub struct ScanResources {
    /// Shared processing context (pool, network, runtime stats, ruleset)
    pub shared_ctx: Arc<ProcessingContext>,

    // Rate limiting
    /// Concurrency semaphore to limit parallel requests
    pub semaphore: Arc<tokio::sync::Semaphore>,
    /// Optional rate limiter for requests per second
    pub request_limiter: Option<Arc<RateLimiter>>,
    /// Shutdown handle for the rate limiter background task
    pub rate_limiter_shutdown: Option<CancellationToken>,

    // In-flight URL registry — used by the drain phase to record a `url_failures`
    // row for every URL whose task is still running when the drain timeout fires,
    // so users see exactly which URLs were lost rather than only an aggregate
    // "X failed" count. Each spawned task adds its URL on entry and removes it on
    // exit via an RAII guard ([`InFlightGuard`] in `run/mod.rs`).
    //
    // `std::sync::Mutex` (not `tokio::sync::Mutex`) so `InFlightGuard::Drop` can
    // run synchronously when a task future is aborted at an `.await` point.
    /// Set of URLs whose tasks are currently in flight (registered/unregistered by RAII guard).
    pub in_flight_urls: Arc<Mutex<HashSet<String>>>,

    // Counters
    /// Count of URLs that produced a persisted `url_status` row
    pub successful_urls: Arc<AtomicUsize>,
    /// Count of URLs intentionally skipped before insert
    pub skipped_urls: Arc<AtomicUsize>,
    /// Count of failed URLs
    pub failed_urls: Arc<AtomicUsize>,
    /// Count of total URLs attempted
    pub total_urls_attempted: Arc<AtomicUsize>,
    /// Total number of URLs in the input file (0 for stdin)
    pub total_urls_in_file: Arc<AtomicUsize>,

    /// Live scan phase for status/metrics (`scanning` / `draining` / `finalizing`)
    pub phase: Arc<crate::status_server::AtomicPhase>,
    /// Shared windowed-throughput tracker for status/metrics ETA
    pub throughput_window: Arc<crate::status_server::ThroughputWindow>,

    // Run metadata
    /// Unique run identifier (format: `run_<timestamp_millis>`)
    pub run_id: String,
    /// Start time as Unix timestamp in milliseconds (used for run metadata)
    pub start_time_epoch: i64,
    /// Start time as Instant for elapsed time calculations
    pub start_time: std::time::Instant,

    /// Optional `GeoIP` database metadata (held to keep data alive during scan).
    pub _geoip_metadata: Option<GeoIpMetadata>,

    // Configuration
    /// Original configuration (for reference during finalization)
    pub config: Config,
}

/// Source of URLs to scan.
///
/// URLs can come from either a file or stdin.
pub enum UrlSource {
    /// URLs from a file
    File(Lines<tokio::io::BufReader<tokio::fs::File>>),
    /// URLs from stdin
    Stdin(Lines<tokio::io::BufReader<tokio::io::Stdin>>),
}

impl UrlSource {
    /// Read the next line from the URL source.
    ///
    /// Returns `Ok(Some(line))` if a line was read, `Ok(None)` if EOF,
    /// or an error if reading failed.
    pub async fn next_line(&mut self) -> std::io::Result<Option<String>> {
        match self {
            UrlSource::File(lines) => lines.next_line().await,
            UrlSource::Stdin(lines) => lines.next_line().await,
        }
    }
}

/// Result of scan loop execution.
///
/// Contains information needed for finalization after the main scan loop completes.
pub struct ScanLoopResult {
    /// Cancellation token for logging task
    pub cancel: CancellationToken,
    /// Handle to the logging task
    pub logging_task: Option<tokio::task::JoinHandle<()>>,
    /// Optional managed status server
    pub status_server: Option<crate::status_server::StatusServerHandle>,
}

/// Parameters for processing a single URL task.
///
/// This struct packages all the data needed by `process_url_task`.
pub struct UrlTaskParams {
    /// The URL to process
    pub url: Arc<str>,
    /// Shared processing context
    pub ctx: Arc<ProcessingContext>,
    /// Cancellation token so workers can respond to Ctrl-C
    pub cancel: CancellationToken,
    /// Semaphore permit (dropped when task completes)
    pub permit: OwnedSemaphorePermit,
    /// Optional rate limiter
    pub request_limiter: Option<Arc<RateLimiter>>,
    /// Persisted-success counter
    pub successful_urls: Arc<AtomicUsize>,
    /// Skipped-without-insert counter
    pub skipped_urls: Arc<AtomicUsize>,
    /// Failed URL counter
    pub failed_urls: Arc<AtomicUsize>,
    /// Total URLs (for progress callback)
    pub total_urls_for_callback: usize,
    /// Optional progress callback
    pub progress_callback: ProgressCallback,
}
