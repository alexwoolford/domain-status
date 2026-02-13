//! Scan resources and state management.
//!
//! This module defines the `ScanResources` struct which holds all initialized
//! resources needed for a URL scan operation.

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

/// Type alias for progress callback function.
pub type ProgressCallback = Option<Arc<dyn Fn(usize, usize, usize) + Send + Sync>>;

use tokio::io::Lines;
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;

use crate::adaptive_rate_limiter::AdaptiveRateLimiter;
use crate::config::Config;
use crate::error_handling::ProcessingStats;
use crate::fetch::ProcessingContext;
use crate::fingerprint::FingerprintRuleset;
use crate::geoip::GeoIpMetadata;
use crate::initialization::RateLimiter;
use crate::storage::DbPool;
use crate::utils::TimingStats;

/// All resources initialized for a scan operation.
///
/// This struct holds ownership of all the resources needed to execute
/// a URL scan, including database connections, HTTP clients, rate limiters,
/// and various statistics trackers.
pub struct ScanResources {
    // Database
    /// Database connection pool
    pub pool: DbPool,
    /// Database write circuit breaker for resilience (passed to ProcessingContext)
    #[allow(dead_code)]
    pub db_circuit_breaker: Arc<crate::storage::circuit_breaker::DbWriteCircuitBreaker>,

    // Network clients (via ProcessingContext)
    /// Shared processing context containing network clients and config
    pub shared_ctx: Arc<ProcessingContext>,

    // Rate limiting
    /// Concurrency semaphore to limit parallel requests
    pub semaphore: Arc<tokio::sync::Semaphore>,
    /// Optional rate limiter for requests per second
    pub request_limiter: Option<Arc<RateLimiter>>,
    /// Shutdown handle for the rate limiter background task
    pub rate_limiter_shutdown: Option<CancellationToken>,
    /// Optional adaptive rate limiter that adjusts based on error rates
    pub adaptive_limiter: Option<Arc<AdaptiveRateLimiter>>,

    // Statistics tracking
    /// Error statistics tracker
    pub error_stats: Arc<ProcessingStats>,
    /// Timing statistics tracker
    pub timing_stats: Arc<TimingStats>,

    // Counters
    /// Count of successfully processed URLs
    pub completed_urls: Arc<AtomicUsize>,
    /// Count of failed URLs
    pub failed_urls: Arc<AtomicUsize>,
    /// Count of total URLs attempted
    pub total_urls_attempted: Arc<AtomicUsize>,
    /// Total number of URLs in the input file (0 for stdin)
    pub total_urls_in_file: Arc<AtomicUsize>,

    // Run metadata
    /// Unique run identifier (format: `run_<timestamp_millis>`)
    pub run_id: String,
    /// Start time as Unix timestamp in milliseconds (used for run metadata)
    #[allow(dead_code)]
    pub start_time_epoch: i64,
    /// Start time as Instant for elapsed time calculations
    pub start_time: std::time::Instant,

    // Fingerprinting and GeoIP
    /// Fingerprint detection ruleset (kept loaded during scan)
    #[allow(dead_code)]
    pub ruleset: Arc<FingerprintRuleset>,
    /// Optional GeoIP database metadata (kept for reference)
    #[allow(dead_code)]
    pub geoip_metadata: Option<GeoIpMetadata>,

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
}

/// Parameters for processing a single URL task.
///
/// This struct packages all the data needed by `process_url_task`.
pub struct UrlTaskParams {
    /// The URL to process
    pub url: Arc<str>,
    /// Shared processing context
    pub ctx: Arc<ProcessingContext>,
    /// Semaphore permit (dropped when task completes)
    pub permit: OwnedSemaphorePermit,
    /// Optional rate limiter
    pub request_limiter: Option<Arc<RateLimiter>>,
    /// Optional adaptive rate limiter
    pub adaptive_limiter: Option<Arc<AdaptiveRateLimiter>>,
    /// Completed URL counter
    pub completed_urls: Arc<AtomicUsize>,
    /// Failed URL counter
    pub failed_urls: Arc<AtomicUsize>,
    /// Total URLs (for progress callback)
    pub total_urls_for_callback: usize,
    /// Optional progress callback
    pub progress_callback: ProgressCallback,
}
