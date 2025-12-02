//! Status server data structures.

use serde::Serialize;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Instant;

use crate::error_handling::ProcessingStats;

/// Shared state for the status server
#[derive(Clone)]
pub struct StatusState {
    pub total_urls: Arc<AtomicUsize>,
    pub completed_urls: Arc<AtomicUsize>,
    pub failed_urls: Arc<AtomicUsize>,
    pub start_time: Arc<Instant>,
    pub error_stats: Arc<ProcessingStats>,
    /// Total number of batch write failures (records that failed to insert)
    pub batch_write_failures: Arc<AtomicUsize>,
    /// Total number of successful batch writes
    pub batch_write_successes: Arc<AtomicUsize>,
}

/// JSON response for `/status` endpoint
#[derive(Serialize)]
pub struct StatusResponse {
    pub total_urls: usize,
    pub completed_urls: usize,
    pub failed_urls: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_urls: Option<usize>,
    pub percentage_complete: f64,
    pub elapsed_seconds: f64,
    pub rate_per_second: f64,
    pub errors: ErrorCounts,
    pub warnings: WarningCounts,
    pub info: InfoCounts,
    pub batch_writes: BatchWriteCounts,
}

#[derive(Serialize)]
pub struct ErrorCounts {
    pub total: usize,
    pub timeout: usize,
    pub connection_error: usize,
    pub http_error: usize,
    pub dns_error: usize,
    pub tls_error: usize,
    pub parse_error: usize,
    pub other_error: usize,
}

#[derive(Serialize)]
pub struct WarningCounts {
    pub total: usize,
    pub missing_meta_keywords: usize,
    pub missing_meta_description: usize,
    pub missing_title: usize,
}

#[derive(Serialize)]
pub struct InfoCounts {
    pub total: usize,
    pub http_redirect: usize,
    pub https_redirect: usize,
    pub bot_detection_403: usize,
    pub multiple_redirects: usize,
}

#[derive(Serialize)]
pub struct BatchWriteCounts {
    pub total_successful: usize,
    pub total_failed: usize,
}

