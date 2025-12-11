//! Status server data structures.

use serde::Serialize;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Instant;

use crate::error_handling::ProcessingStats;
use crate::utils::TimingStats;

/// Shared state for the status server
#[derive(Clone)]
pub struct StatusState {
    /// Total lines in the input file (non-empty, non-comment lines)
    /// This is used for progress calculations to show progress against all URLs in the file
    pub total_urls: Arc<AtomicUsize>,
    /// Total URLs that have been attempted (valid URLs that passed validation)
    /// Used in lib.rs for logging and statistics, but not in status server handlers
    #[allow(dead_code)]
    pub total_urls_attempted: Arc<AtomicUsize>,
    pub completed_urls: Arc<AtomicUsize>,
    pub failed_urls: Arc<AtomicUsize>,
    pub start_time: Arc<Instant>,
    pub error_stats: Arc<ProcessingStats>,
    /// Timing statistics for performance monitoring
    pub timing_stats: Option<Arc<TimingStats>>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<TimingSummary>,
}

/// Timing summary for status endpoint
#[derive(Serialize)]
pub struct TimingSummary {
    pub count: u64,
    pub averages: TimingMetrics,
}

/// Timing metrics in milliseconds
#[derive(Serialize)]
pub struct TimingMetrics {
    pub http_request_ms: u64,
    pub dns_forward_ms: u64,
    pub dns_reverse_ms: u64,
    pub dns_additional_ms: u64,
    pub tls_handshake_ms: u64,
    pub html_parsing_ms: u64,
    pub tech_detection_ms: u64,
    pub geoip_lookup_ms: u64,
    pub whois_lookup_ms: u64,
    pub security_analysis_ms: u64,
    pub total_ms: u64,
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
