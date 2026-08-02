//! Status server data structures.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::Semaphore;

use crate::error_handling::ProcessingStats;
use crate::runtime_metrics::RuntimeMetrics;
use crate::utils::TimingStats;

/// High-level scan lifecycle phase for live status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ScanPhase {
    /// Reading input and processing URLs.
    Scanning = 0,
    /// Input exhausted; waiting for in-flight tasks (or aborting on drain timeout).
    Draining = 1,
    /// Computing final stats and shutting down helpers.
    Finalizing = 2,
}

impl ScanPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scanning => "scanning",
            Self::Draining => "draining",
            Self::Finalizing => "finalizing",
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Draining,
            2 => Self::Finalizing,
            _ => Self::Scanning,
        }
    }
}

/// Atomic wrapper around [`ScanPhase`].
#[derive(Debug)]
pub struct AtomicPhase {
    value: AtomicU8,
}

impl AtomicPhase {
    pub fn new(phase: ScanPhase) -> Self {
        Self {
            value: AtomicU8::new(phase as u8),
        }
    }

    pub fn set(&self, phase: ScanPhase) {
        self.value.store(phase as u8, Ordering::SeqCst);
    }

    pub fn get(&self) -> ScanPhase {
        ScanPhase::from_u8(self.value.load(Ordering::SeqCst))
    }
}

impl Default for AtomicPhase {
    fn default() -> Self {
        Self::new(ScanPhase::Scanning)
    }
}

/// Tracks recent finished-URL throughput for windowed rate / ETA.
#[derive(Debug)]
pub struct ThroughputWindow {
    inner: Mutex<ThroughputWindowInner>,
}

#[derive(Debug)]
struct ThroughputWindowInner {
    prev_at: Instant,
    prev_finished: usize,
    rate: f64,
}

impl ThroughputWindow {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(ThroughputWindowInner {
                prev_at: Instant::now(),
                prev_finished: 0,
                rate: 0.0,
            }),
        }
    }

    /// Observe current finished count; returns the latest windowed rate (URLs/sec).
    ///
    /// Updates when at least ~1s has elapsed since the previous sample so scrapes
    /// denser than that reuse the last computed rate.
    pub fn observe(&self, finished: usize) -> f64 {
        let Ok(mut guard) = self.inner.lock() else {
            return 0.0;
        };
        let now = Instant::now();
        let dt = now.duration_since(guard.prev_at).as_secs_f64();
        if dt >= 1.0 {
            let delta = finished.saturating_sub(guard.prev_finished);
            #[allow(clippy::cast_precision_loss)]
            {
                guard.rate = delta as f64 / dt;
            }
            guard.prev_at = now;
            guard.prev_finished = finished;
        } else if finished < guard.prev_finished {
            // Counter reset (should not happen mid-run); resync baseline.
            guard.prev_finished = finished;
            guard.prev_at = now;
            guard.rate = 0.0;
        }
        guard.rate
    }
}

impl Default for ThroughputWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared state for the status server
#[derive(Clone)]
pub struct StatusState {
    /// Total lines in the input file (non-empty, non-comment lines)
    pub total_urls: Arc<AtomicUsize>,
    /// Total URLs that have entered processing or early-skip paths
    pub total_urls_attempted: Arc<AtomicUsize>,
    /// URLs that finished without failure via the success path (persisted inserts).
    /// Mid-process skips are counted only in [`Self::skipped_urls`].
    pub completed_urls: Arc<AtomicUsize>,
    /// URLs that produced a persisted `url_status` row (matches finalize / `runs`)
    pub successful_urls: Arc<AtomicUsize>,
    pub failed_urls: Arc<AtomicUsize>,
    /// URLs skipped (invalid, SSRF-unsafe, or mid-process intentional skip)
    pub skipped_urls: Arc<AtomicUsize>,
    pub start_time: Arc<Instant>,
    pub error_stats: Arc<ProcessingStats>,
    /// Timing statistics for performance monitoring
    pub timing_stats: Option<Arc<TimingStats>>,
    /// Request-per-second limiter for configured rate reporting
    pub request_limiter: Option<Arc<crate::initialization::RateLimiter>>,
    /// Runtime retry/degradation counters
    pub runtime_metrics: Arc<RuntimeMetrics>,
    /// Run identifier for correlating metrics with database and logs
    pub run_id: Option<String>,
    /// Run start time as Unix timestamp in seconds
    pub run_start_time_unix_secs: Option<f64>,
    /// Current scan lifecycle phase
    pub phase: Arc<AtomicPhase>,
    /// Windowed throughput tracker shared across scrapes
    pub throughput_window: Arc<ThroughputWindow>,
    /// Configured concurrency limit (`max_concurrency`)
    pub max_concurrency: Option<usize>,
    /// Live semaphore for in-use concurrency reporting
    pub semaphore: Option<Arc<Semaphore>>,
}

/// JSON response for `/status` endpoint
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct StatusResponse {
    pub total_urls: usize,
    pub total_urls_attempted: usize,
    pub completed_urls: usize,
    pub successful_urls: usize,
    pub failed_urls: usize,
    pub skipped_urls: usize,
    pub active_urls: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_urls: Option<usize>,
    /// Finished (`successful + failed + skipped`) / total × 100
    pub percentage_complete: f64,
    /// Dispatched (`attempted`) / total × 100
    pub percentage_dispatched: f64,
    pub elapsed_seconds: f64,
    /// Lifetime finished URLs per second
    pub rate_per_second: f64,
    /// Recent windowed finished URLs per second (~1s+ samples)
    pub windowed_rate_per_second: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta_seconds: Option<f64>,
    /// `scanning` | `draining` | `finalizing`
    pub phase: String,
    /// Configured request-rate limit when a limiter is enabled (not measured RPS)
    pub current_rps: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concurrency_limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concurrency_in_use: Option<usize>,
    pub retried_requests: usize,
    pub non_retriable_failures: usize,
    pub errors: ErrorCounts,
    pub warnings: WarningCounts,
    pub info: InfoCounts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<TimingSummary>,
}

/// Timing summary for status endpoint
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct TimingSummary {
    pub count: u64,
    pub averages: TimingMetrics,
}

/// Timing metrics in milliseconds
#[derive(Debug, Serialize, Deserialize, PartialEq)]
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
    pub total_ms: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
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

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct WarningCounts {
    pub total: usize,
    pub missing_meta_description: usize,
    pub missing_title: usize,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct InfoCounts {
    pub total: usize,
    pub http_redirect: usize,
    pub https_redirect: usize,
    pub bot_detection_403: usize,
    pub multiple_redirects: usize,
}

/// Helper to build a minimal [`StatusState`] for tests.
#[cfg(test)]
pub(crate) fn test_status_state(
    total: usize,
    attempted: usize,
    completed: usize,
    successful: usize,
    failed: usize,
    skipped: usize,
) -> StatusState {
    StatusState {
        total_urls: Arc::new(AtomicUsize::new(total)),
        total_urls_attempted: Arc::new(AtomicUsize::new(attempted)),
        completed_urls: Arc::new(AtomicUsize::new(completed)),
        successful_urls: Arc::new(AtomicUsize::new(successful)),
        failed_urls: Arc::new(AtomicUsize::new(failed)),
        skipped_urls: Arc::new(AtomicUsize::new(skipped)),
        start_time: Arc::new(Instant::now()),
        error_stats: Arc::new(ProcessingStats::new()),
        timing_stats: None,
        request_limiter: None,
        runtime_metrics: Arc::new(RuntimeMetrics::default()),
        run_id: None,
        run_start_time_unix_secs: None,
        phase: Arc::new(AtomicPhase::default()),
        throughput_window: Arc::new(ThroughputWindow::new()),
        max_concurrency: None,
        semaphore: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_state_atomic_operations() {
        let state = test_status_state(100, 0, 0, 0, 0, 0);
        state.completed_urls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(state.completed_urls.load(Ordering::SeqCst), 1);
        state.failed_urls.fetch_add(5, Ordering::SeqCst);
        assert_eq!(state.failed_urls.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn test_status_state_clone() {
        let state = test_status_state(50, 0, 10, 10, 2, 0);
        let cloned = state.clone();
        cloned.completed_urls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(state.completed_urls.load(Ordering::SeqCst), 11);
    }

    #[test]
    fn test_status_response_serialization() {
        let response = StatusResponse {
            total_urls: 100,
            total_urls_attempted: 55,
            completed_urls: 50,
            successful_urls: 50,
            failed_urls: 5,
            skipped_urls: 0,
            active_urls: 0,
            pending_urls: Some(45),
            percentage_complete: 50.0,
            percentage_dispatched: 55.0,
            elapsed_seconds: 30.5,
            rate_per_second: 1.64,
            windowed_rate_per_second: 2.0,
            eta_seconds: Some(20.0),
            phase: "scanning".to_string(),
            current_rps: Some(20),
            concurrency_limit: Some(50),
            concurrency_in_use: Some(10),
            retried_requests: 4,
            non_retriable_failures: 2,
            errors: ErrorCounts {
                total: 5,
                timeout: 2,
                connection_error: 1,
                http_error: 1,
                dns_error: 0,
                tls_error: 1,
                parse_error: 0,
                other_error: 0,
            },
            warnings: WarningCounts {
                total: 2,
                missing_meta_description: 1,
                missing_title: 1,
            },
            info: InfoCounts {
                total: 10,
                http_redirect: 5,
                https_redirect: 3,
                bot_detection_403: 1,
                multiple_redirects: 1,
            },
            timing: None,
        };

        let json = serde_json::to_string(&response).expect("Failed to serialize StatusResponse");
        assert!(json.contains("\"total_urls\":100"));
        assert!(json.contains("\"successful_urls\":50"));
        assert!(json.contains("\"skipped_urls\":0"));
        assert!(json.contains("\"percentage_complete\":50"));
        assert!(json.contains("\"phase\":\"scanning\""));
    }

    #[test]
    fn test_status_response_pending_urls_optional() {
        let response = StatusResponse {
            total_urls: 100,
            total_urls_attempted: 100,
            completed_urls: 100,
            successful_urls: 100,
            failed_urls: 0,
            skipped_urls: 0,
            active_urls: 0,
            pending_urls: None,
            percentage_complete: 100.0,
            percentage_dispatched: 100.0,
            elapsed_seconds: 60.0,
            rate_per_second: 1.67,
            windowed_rate_per_second: 0.0,
            eta_seconds: Some(0.0),
            phase: "finalizing".to_string(),
            current_rps: None,
            concurrency_limit: None,
            concurrency_in_use: None,
            retried_requests: 0,
            non_retriable_failures: 0,
            errors: ErrorCounts {
                total: 0,
                timeout: 0,
                connection_error: 0,
                http_error: 0,
                dns_error: 0,
                tls_error: 0,
                parse_error: 0,
                other_error: 0,
            },
            warnings: WarningCounts {
                total: 0,
                missing_meta_description: 0,
                missing_title: 0,
            },
            info: InfoCounts {
                total: 0,
                http_redirect: 0,
                https_redirect: 0,
                bot_detection_403: 0,
                multiple_redirects: 0,
            },
            timing: None,
        };

        let json = serde_json::to_string(&response).expect("Failed to serialize");
        assert!(!json.contains("pending_urls"));
    }

    #[test]
    fn test_atomic_phase_transitions() {
        let phase = AtomicPhase::new(ScanPhase::Scanning);
        assert_eq!(phase.get(), ScanPhase::Scanning);
        phase.set(ScanPhase::Draining);
        assert_eq!(phase.get().as_str(), "draining");
        phase.set(ScanPhase::Finalizing);
        assert_eq!(phase.get().as_str(), "finalizing");
    }

    #[test]
    fn test_timing_summary_serialization() {
        let timing = TimingSummary {
            count: 100,
            averages: TimingMetrics {
                http_request_ms: 150,
                dns_forward_ms: 20,
                dns_reverse_ms: 15,
                dns_additional_ms: 10,
                tls_handshake_ms: 50,
                html_parsing_ms: 30,
                tech_detection_ms: 25,
                geoip_lookup_ms: 5,
                whois_lookup_ms: 100,
                total_ms: 415,
            },
        };

        let json = serde_json::to_string(&timing).expect("Failed to serialize TimingSummary");
        assert!(json.contains("\"count\":100"));
        assert!(json.contains("\"http_request_ms\":150"));
        assert!(json.contains("\"total_ms\":415"));
    }
}
