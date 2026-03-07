//! Status server data structures.

use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Instant;

use crate::error_handling::ProcessingStats;
use crate::runtime_metrics::RuntimeMetrics;
use crate::storage::circuit_breaker::DbWriteCircuitBreaker;
use crate::utils::TimingStats;

/// Shared state for the status server
#[derive(Clone)]
pub struct StatusState {
    /// Total lines in the input file (non-empty, non-comment lines)
    /// This is used for progress calculations to show progress against all URLs in the file
    pub total_urls: Arc<AtomicUsize>,
    /// Total URLs that have been attempted (valid URLs that passed validation)
    /// Used in lib.rs for logging and statistics, but not in status server handlers
    pub total_urls_attempted: Arc<AtomicUsize>,
    pub completed_urls: Arc<AtomicUsize>,
    pub failed_urls: Arc<AtomicUsize>,
    pub start_time: Arc<Instant>,
    pub error_stats: Arc<ProcessingStats>,
    /// Timing statistics for performance monitoring
    pub timing_stats: Option<Arc<TimingStats>>,
    /// Request-per-second limiter for current effective rate reporting
    pub request_limiter: Option<Arc<crate::initialization::RateLimiter>>,
    /// Database write circuit breaker state
    pub db_circuit_breaker: Arc<DbWriteCircuitBreaker>,
    /// Runtime retry/degradation counters
    pub runtime_metrics: Arc<RuntimeMetrics>,
}

/// JSON response for `/status` endpoint
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct StatusResponse {
    pub total_urls: usize,
    pub total_urls_attempted: usize,
    pub completed_urls: usize,
    pub failed_urls: usize,
    pub active_urls: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_urls: Option<usize>,
    pub percentage_complete: f64,
    pub elapsed_seconds: f64,
    pub rate_per_second: f64,
    pub current_rps: Option<u32>,
    pub retried_requests: usize,
    pub non_retriable_failures: usize,
    pub db_write_failures: u32,
    pub skipped_failure_writes: u32,
    pub circuit_breaker_open: bool,
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
    pub security_analysis_ms: u64,
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
    pub missing_meta_keywords: usize,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_status_state_atomic_operations() {
        // Test that atomic counters work correctly in StatusState
        // This is critical - incorrect atomic operations could cause data races
        let state = StatusState {
            total_urls: Arc::new(AtomicUsize::new(100)),
            total_urls_attempted: Arc::new(AtomicUsize::new(0)),
            completed_urls: Arc::new(AtomicUsize::new(0)),
            failed_urls: Arc::new(AtomicUsize::new(0)),
            start_time: Arc::new(Instant::now()),
            error_stats: Arc::new(ProcessingStats::new()),
            timing_stats: None,
            request_limiter: None,
            db_circuit_breaker: Arc::new(DbWriteCircuitBreaker::default()),
            runtime_metrics: Arc::new(RuntimeMetrics::default()),
        };

        // Test increment operations
        state.completed_urls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(state.completed_urls.load(Ordering::SeqCst), 1);

        state.failed_urls.fetch_add(5, Ordering::SeqCst);
        assert_eq!(state.failed_urls.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn test_status_state_clone() {
        // Test that StatusState can be cloned (Arc clones are cheap)
        let state = StatusState {
            total_urls: Arc::new(AtomicUsize::new(50)),
            total_urls_attempted: Arc::new(AtomicUsize::new(0)),
            completed_urls: Arc::new(AtomicUsize::new(10)),
            failed_urls: Arc::new(AtomicUsize::new(2)),
            start_time: Arc::new(Instant::now()),
            error_stats: Arc::new(ProcessingStats::new()),
            timing_stats: None,
            request_limiter: None,
            db_circuit_breaker: Arc::new(DbWriteCircuitBreaker::default()),
            runtime_metrics: Arc::new(RuntimeMetrics::default()),
        };

        let cloned = state.clone();

        // Both should point to the same data
        cloned.completed_urls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(state.completed_urls.load(Ordering::SeqCst), 11);
    }

    #[test]
    fn test_status_response_serialization() {
        // Test that StatusResponse serializes correctly
        // This is critical - malformed JSON would break monitoring integrations
        let response = StatusResponse {
            total_urls: 100,
            total_urls_attempted: 55,
            completed_urls: 50,
            failed_urls: 5,
            active_urls: 0,
            pending_urls: Some(45),
            percentage_complete: 50.0,
            elapsed_seconds: 30.5,
            rate_per_second: 1.64,
            current_rps: Some(20),
            retried_requests: 4,
            non_retriable_failures: 2,
            db_write_failures: 1,
            skipped_failure_writes: 0,
            circuit_breaker_open: false,
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
                total: 3,
                missing_meta_keywords: 1,
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

        // Verify key fields are present
        assert!(json.contains("\"total_urls\":100"));
        assert!(json.contains("\"completed_urls\":50"));
        assert!(json.contains("\"percentage_complete\":50"));
        assert!(json.contains("\"errors\""));
        assert!(json.contains("\"warnings\""));
    }

    #[test]
    fn test_status_response_pending_urls_optional() {
        // Test that pending_urls is skipped when None
        let response = StatusResponse {
            total_urls: 100,
            total_urls_attempted: 100,
            completed_urls: 100,
            failed_urls: 0,
            active_urls: 0,
            pending_urls: None, // Should be skipped in JSON
            percentage_complete: 100.0,
            elapsed_seconds: 60.0,
            rate_per_second: 1.67,
            current_rps: None,
            retried_requests: 0,
            non_retriable_failures: 0,
            db_write_failures: 0,
            skipped_failure_writes: 0,
            circuit_breaker_open: false,
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
                missing_meta_keywords: 0,
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
        // pending_urls should not appear in JSON when None
        assert!(!json.contains("pending_urls"));
    }

    #[test]
    fn test_timing_summary_serialization() {
        // Test that TimingSummary serializes correctly
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
                security_analysis_ms: 10,
                total_ms: 415,
            },
        };

        let json = serde_json::to_string(&timing).expect("Failed to serialize TimingSummary");
        assert!(json.contains("\"count\":100"));
        assert!(json.contains("\"http_request_ms\":150"));
        assert!(json.contains("\"total_ms\":415"));
    }

    #[test]
    fn test_error_counts_all_zero() {
        // Test that zero counts serialize correctly
        let errors = ErrorCounts {
            total: 0,
            timeout: 0,
            connection_error: 0,
            http_error: 0,
            dns_error: 0,
            tls_error: 0,
            parse_error: 0,
            other_error: 0,
        };

        let json = serde_json::to_string(&errors).expect("Failed to serialize");
        assert!(json.contains("\"total\":0"));
        assert!(json.contains("\"timeout\":0"));
    }

    #[test]
    fn test_status_state_with_timing_stats() {
        // Test StatusState with timing stats enabled
        let state = StatusState {
            total_urls: Arc::new(AtomicUsize::new(100)),
            total_urls_attempted: Arc::new(AtomicUsize::new(0)),
            completed_urls: Arc::new(AtomicUsize::new(0)),
            failed_urls: Arc::new(AtomicUsize::new(0)),
            start_time: Arc::new(Instant::now()),
            error_stats: Arc::new(ProcessingStats::new()),
            timing_stats: Some(Arc::new(TimingStats::new())),
            request_limiter: None,
            db_circuit_breaker: Arc::new(DbWriteCircuitBreaker::default()),
            runtime_metrics: Arc::new(RuntimeMetrics::default()),
        };

        assert!(state.timing_stats.is_some());
    }
}
