//! Prometheus metrics handler.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::sync::atomic::Ordering;

use super::super::types::StatusState;

/// Prometheus-compatible metrics endpoint
pub async fn metrics_handler(State(state): State<StatusState>) -> Response {
    let total_urls_in_file = state.total_urls.load(Ordering::SeqCst);
    let completed = state.completed_urls.load(Ordering::SeqCst);
    let failed = state.failed_urls.load(Ordering::SeqCst);
    let elapsed = state.start_time.elapsed().as_secs_f64();
    let rate = if elapsed > 0.0 {
        completed as f64 / elapsed
    } else {
        0.0
    };

    let total_errors = state.error_stats.total_errors();
    let total_warnings = state.error_stats.total_warnings();
    let total_info = state.error_stats.total_info();

    // Add timing metrics if available
    let timing_metrics = if let Some(timing_stats) = &state.timing_stats {
        let count = timing_stats.count.load(Ordering::Relaxed);
        if count > 0 {
            let avg = timing_stats.averages();
            // Convert from microseconds to milliseconds for display
            let micros_to_ms = |micros: u64| (micros + 500) / 1000;

            format!(
                r#"
# HELP domain_status_timing_http_request_ms Average HTTP request time in milliseconds
# TYPE domain_status_timing_http_request_ms gauge
domain_status_timing_http_request_ms {}

# HELP domain_status_timing_dns_forward_ms Average DNS forward lookup time in milliseconds
# TYPE domain_status_timing_dns_forward_ms gauge
domain_status_timing_dns_forward_ms {}

# HELP domain_status_timing_dns_reverse_ms Average DNS reverse lookup time in milliseconds
# TYPE domain_status_timing_dns_reverse_ms gauge
domain_status_timing_dns_reverse_ms {}

# HELP domain_status_timing_dns_additional_ms Average DNS additional records lookup time in milliseconds
# TYPE domain_status_timing_dns_additional_ms gauge
domain_status_timing_dns_additional_ms {}

# HELP domain_status_timing_tls_handshake_ms Average TLS handshake time in milliseconds
# TYPE domain_status_timing_tls_handshake_ms gauge
domain_status_timing_tls_handshake_ms {}

# HELP domain_status_timing_html_parsing_ms Average HTML parsing time in milliseconds
# TYPE domain_status_timing_html_parsing_ms gauge
domain_status_timing_html_parsing_ms {}

# HELP domain_status_timing_tech_detection_ms Average technology detection time in milliseconds
# TYPE domain_status_timing_tech_detection_ms gauge
domain_status_timing_tech_detection_ms {}

# HELP domain_status_timing_geoip_lookup_ms Average GeoIP lookup time in milliseconds
# TYPE domain_status_timing_geoip_lookup_ms gauge
domain_status_timing_geoip_lookup_ms {}

# HELP domain_status_timing_whois_lookup_ms Average WHOIS lookup time in milliseconds
# TYPE domain_status_timing_whois_lookup_ms gauge
domain_status_timing_whois_lookup_ms {}

# HELP domain_status_timing_security_analysis_ms Average security analysis time in milliseconds
# TYPE domain_status_timing_security_analysis_ms gauge
domain_status_timing_security_analysis_ms {}

# HELP domain_status_timing_total_ms Average total processing time in milliseconds
# TYPE domain_status_timing_total_ms gauge
domain_status_timing_total_ms {}
"#,
                micros_to_ms(avg.http_request_ms),
                micros_to_ms(avg.dns_forward_ms),
                micros_to_ms(avg.dns_reverse_ms),
                micros_to_ms(avg.dns_additional_ms),
                micros_to_ms(avg.tls_handshake_ms),
                micros_to_ms(avg.html_parsing_ms),
                micros_to_ms(avg.tech_detection_ms),
                micros_to_ms(avg.geoip_lookup_ms),
                micros_to_ms(avg.whois_lookup_ms),
                micros_to_ms(avg.security_analysis_ms),
                micros_to_ms(avg.total_ms),
            )
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let metrics = format!(
        r#"# HELP domain_status_total_urls Total number of URLs to process
# TYPE domain_status_total_urls gauge
domain_status_total_urls {}

# HELP domain_status_completed_urls Number of URLs successfully processed
# TYPE domain_status_completed_urls gauge
domain_status_completed_urls {}

# HELP domain_status_failed_urls Number of URLs that failed to process
# TYPE domain_status_failed_urls gauge
domain_status_failed_urls {}

# HELP domain_status_percentage_complete Percentage of URLs completed (0-100)
# TYPE domain_status_percentage_complete gauge
domain_status_percentage_complete {}

# HELP domain_status_rate_per_second URLs processed per second
# TYPE domain_status_rate_per_second gauge
domain_status_rate_per_second {}

# HELP domain_status_errors_total Total number of errors encountered
# TYPE domain_status_errors_total counter
domain_status_errors_total {}

# HELP domain_status_warnings_total Total number of warnings encountered
# TYPE domain_status_warnings_total counter
domain_status_warnings_total {}

# HELP domain_status_info_total Total number of info events
# TYPE domain_status_info_total counter
domain_status_info_total {}
{}"#,
        total_urls_in_file,
        completed,
        failed,
        if total_urls_in_file > 0 {
            ((completed + failed) as f64 / total_urls_in_file as f64) * 100.0
        } else {
            0.0
        },
        rate,
        total_errors,
        total_warnings,
        total_info,
        timing_metrics
    );

    (StatusCode::OK, metrics).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ProcessingStats;
    use crate::status_server::StatusState;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use std::time::Instant;

    fn create_test_state() -> StatusState {
        StatusState {
            total_urls: Arc::new(AtomicUsize::new(100)),
            total_urls_attempted: Arc::new(AtomicUsize::new(100)),
            completed_urls: Arc::new(AtomicUsize::new(50)),
            failed_urls: Arc::new(AtomicUsize::new(10)),
            start_time: Arc::new(Instant::now()),
            error_stats: Arc::new(ProcessingStats::new()),
            timing_stats: None,
        }
    }

    #[tokio::test]
    async fn test_metrics_handler_returns_text() {
        let state = create_test_state();
        let response = metrics_handler(State(state)).await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_metrics_handler_includes_basic_metrics() {
        let state = create_test_state();
        let response = metrics_handler(State(state)).await;

        assert_eq!(response.status(), StatusCode::OK);

        // Extract body to verify metrics format
        let (_parts, body) = response.into_parts();
        let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        // Verify Prometheus format
        assert!(body_str.contains("domain_status_total_urls"));
        assert!(body_str.contains("domain_status_completed_urls"));
        assert!(body_str.contains("domain_status_failed_urls"));
        assert!(body_str.contains("domain_status_percentage_complete"));
        assert!(body_str.contains("domain_status_rate_per_second"));
        assert!(body_str.contains("domain_status_errors_total"));
        assert!(body_str.contains("domain_status_warnings_total"));
        assert!(body_str.contains("domain_status_info_total"));
    }

    #[tokio::test]
    async fn test_metrics_handler_handles_zero_urls() {
        let state = StatusState {
            total_urls: Arc::new(AtomicUsize::new(0)),
            total_urls_attempted: Arc::new(AtomicUsize::new(0)),
            completed_urls: Arc::new(AtomicUsize::new(0)),
            failed_urls: Arc::new(AtomicUsize::new(0)),
            start_time: Arc::new(Instant::now()),
            error_stats: Arc::new(ProcessingStats::new()),
            timing_stats: None,
        };

        let response = metrics_handler(State(state)).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_metrics_handler_includes_timing_when_available() {
        use crate::utils::TimingStats;

        let timing_stats = Arc::new(TimingStats::new());
        timing_stats.count.store(1, Ordering::Relaxed);

        let state = StatusState {
            total_urls: Arc::new(AtomicUsize::new(100)),
            total_urls_attempted: Arc::new(AtomicUsize::new(100)),
            completed_urls: Arc::new(AtomicUsize::new(50)),
            failed_urls: Arc::new(AtomicUsize::new(10)),
            start_time: Arc::new(Instant::now()),
            error_stats: Arc::new(ProcessingStats::new()),
            timing_stats: Some(timing_stats),
        };

        let response = metrics_handler(State(state)).await;
        assert_eq!(response.status(), StatusCode::OK);

        let (_parts, body) = response.into_parts();
        let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        // Verify timing metrics are included
        assert!(body_str.contains("domain_status_timing_http_request_ms"));
        assert!(body_str.contains("domain_status_timing_total_ms"));
    }
}
