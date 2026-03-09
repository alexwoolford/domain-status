//! Prometheus metrics handler.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::sync::atomic::Ordering;

use super::super::types::StatusState;

fn micros_to_ms(micros: u64) -> u64 {
    (micros + 500) / 1000
}

/// Escapes a string for use as a Prometheus label value (double-quoted; backslash and quote escaped).
fn escape_prometheus_label_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Renders the Prometheus metrics payload for the given state and elapsed time.
#[allow(clippy::too_many_lines)]
pub(crate) fn render_metrics(state: &StatusState, elapsed: f64) -> String {
    let total_urls_in_file = state.total_urls.load(Ordering::SeqCst);
    let attempted = state.total_urls_attempted.load(Ordering::SeqCst);
    let completed = state.completed_urls.load(Ordering::SeqCst);
    let failed = state.failed_urls.load(Ordering::SeqCst);
    let skipped = state.skipped_urls.load(Ordering::SeqCst);
    let active = attempted.saturating_sub(completed + failed + skipped);
    #[allow(clippy::cast_precision_loss)]
    let rate = if elapsed > 0.0 {
        completed as f64 / elapsed
    } else {
        0.0
    };

    let total_errors = state.error_stats.total_errors();
    let total_warnings = state.error_stats.total_warnings();
    let total_info = state.error_stats.total_info();

    let timing_metrics = if let Some(timing_stats) = &state.timing_stats {
        let count = timing_stats.count.load(Ordering::Relaxed);
        if count > 0 {
            let avg = timing_stats.averages();

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
                micros_to_ms(avg.http_request_us),
                micros_to_ms(avg.dns_forward_us),
                micros_to_ms(avg.dns_reverse_us),
                micros_to_ms(avg.dns_additional_us),
                micros_to_ms(avg.tls_handshake_us),
                micros_to_ms(avg.html_parsing_us),
                micros_to_ms(avg.tech_detection_us),
                micros_to_ms(avg.geoip_lookup_us),
                micros_to_ms(avg.whois_lookup_us),
                micros_to_ms(avg.security_analysis_us),
                micros_to_ms(avg.total_us),
            )
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let run_id_label = state
        .run_id
        .as_deref()
        .map(escape_prometheus_label_value)
        .unwrap_or_default();
    let start_time_secs = state.run_start_time_unix_secs.unwrap_or(0.0);

    format!(
        r#"# HELP domain_status_run_info Run identifier for correlating with database and logs
# TYPE domain_status_run_info gauge
domain_status_run_info{{run_id="{}"}} 1

# HELP domain_status_elapsed_seconds Seconds since the current run started
# TYPE domain_status_elapsed_seconds gauge
domain_status_elapsed_seconds {}

# HELP domain_status_start_time_seconds Unix timestamp when the run started
# TYPE domain_status_start_time_seconds gauge
domain_status_start_time_seconds {}

# HELP domain_status_total_urls Total number of URLs to process
# TYPE domain_status_total_urls gauge
domain_status_total_urls {}

# HELP domain_status_completed_urls Number of URLs successfully processed
# TYPE domain_status_completed_urls gauge
domain_status_completed_urls {}

# HELP domain_status_failed_urls Number of URLs that failed to process
# TYPE domain_status_failed_urls gauge
domain_status_failed_urls {}

# HELP domain_status_attempted_urls Number of URLs that have entered processing
# TYPE domain_status_attempted_urls gauge
domain_status_attempted_urls {}

# HELP domain_status_active_urls Number of URLs currently in flight
# TYPE domain_status_active_urls gauge
domain_status_active_urls {}

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

# HELP domain_status_runtime_retries_total Total retry attempts consumed
# TYPE domain_status_runtime_retries_total counter
domain_status_runtime_retries_total {}

# HELP domain_status_runtime_non_retriable_failures_total Total failures classified as terminal at the retry boundary
# TYPE domain_status_runtime_non_retriable_failures_total counter
domain_status_runtime_non_retriable_failures_total {}

# HELP domain_status_current_rps Current effective configured request rate
# TYPE domain_status_current_rps gauge
domain_status_current_rps {}
{}"#,
        run_id_label,
        elapsed,
        start_time_secs,
        total_urls_in_file,
        completed,
        failed,
        attempted,
        active,
        if total_urls_in_file > 0 {
            #[allow(clippy::cast_precision_loss)]
            {
                (attempted as f64 / total_urls_in_file as f64) * 100.0
            }
        } else {
            0.0
        },
        rate,
        total_errors,
        total_warnings,
        total_info,
        state.runtime_metrics.retried_requests(),
        state.runtime_metrics.non_retriable_failures(),
        state
            .request_limiter
            .as_ref()
            .map_or(0, |limiter| limiter.current_rps()),
        timing_metrics
    )
}

/// Prometheus-compatible metrics endpoint
pub async fn metrics_handler(State(state): State<StatusState>) -> Response {
    let elapsed = state.start_time.elapsed().as_secs_f64();
    (StatusCode::OK, render_metrics(&state, elapsed)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ProcessingStats;
    use crate::status_server::StatusState;
    use crate::utils::{TimingStats, UrlTimingMetrics};
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use std::time::Instant;

    fn create_test_state() -> StatusState {
        StatusState {
            total_urls: Arc::new(AtomicUsize::new(100)),
            total_urls_attempted: Arc::new(AtomicUsize::new(100)),
            completed_urls: Arc::new(AtomicUsize::new(50)),
            failed_urls: Arc::new(AtomicUsize::new(10)),
            skipped_urls: Arc::new(AtomicUsize::new(0)),
            start_time: Arc::new(Instant::now()),
            error_stats: Arc::new(ProcessingStats::new()),
            timing_stats: None,
            request_limiter: None,
            runtime_metrics: Arc::new(crate::runtime_metrics::RuntimeMetrics::default()),
            run_id: None,
            run_start_time_unix_secs: None,
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

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_render_metrics_exact_output_with_timing() {
        let timing_stats = Arc::new(TimingStats::new());
        timing_stats.record(&UrlTimingMetrics {
            http_request_us: 1500,
            total_us: 2000,
            ..Default::default()
        });
        let state = StatusState {
            total_urls: Arc::new(AtomicUsize::new(100)),
            total_urls_attempted: Arc::new(AtomicUsize::new(60)),
            completed_urls: Arc::new(AtomicUsize::new(50)),
            failed_urls: Arc::new(AtomicUsize::new(10)),
            skipped_urls: Arc::new(AtomicUsize::new(0)),
            start_time: Arc::new(Instant::now()),
            error_stats: Arc::new({
                let stats = ProcessingStats::new();
                stats.increment_error(crate::error_handling::ErrorType::DnsNsLookupError);
                stats.increment_warning(crate::error_handling::WarningType::MissingTitle);
                stats.increment_info(crate::error_handling::InfoType::HttpsRedirect);
                stats
            }),
            timing_stats: Some(timing_stats),
            request_limiter: None,
            runtime_metrics: Arc::new({
                let metrics = crate::runtime_metrics::RuntimeMetrics::default();
                metrics.record_retry();
                metrics
            }),
            run_id: None,
            run_start_time_unix_secs: None,
        };

        let metrics = render_metrics(&state, 5.0);
        assert_eq!(
            metrics.trim(),
            r#"# HELP domain_status_run_info Run identifier for correlating with database and logs
# TYPE domain_status_run_info gauge
domain_status_run_info{run_id=""} 1

# HELP domain_status_elapsed_seconds Seconds since the current run started
# TYPE domain_status_elapsed_seconds gauge
domain_status_elapsed_seconds 5

# HELP domain_status_start_time_seconds Unix timestamp when the run started
# TYPE domain_status_start_time_seconds gauge
domain_status_start_time_seconds 0

# HELP domain_status_total_urls Total number of URLs to process
# TYPE domain_status_total_urls gauge
domain_status_total_urls 100

# HELP domain_status_completed_urls Number of URLs successfully processed
# TYPE domain_status_completed_urls gauge
domain_status_completed_urls 50

# HELP domain_status_failed_urls Number of URLs that failed to process
# TYPE domain_status_failed_urls gauge
domain_status_failed_urls 10

# HELP domain_status_attempted_urls Number of URLs that have entered processing
# TYPE domain_status_attempted_urls gauge
domain_status_attempted_urls 60

# HELP domain_status_active_urls Number of URLs currently in flight
# TYPE domain_status_active_urls gauge
domain_status_active_urls 0

# HELP domain_status_percentage_complete Percentage of URLs completed (0-100)
# TYPE domain_status_percentage_complete gauge
domain_status_percentage_complete 60

# HELP domain_status_rate_per_second URLs processed per second
# TYPE domain_status_rate_per_second gauge
domain_status_rate_per_second 10

# HELP domain_status_errors_total Total number of errors encountered
# TYPE domain_status_errors_total counter
domain_status_errors_total 1

# HELP domain_status_warnings_total Total number of warnings encountered
# TYPE domain_status_warnings_total counter
domain_status_warnings_total 1

# HELP domain_status_info_total Total number of info events
# TYPE domain_status_info_total counter
domain_status_info_total 1

# HELP domain_status_runtime_retries_total Total retry attempts consumed
# TYPE domain_status_runtime_retries_total counter
domain_status_runtime_retries_total 1

# HELP domain_status_runtime_non_retriable_failures_total Total failures classified as terminal at the retry boundary
# TYPE domain_status_runtime_non_retriable_failures_total counter
domain_status_runtime_non_retriable_failures_total 0

# HELP domain_status_current_rps Current effective configured request rate
# TYPE domain_status_current_rps gauge
domain_status_current_rps 0

# HELP domain_status_timing_http_request_ms Average HTTP request time in milliseconds
# TYPE domain_status_timing_http_request_ms gauge
domain_status_timing_http_request_ms 2

# HELP domain_status_timing_dns_forward_ms Average DNS forward lookup time in milliseconds
# TYPE domain_status_timing_dns_forward_ms gauge
domain_status_timing_dns_forward_ms 0

# HELP domain_status_timing_dns_reverse_ms Average DNS reverse lookup time in milliseconds
# TYPE domain_status_timing_dns_reverse_ms gauge
domain_status_timing_dns_reverse_ms 0

# HELP domain_status_timing_dns_additional_ms Average DNS additional records lookup time in milliseconds
# TYPE domain_status_timing_dns_additional_ms gauge
domain_status_timing_dns_additional_ms 0

# HELP domain_status_timing_tls_handshake_ms Average TLS handshake time in milliseconds
# TYPE domain_status_timing_tls_handshake_ms gauge
domain_status_timing_tls_handshake_ms 0

# HELP domain_status_timing_html_parsing_ms Average HTML parsing time in milliseconds
# TYPE domain_status_timing_html_parsing_ms gauge
domain_status_timing_html_parsing_ms 0

# HELP domain_status_timing_tech_detection_ms Average technology detection time in milliseconds
# TYPE domain_status_timing_tech_detection_ms gauge
domain_status_timing_tech_detection_ms 0

# HELP domain_status_timing_geoip_lookup_ms Average GeoIP lookup time in milliseconds
# TYPE domain_status_timing_geoip_lookup_ms gauge
domain_status_timing_geoip_lookup_ms 0

# HELP domain_status_timing_whois_lookup_ms Average WHOIS lookup time in milliseconds
# TYPE domain_status_timing_whois_lookup_ms gauge
domain_status_timing_whois_lookup_ms 0

# HELP domain_status_timing_security_analysis_ms Average security analysis time in milliseconds
# TYPE domain_status_timing_security_analysis_ms gauge
domain_status_timing_security_analysis_ms 0

# HELP domain_status_timing_total_ms Average total processing time in milliseconds
# TYPE domain_status_timing_total_ms gauge
domain_status_timing_total_ms 2"#.trim()
        );
    }

    #[test]
    fn test_render_metrics_omits_timing_when_empty() {
        let state = StatusState {
            total_urls: Arc::new(AtomicUsize::new(0)),
            total_urls_attempted: Arc::new(AtomicUsize::new(0)),
            completed_urls: Arc::new(AtomicUsize::new(0)),
            failed_urls: Arc::new(AtomicUsize::new(0)),
            skipped_urls: Arc::new(AtomicUsize::new(0)),
            start_time: Arc::new(Instant::now()),
            error_stats: Arc::new(ProcessingStats::new()),
            timing_stats: Some(Arc::new(TimingStats::new())),
            request_limiter: None,
            runtime_metrics: Arc::new(crate::runtime_metrics::RuntimeMetrics::default()),
            run_id: None,
            run_start_time_unix_secs: None,
        };

        let metrics = render_metrics(&state, 0.0);
        assert!(metrics.contains("domain_status_percentage_complete 0"));
        assert!(!metrics.contains("domain_status_timing_http_request_ms"));
    }
}
