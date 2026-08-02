//! Prometheus metrics handler.

use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

use super::super::progress::{concurrency_in_use, phase_label, progress_snapshot};
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
#[allow(clippy::too_many_lines)] // Prometheus text format requires one line per metric; splitting would fragment the output
pub(crate) fn render_metrics(state: &StatusState, elapsed: f64) -> String {
    let snap = progress_snapshot(state, elapsed);
    let windowed_rate = state.throughput_window.observe(snap.finished);
    let phase = phase_label(state);
    let concurrency_in_use = concurrency_in_use(state).unwrap_or(0);
    let concurrency_limit = state.max_concurrency.unwrap_or(0);
    let remaining = snap.total_urls.saturating_sub(snap.finished);
    #[allow(clippy::cast_precision_loss)]
    let eta = if remaining == 0 && snap.total_urls > 0 {
        0.0
    } else if remaining > 0 && windowed_rate > 0.0 {
        remaining as f64 / windowed_rate
    } else {
        snap.eta_seconds.unwrap_or(0.0)
    };

    let total_errors = state.error_stats.total_errors();
    let total_warnings = state.error_stats.total_warnings();
    let total_info = state.error_stats.total_info();

    let timing_metrics = if let Some(timing_stats) = &state.timing_stats {
        let count = timing_stats
            .count
            .load(std::sync::atomic::Ordering::Relaxed);
        if count > 0 {
            let avg = timing_stats.averages();

            format!(
                r"
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

# HELP domain_status_timing_total_ms Average total processing time in milliseconds
# TYPE domain_status_timing_total_ms gauge
domain_status_timing_total_ms {}
",
                micros_to_ms(avg.http_request_us),
                micros_to_ms(avg.dns_forward_us),
                micros_to_ms(avg.dns_reverse_us),
                micros_to_ms(avg.dns_additional_us),
                micros_to_ms(avg.tls_handshake_us),
                micros_to_ms(avg.html_parsing_us),
                micros_to_ms(avg.tech_detection_us),
                micros_to_ms(avg.geoip_lookup_us),
                micros_to_ms(avg.whois_lookup_us),
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
domain_status_run_info{{run_id="{run_id_label}"}} 1

# HELP domain_status_elapsed_seconds Seconds since the current run started
# TYPE domain_status_elapsed_seconds gauge
domain_status_elapsed_seconds {elapsed}

# HELP domain_status_start_time_seconds Unix timestamp when the run started
# TYPE domain_status_start_time_seconds gauge
domain_status_start_time_seconds {start_time_secs}

# HELP domain_status_total_urls Total number of URLs to process
# TYPE domain_status_total_urls gauge
domain_status_total_urls {total}

# HELP domain_status_completed_urls URLs finished via the success path (persisted inserts; excludes skips)
# TYPE domain_status_completed_urls gauge
domain_status_completed_urls {completed}

# HELP domain_status_successful_urls URLs that produced a persisted url_status row
# TYPE domain_status_successful_urls gauge
domain_status_successful_urls {successful}

# HELP domain_status_failed_urls Number of URLs that failed to process
# TYPE domain_status_failed_urls gauge
domain_status_failed_urls {failed}

# HELP domain_status_skipped_urls URLs skipped (invalid, SSRF-unsafe, or intentional mid-process skip)
# TYPE domain_status_skipped_urls gauge
domain_status_skipped_urls {skipped}

# HELP domain_status_attempted_urls Number of URLs that have entered processing or early-skip
# TYPE domain_status_attempted_urls gauge
domain_status_attempted_urls {attempted}

# HELP domain_status_active_urls Number of URLs currently in flight
# TYPE domain_status_active_urls gauge
domain_status_active_urls {active}

# HELP domain_status_percentage_complete Percentage of URLs finished (successful+failed+skipped)/total (0-100)
# TYPE domain_status_percentage_complete gauge
domain_status_percentage_complete {pct_complete}

# HELP domain_status_percentage_dispatched Percentage of URLs dispatched (attempted)/total (0-100)
# TYPE domain_status_percentage_dispatched gauge
domain_status_percentage_dispatched {pct_dispatched}

# HELP domain_status_rate_per_second Lifetime finished URLs per second
# TYPE domain_status_rate_per_second gauge
domain_status_rate_per_second {rate}

# HELP domain_status_windowed_rate_per_second Recent finished URLs per second (approx 1s+ window)
# TYPE domain_status_windowed_rate_per_second gauge
domain_status_windowed_rate_per_second {windowed_rate}

# HELP domain_status_eta_seconds Estimated seconds remaining (0 when unknown or complete)
# TYPE domain_status_eta_seconds gauge
domain_status_eta_seconds {eta}

# HELP domain_status_phase Scan lifecycle phase (1=scanning, 2=draining, 3=finalizing)
# TYPE domain_status_phase gauge
domain_status_phase{{phase="{phase}"}} {phase_num}

# HELP domain_status_concurrency_limit Configured max concurrent URL tasks
# TYPE domain_status_concurrency_limit gauge
domain_status_concurrency_limit {concurrency_limit}

# HELP domain_status_concurrency_in_use Concurrent URL tasks currently holding a semaphore permit
# TYPE domain_status_concurrency_in_use gauge
domain_status_concurrency_in_use {concurrency_in_use}

# HELP domain_status_errors_total Total number of errors encountered
# TYPE domain_status_errors_total counter
domain_status_errors_total {total_errors}

# HELP domain_status_warnings_total Total number of warnings encountered
# TYPE domain_status_warnings_total counter
domain_status_warnings_total {total_warnings}

# HELP domain_status_info_total Total number of info events
# TYPE domain_status_info_total counter
domain_status_info_total {total_info}

# HELP domain_status_runtime_retries_total Total retry attempts consumed
# TYPE domain_status_runtime_retries_total counter
domain_status_runtime_retries_total {retries}

# HELP domain_status_runtime_non_retriable_failures_total Total failures classified as terminal at the retry boundary
# TYPE domain_status_runtime_non_retriable_failures_total counter
domain_status_runtime_non_retriable_failures_total {non_retriable}

# HELP domain_status_current_rps Configured request-rate limit (not measured throughput)
# TYPE domain_status_current_rps gauge
domain_status_current_rps {current_rps}
{timing_metrics}"#,
        total = snap.total_urls,
        completed = snap.completed,
        successful = snap.successful,
        failed = snap.failed,
        skipped = snap.skipped,
        attempted = snap.attempted,
        active = snap.active_urls,
        pct_complete = snap.percentage_complete,
        pct_dispatched = snap.percentage_dispatched,
        rate = snap.rate_per_second,
        phase_num = match phase {
            "draining" => 2,
            "finalizing" => 3,
            _ => 1,
        },
        retries = state.runtime_metrics.retried_requests(),
        non_retriable = state.runtime_metrics.non_retriable_failures(),
        current_rps = state
            .request_limiter
            .as_ref()
            .map_or(0, |limiter| limiter.current_rps()),
    )
}

/// Prometheus-compatible metrics endpoint
pub async fn metrics_handler(State(state): State<StatusState>) -> Response {
    let elapsed = state.start_time.elapsed().as_secs_f64();
    let body = render_metrics(&state, elapsed);
    let mut response = (StatusCode::OK, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ProcessingStats;
    use crate::status_server::types::test_status_state;
    use crate::utils::{TimingStats, UrlTimingMetrics};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_metrics_handler_returns_text() {
        let state = test_status_state(100, 100, 50, 50, 10, 0);
        let response = metrics_handler(State(state)).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; version=0.0.4; charset=utf-8"
        );
    }

    #[tokio::test]
    async fn test_metrics_handler_includes_basic_metrics() {
        let state = test_status_state(100, 100, 50, 50, 10, 0);
        let response = metrics_handler(State(state)).await;

        assert_eq!(response.status(), StatusCode::OK);

        let (_parts, body) = response.into_parts();
        let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        assert!(body_str.contains("domain_status_total_urls"));
        assert!(body_str.contains("domain_status_completed_urls"));
        assert!(body_str.contains("domain_status_successful_urls"));
        assert!(body_str.contains("domain_status_skipped_urls"));
        assert!(body_str.contains("domain_status_failed_urls"));
        assert!(body_str.contains("domain_status_percentage_complete"));
        assert!(body_str.contains("domain_status_percentage_dispatched"));
        assert!(body_str.contains("domain_status_windowed_rate_per_second"));
        assert!(body_str.contains("domain_status_eta_seconds"));
        assert!(body_str.contains("domain_status_phase"));
        assert!(body_str.contains("domain_status_rate_per_second"));
        assert!(body_str.contains("domain_status_errors_total"));
    }

    #[test]
    fn test_render_metrics_early_skip_active_zero() {
        let state = test_status_state(10, 3, 0, 0, 0, 3);
        let metrics = render_metrics(&state, 1.0);
        assert!(metrics.contains("domain_status_active_urls 0"));
        assert!(metrics.contains("domain_status_skipped_urls 3"));
        assert!(metrics.contains("domain_status_percentage_complete 30"));
    }

    #[test]
    fn test_render_metrics_includes_timing_when_present() {
        let timing_stats = Arc::new(TimingStats::new());
        timing_stats.record(&UrlTimingMetrics {
            http_request_us: 1500,
            total_us: 2000,
            ..Default::default()
        });
        let mut state = test_status_state(100, 60, 50, 50, 10, 0);
        state.error_stats = Arc::new({
            let stats = ProcessingStats::new();
            stats.increment_error(crate::error_handling::ErrorType::DnsNsLookupError);
            stats.increment_warning(crate::error_handling::WarningType::MissingTitle);
            stats.increment_info(crate::error_handling::InfoType::HttpsRedirect);
            stats
        });
        state.timing_stats = Some(timing_stats);
        state.runtime_metrics = Arc::new({
            let metrics = crate::runtime_metrics::RuntimeMetrics::default();
            metrics.record_retry();
            metrics
        });

        let metrics = render_metrics(&state, 5.0);
        assert!(metrics.contains("domain_status_completed_urls 50"));
        assert!(metrics.contains("domain_status_successful_urls 50"));
        assert!(metrics.contains("domain_status_percentage_complete 60"));
        assert!(metrics.contains("domain_status_percentage_dispatched 60"));
        assert!(metrics.contains("domain_status_rate_per_second 12"));
        assert!(metrics.contains("domain_status_timing_http_request_ms 2"));
        assert!(metrics.contains("domain_status_timing_total_ms 2"));
        assert!(metrics.contains("domain_status_runtime_retries_total 1"));
        assert!(metrics.contains(r#"domain_status_phase{phase="scanning"} 1"#));
    }

    #[test]
    fn test_render_metrics_omits_timing_when_empty() {
        let mut state = test_status_state(0, 0, 0, 0, 0, 0);
        state.timing_stats = Some(Arc::new(TimingStats::new()));

        let metrics = render_metrics(&state, 0.0);
        assert!(metrics.contains("domain_status_percentage_complete 0"));
        assert!(!metrics.contains("domain_status_timing_http_request_ms"));
    }
}
