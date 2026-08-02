//! JSON status handler.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::sync::atomic::Ordering;

use super::super::progress::{concurrency_in_use, phase_label, progress_snapshot};
use super::super::types::{
    ErrorCounts, InfoCounts, StatusResponse, StatusState, TimingMetrics, TimingSummary,
    WarningCounts,
};
use crate::error_handling::{ErrorType, InfoType, WarningType};

fn micros_to_ms(micros: u64) -> u64 {
    (micros + 500) / 1000
}

fn refine_eta(
    lifetime_eta: Option<f64>,
    total_urls: usize,
    finished: usize,
    windowed_rate: f64,
) -> Option<f64> {
    let remaining = total_urls.saturating_sub(finished);
    if remaining == 0 && total_urls > 0 {
        return Some(0.0);
    }
    if remaining > 0 && windowed_rate > 0.0 {
        #[allow(clippy::cast_precision_loss)]
        return Some(remaining as f64 / windowed_rate);
    }
    lifetime_eta
}

/// Builds the structured `/status` response from the current state and elapsed time.
#[allow(clippy::too_many_lines)] // Assembles all status fields from atomic counters into a single response struct
pub(crate) fn build_status_response(state: &StatusState, elapsed: f64) -> StatusResponse {
    let snap = progress_snapshot(state, elapsed);
    let windowed_rate = state.throughput_window.observe(snap.finished);
    let eta_seconds = refine_eta(
        snap.eta_seconds,
        snap.total_urls,
        snap.finished,
        windowed_rate,
    );

    StatusResponse {
        total_urls: snap.total_urls,
        total_urls_attempted: snap.attempted,
        completed_urls: snap.completed,
        successful_urls: snap.successful,
        failed_urls: snap.failed,
        skipped_urls: snap.skipped,
        active_urls: snap.active_urls,
        pending_urls: Some(snap.pending_urls),
        percentage_complete: snap.percentage_complete,
        percentage_dispatched: snap.percentage_dispatched,
        elapsed_seconds: elapsed,
        rate_per_second: snap.rate_per_second,
        windowed_rate_per_second: windowed_rate,
        eta_seconds,
        phase: phase_label(state).to_string(),
        current_rps: state
            .request_limiter
            .as_ref()
            .map(|limiter| limiter.current_rps()),
        concurrency_limit: state.max_concurrency,
        concurrency_in_use: concurrency_in_use(state),
        retried_requests: state.runtime_metrics.retried_requests(),
        non_retriable_failures: state.runtime_metrics.non_retriable_failures(),
        errors: ErrorCounts {
            total: state.error_stats.total_errors(),
            timeout: state
                .error_stats
                .get_error_count(ErrorType::ProcessUrlTimeout)
                + state
                    .error_stats
                    .get_error_count(ErrorType::HttpRequestTimeoutError),
            connection_error: state
                .error_stats
                .get_error_count(ErrorType::HttpRequestConnectError),
            http_error: state
                .error_stats
                .get_error_count(ErrorType::HttpRequestStatusError)
                + state
                    .error_stats
                    .get_error_count(ErrorType::HttpRequestTooManyRequests)
                + state
                    .error_stats
                    .get_error_count(ErrorType::HttpRequestBadRequest)
                + state
                    .error_stats
                    .get_error_count(ErrorType::HttpRequestUnauthorized)
                + state
                    .error_stats
                    .get_error_count(ErrorType::HttpRequestNotFound)
                + state
                    .error_stats
                    .get_error_count(ErrorType::HttpRequestInternalServerError)
                + state
                    .error_stats
                    .get_error_count(ErrorType::HttpRequestBadGateway)
                + state
                    .error_stats
                    .get_error_count(ErrorType::HttpRequestServiceUnavailable)
                + state
                    .error_stats
                    .get_error_count(ErrorType::HttpRequestGatewayTimeout)
                + state
                    .error_stats
                    .get_error_count(ErrorType::HttpRequestBotDetectionError),
            dns_error: state
                .error_stats
                .get_error_count(ErrorType::DnsForwardLookupError)
                + state
                    .error_stats
                    .get_error_count(ErrorType::DnsNsLookupError)
                + state
                    .error_stats
                    .get_error_count(ErrorType::DnsTxtLookupError)
                + state
                    .error_stats
                    .get_error_count(ErrorType::DnsMxLookupError)
                + state
                    .error_stats
                    .get_error_count(ErrorType::DnsCnameLookupError)
                + state
                    .error_stats
                    .get_error_count(ErrorType::DnsAaaaLookupError)
                + state
                    .error_stats
                    .get_error_count(ErrorType::DnsCaaLookupError),
            tls_error: state
                .error_stats
                .get_error_count(ErrorType::TlsCertificateError),
            parse_error: state
                .error_stats
                .get_error_count(ErrorType::HttpRequestDecodeError)
                + state
                    .error_stats
                    .get_error_count(ErrorType::TitleExtractError),
            other_error: state
                .error_stats
                .get_error_count(ErrorType::HttpRequestOtherError)
                + state
                    .error_stats
                    .get_error_count(ErrorType::HttpRequestBuilderError)
                + state
                    .error_stats
                    .get_error_count(ErrorType::HttpRequestRedirectError)
                + state
                    .error_stats
                    .get_error_count(ErrorType::HttpRequestRequestError)
                + state
                    .error_stats
                    .get_error_count(ErrorType::HttpRequestBodyError)
                + state
                    .error_stats
                    .get_error_count(ErrorType::TechnologyDetectionError),
        },
        warnings: WarningCounts {
            total: state.error_stats.total_warnings(),
            missing_meta_description: state
                .error_stats
                .get_warning_count(WarningType::MissingMetaDescription),
            missing_title: state
                .error_stats
                .get_warning_count(WarningType::MissingTitle),
        },
        info: InfoCounts {
            total: state.error_stats.total_info(),
            http_redirect: state.error_stats.get_info_count(InfoType::HttpRedirect),
            https_redirect: state.error_stats.get_info_count(InfoType::HttpsRedirect),
            bot_detection_403: state.error_stats.get_info_count(InfoType::BotDetection403),
            multiple_redirects: state
                .error_stats
                .get_info_count(InfoType::MultipleRedirects),
        },
        timing: state.timing_stats.as_ref().and_then(|timing_stats| {
            let count = timing_stats.count.load(Ordering::Relaxed);
            if count > 0 {
                let avg = timing_stats.averages();
                Some(TimingSummary {
                    count,
                    averages: TimingMetrics {
                        http_request_ms: micros_to_ms(avg.http_request_us),
                        dns_forward_ms: micros_to_ms(avg.dns_forward_us),
                        dns_reverse_ms: micros_to_ms(avg.dns_reverse_us),
                        dns_additional_ms: micros_to_ms(avg.dns_additional_us),
                        tls_handshake_ms: micros_to_ms(avg.tls_handshake_us),
                        html_parsing_ms: micros_to_ms(avg.html_parsing_us),
                        tech_detection_ms: micros_to_ms(avg.tech_detection_us),
                        geoip_lookup_ms: micros_to_ms(avg.geoip_lookup_us),
                        whois_lookup_ms: micros_to_ms(avg.whois_lookup_us),
                        total_ms: micros_to_ms(avg.total_us),
                    },
                })
            } else {
                None
            }
        }),
    }
}

/// JSON status endpoint with detailed progress information
pub async fn status_handler(State(state): State<StatusState>) -> Response {
    let elapsed = state.start_time.elapsed().as_secs_f64();
    let response = build_status_response(&state, elapsed);

    let json = match serde_json::to_string_pretty(&response) {
        Ok(json) => json,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to serialize status: {e}"),
            )
                .into_response();
        }
    };

    (StatusCode::OK, [("content-type", "application/json")], json).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ProcessingStats;
    use crate::status_server::types::test_status_state;
    use crate::utils::{TimingStats, UrlTimingMetrics};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_status_handler_returns_json() {
        let state = test_status_state(100, 100, 50, 50, 10, 0);
        let response = status_handler(State(state)).await;

        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();
        assert_eq!(
            headers.get("content-type"),
            Some(&"application/json".parse().unwrap())
        );
    }

    #[test]
    fn test_build_status_response_returns_exact_contract() {
        let mut state = test_status_state(100, 80, 50, 50, 10, 0);
        state.error_stats = Arc::new({
            let stats = ProcessingStats::new();
            stats.increment_error(ErrorType::ProcessUrlTimeout);
            stats.increment_error(ErrorType::HttpRequestTimeoutError);
            stats.increment_error(ErrorType::DnsNsLookupError);
            stats.increment_warning(WarningType::MissingMetaDescription);
            stats.increment_info(InfoType::HttpRedirect);
            stats
        });
        state.timing_stats = Some(Arc::new({
            let stats = TimingStats::new();
            stats.record(&UrlTimingMetrics {
                http_request_us: 1500,
                dns_forward_us: 499,
                total_us: 2000,
                ..Default::default()
            });
            stats
        }));
        state.runtime_metrics = Arc::new({
            let metrics = crate::runtime_metrics::RuntimeMetrics::default();
            metrics.record_retry();
            metrics.record_non_retriable_failure();
            metrics
        });

        let response = build_status_response(&state, 5.0);
        assert_eq!(response.total_urls, 100);
        assert_eq!(response.total_urls_attempted, 80);
        assert_eq!(response.completed_urls, 50);
        assert_eq!(response.successful_urls, 50);
        assert_eq!(response.failed_urls, 10);
        assert_eq!(response.skipped_urls, 0);
        assert_eq!(response.active_urls, 20);
        assert_eq!(response.pending_urls, Some(20));
        // finished = 60 / 100
        assert!((response.percentage_complete - 60.0).abs() < f64::EPSILON);
        assert!((response.percentage_dispatched - 80.0).abs() < f64::EPSILON);
        assert!((response.rate_per_second - 12.0).abs() < f64::EPSILON);
        assert_eq!(response.phase, "scanning");
        assert_eq!(response.retried_requests, 1);
        assert_eq!(response.non_retriable_failures, 1);
        assert_eq!(response.errors.total, 3);
        assert_eq!(response.errors.timeout, 2);
        assert_eq!(response.errors.dns_error, 1);
        assert_eq!(response.warnings.missing_meta_description, 1);
        assert_eq!(response.info.http_redirect, 1);
        let timing = response.timing.expect("timing present");
        assert_eq!(timing.count, 1);
        assert_eq!(timing.averages.http_request_ms, 2);
        assert_eq!(timing.averages.total_ms, 2);
    }

    #[test]
    fn test_early_skips_do_not_inflate_active_urls() {
        // Early invalid/SSRF skip: attempted++ and skipped++, not completed.
        let state = test_status_state(10, 3, 0, 0, 0, 3);
        let response = build_status_response(&state, 1.0);
        assert_eq!(response.skipped_urls, 3);
        assert_eq!(response.active_urls, 0);
        assert!((response.percentage_complete - 30.0).abs() < f64::EPSILON);
        assert!((response.percentage_dispatched - 30.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_build_status_response_handles_zero_total_urls() {
        let state = test_status_state(0, 0, 0, 0, 0, 0);
        let response = build_status_response(&state, 0.0);
        assert_eq!(response.pending_urls, Some(0));
        assert!(response.percentage_complete.abs() < f64::EPSILON);
        assert!(response.rate_per_second.abs() < f64::EPSILON);
        assert_eq!(response.timing, None);
        assert!(response.eta_seconds.is_none());
    }

    #[test]
    fn test_build_status_response_uses_saturating_pending_urls() {
        let state = test_status_state(100, 100, 150, 150, 50, 0);
        let response = build_status_response(&state, 1.0);
        assert_eq!(response.pending_urls, Some(0));
    }

    #[test]
    fn test_mid_process_skip_counts_once_in_finished() {
        // Mid-process skip increments skipped only (not completed).
        let state = test_status_state(10, 2, 1, 1, 0, 1);
        let response = build_status_response(&state, 2.0);
        assert_eq!(response.active_urls, 0);
        assert_eq!(response.successful_urls, 1);
        assert_eq!(response.skipped_urls, 1);
        assert!((response.percentage_complete - 20.0).abs() < f64::EPSILON);
        assert!((response.rate_per_second - 1.0).abs() < f64::EPSILON);
    }
}
