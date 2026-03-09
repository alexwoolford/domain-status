//! JSON status handler.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::sync::atomic::Ordering;

use super::super::types::{
    ErrorCounts, InfoCounts, StatusResponse, StatusState, TimingMetrics, TimingSummary,
    WarningCounts,
};
use crate::error_handling::{ErrorType, InfoType, WarningType};

fn micros_to_ms(micros: u64) -> u64 {
    (micros + 500) / 1000
}

/// Builds the structured `/status` response from the current state and elapsed time.
#[allow(clippy::too_many_lines)]
pub(crate) fn build_status_response(state: &StatusState, elapsed: f64) -> StatusResponse {
    let total_urls_in_file = state.total_urls.load(Ordering::SeqCst);
    let attempted = state.total_urls_attempted.load(Ordering::SeqCst);
    let completed = state.completed_urls.load(Ordering::SeqCst);
    let failed = state.failed_urls.load(Ordering::SeqCst);
    let processed = completed + failed;
    let active_urls = attempted.saturating_sub(processed);
    // Progress is based on lines dealt with (attempted or skipped), so the bar reaches 100% when done
    #[allow(clippy::cast_precision_loss)]
    let percentage = if total_urls_in_file > 0 {
        (attempted as f64 / total_urls_in_file as f64) * 100.0
    } else {
        0.0
    };
    #[allow(clippy::cast_precision_loss)]
    let rate = if elapsed > 0.0 {
        completed as f64 / elapsed
    } else {
        0.0
    };
    let pending_urls = total_urls_in_file.saturating_sub(attempted);

    StatusResponse {
        total_urls: total_urls_in_file,
        total_urls_attempted: attempted,
        completed_urls: completed,
        failed_urls: failed,
        active_urls,
        pending_urls: Some(pending_urls),
        percentage_complete: percentage,
        elapsed_seconds: elapsed,
        rate_per_second: rate,
        current_rps: state
            .request_limiter
            .as_ref()
            .map(|limiter| limiter.current_rps()),
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
                .get_error_count(ErrorType::DnsNsLookupError)
                + state
                    .error_stats
                    .get_error_count(ErrorType::DnsTxtLookupError)
                + state
                    .error_stats
                    .get_error_count(ErrorType::DnsMxLookupError),
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
            missing_meta_keywords: state
                .error_stats
                .get_warning_count(WarningType::MissingMetaKeywords),
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
                        security_analysis_ms: micros_to_ms(avg.security_analysis_us),
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
                format!("Failed to serialize status: {}", e),
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
    use crate::status_server::StatusState;
    use crate::utils::{TimingStats, UrlTimingMetrics};
    use pretty_assertions::assert_eq;
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
            request_limiter: None,
            runtime_metrics: Arc::new(crate::runtime_metrics::RuntimeMetrics::default()),
            run_id: None,
            run_start_time_unix_secs: None,
        }
    }

    #[tokio::test]
    async fn test_status_handler_returns_json() {
        let state = create_test_state();
        let response = status_handler(State(state)).await;

        assert_eq!(response.status(), StatusCode::OK);

        // Verify content-type header
        let headers = response.headers();
        assert_eq!(
            headers.get("content-type"),
            Some(&"application/json".parse().unwrap())
        );
    }

    #[test]
    fn test_build_status_response_returns_exact_contract() {
        let state = StatusState {
            total_urls: Arc::new(AtomicUsize::new(100)),
            total_urls_attempted: Arc::new(AtomicUsize::new(80)),
            completed_urls: Arc::new(AtomicUsize::new(50)),
            failed_urls: Arc::new(AtomicUsize::new(10)),
            start_time: Arc::new(Instant::now()),
            error_stats: Arc::new({
                let stats = ProcessingStats::new();
                stats.increment_error(ErrorType::ProcessUrlTimeout);
                stats.increment_error(ErrorType::HttpRequestTimeoutError);
                stats.increment_error(ErrorType::DnsNsLookupError);
                stats.increment_warning(WarningType::MissingMetaDescription);
                stats.increment_info(InfoType::HttpRedirect);
                stats
            }),
            timing_stats: Some(Arc::new({
                let stats = TimingStats::new();
                stats.record(&UrlTimingMetrics {
                    http_request_us: 1500,
                    dns_forward_us: 499,
                    total_us: 2000,
                    ..Default::default()
                });
                stats
            })),
            request_limiter: None,
            runtime_metrics: Arc::new({
                let metrics = crate::runtime_metrics::RuntimeMetrics::default();
                metrics.record_retry();
                metrics.record_non_retriable_failure();
                metrics
            }),
            run_id: None,
            run_start_time_unix_secs: None,
        };

        let response = build_status_response(&state, 5.0);
        assert_eq!(
            response,
            StatusResponse {
                total_urls: 100,
                total_urls_attempted: 80,
                completed_urls: 50,
                failed_urls: 10,
                active_urls: 20,
                pending_urls: Some(20), // total - attempted (lines not yet dealt with)
                percentage_complete: 80.0, // attempted / total (progress reaches 100% when done)
                elapsed_seconds: 5.0,
                rate_per_second: 10.0,
                current_rps: None,
                retried_requests: 1,
                non_retriable_failures: 1,
                errors: ErrorCounts {
                    total: 3,
                    timeout: 2,
                    connection_error: 0,
                    http_error: 0,
                    dns_error: 1,
                    tls_error: 0,
                    parse_error: 0,
                    other_error: 0,
                },
                warnings: WarningCounts {
                    total: 1,
                    missing_meta_keywords: 0,
                    missing_meta_description: 1,
                    missing_title: 0,
                },
                info: InfoCounts {
                    total: 1,
                    http_redirect: 1,
                    https_redirect: 0,
                    bot_detection_403: 0,
                    multiple_redirects: 0,
                },
                timing: Some(TimingSummary {
                    count: 1,
                    averages: TimingMetrics {
                        http_request_ms: 2,
                        dns_forward_ms: 0,
                        dns_reverse_ms: 0,
                        dns_additional_ms: 0,
                        tls_handshake_ms: 0,
                        html_parsing_ms: 0,
                        tech_detection_ms: 0,
                        geoip_lookup_ms: 0,
                        whois_lookup_ms: 0,
                        security_analysis_ms: 0,
                        total_ms: 2,
                    },
                }),
            }
        );
    }

    #[test]
    fn test_build_status_response_handles_zero_total_urls() {
        let state = StatusState {
            total_urls: Arc::new(AtomicUsize::new(0)),
            total_urls_attempted: Arc::new(AtomicUsize::new(0)),
            completed_urls: Arc::new(AtomicUsize::new(0)),
            failed_urls: Arc::new(AtomicUsize::new(0)),
            start_time: Arc::new(Instant::now()),
            error_stats: Arc::new(ProcessingStats::new()),
            timing_stats: None,
            request_limiter: None,
            runtime_metrics: Arc::new(crate::runtime_metrics::RuntimeMetrics::default()),
            run_id: None,
            run_start_time_unix_secs: None,
        };

        let response = build_status_response(&state, 0.0);
        assert_eq!(response.pending_urls, Some(0));
        assert!(response.percentage_complete.abs() < f64::EPSILON);
        assert!(response.rate_per_second.abs() < f64::EPSILON);
        assert_eq!(response.timing, None);
    }

    #[test]
    fn test_build_status_response_uses_saturating_pending_urls() {
        let state = StatusState {
            total_urls: Arc::new(AtomicUsize::new(100)),
            total_urls_attempted: Arc::new(AtomicUsize::new(100)),
            completed_urls: Arc::new(AtomicUsize::new(150)),
            failed_urls: Arc::new(AtomicUsize::new(50)),
            start_time: Arc::new(Instant::now()),
            error_stats: Arc::new(ProcessingStats::new()),
            timing_stats: None,
            request_limiter: None,
            runtime_metrics: Arc::new(crate::runtime_metrics::RuntimeMetrics::default()),
            run_id: None,
            run_start_time_unix_secs: None,
        };

        let response = build_status_response(&state, 1.0);
        assert_eq!(response.pending_urls, Some(0));
    }
}
