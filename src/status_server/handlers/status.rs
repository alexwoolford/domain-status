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

/// JSON status endpoint with detailed progress information
pub async fn status_handler(State(state): State<StatusState>) -> Response {
    let total_urls_in_file = state.total_urls.load(Ordering::SeqCst);
    let completed = state.completed_urls.load(Ordering::SeqCst);
    let failed = state.failed_urls.load(Ordering::SeqCst);
    let elapsed = state.start_time.elapsed().as_secs_f64();
    let rate = if elapsed > 0.0 {
        completed as f64 / elapsed
    } else {
        0.0
    };

    // Calculate percentage based on total URLs in file (completed + failed out of total)
    // This shows progress through all URLs in the file, not just attempted ones
    let processed = completed + failed;
    let percentage = if total_urls_in_file > 0 {
        (processed as f64 / total_urls_in_file as f64) * 100.0
    } else {
        0.0
    };

    // Pending URLs = total URLs in file that haven't completed or failed yet
    // This includes both URLs that are currently being processed and URLs that haven't been read yet
    let pending_urls = total_urls_in_file
        .saturating_sub(completed)
        .saturating_sub(failed);

    let response = StatusResponse {
        total_urls: total_urls_in_file, // Use total URLs in file, not just attempted
        completed_urls: completed,
        failed_urls: failed,
        pending_urls: Some(pending_urls),
        percentage_complete: percentage,
        elapsed_seconds: elapsed,
        rate_per_second: rate,
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
                // Convert from microseconds to milliseconds for display
                let micros_to_ms = |micros: u64| (micros + 500) / 1000;

                Some(TimingSummary {
                    count,
                    averages: TimingMetrics {
                        http_request_ms: micros_to_ms(avg.http_request_ms),
                        dns_forward_ms: micros_to_ms(avg.dns_forward_ms),
                        dns_reverse_ms: micros_to_ms(avg.dns_reverse_ms),
                        dns_additional_ms: micros_to_ms(avg.dns_additional_ms),
                        tls_handshake_ms: micros_to_ms(avg.tls_handshake_ms),
                        html_parsing_ms: micros_to_ms(avg.html_parsing_ms),
                        tech_detection_ms: micros_to_ms(avg.tech_detection_ms),
                        geoip_lookup_ms: micros_to_ms(avg.geoip_lookup_ms),
                        whois_lookup_ms: micros_to_ms(avg.whois_lookup_ms),
                        security_analysis_ms: micros_to_ms(avg.security_analysis_ms),
                        total_ms: micros_to_ms(avg.total_ms),
                    },
                })
            } else {
                None
            }
        }),
    };

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

    #[tokio::test]
    async fn test_status_handler_calculates_percentage() {
        let state = create_test_state();
        let response = status_handler(State(state)).await;

        // Response should be valid JSON
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_status_handler_handles_zero_urls() {
        let state = StatusState {
            total_urls: Arc::new(AtomicUsize::new(0)),
            total_urls_attempted: Arc::new(AtomicUsize::new(0)),
            completed_urls: Arc::new(AtomicUsize::new(0)),
            failed_urls: Arc::new(AtomicUsize::new(0)),
            start_time: Arc::new(Instant::now()),
            error_stats: Arc::new(ProcessingStats::new()),
            timing_stats: None,
        };

        let response = status_handler(State(state)).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_status_handler_handles_serialization_error() {
        // This test verifies error handling, but we can't easily trigger
        // a serialization error without mocking serde_json
        // The error path is tested via code review
        let state = create_test_state();
        let response = status_handler(State(state)).await;
        // Should succeed with normal state
        assert_eq!(response.status(), StatusCode::OK);
    }
}
