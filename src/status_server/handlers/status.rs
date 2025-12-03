//! JSON status handler.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::sync::atomic::Ordering;

use super::super::types::{ErrorCounts, InfoCounts, StatusResponse, StatusState, WarningCounts};
use crate::error_handling::{ErrorType, InfoType, WarningType};

/// JSON status endpoint with detailed progress information
pub async fn status_handler(State(state): State<StatusState>) -> Response {
    let total = state.total_urls.load(Ordering::SeqCst);
    let completed = state.completed_urls.load(Ordering::SeqCst);
    let failed = state.failed_urls.load(Ordering::SeqCst);
    let elapsed = state.start_time.elapsed().as_secs_f64();
    let rate = if elapsed > 0.0 {
        completed as f64 / elapsed
    } else {
        0.0
    };

    // Calculate percentage based on total URLs (completed + failed out of total)
    // This shows progress through the entire job, not just attempted URLs
    let attempted = completed + failed;
    let percentage = if total > 0 {
        (attempted as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let pending_urls = total.saturating_sub(completed).saturating_sub(failed);

    let response = StatusResponse {
        total_urls: total,
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
                    .get_error_count(ErrorType::HttpRequestNotAcceptable)
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
                    .get_error_count(ErrorType::HttpRequestCloudflareError)
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
