//! HTTP status server for monitoring long-running jobs.
//!
//! Provides two endpoints:
//! - `/metrics` - Prometheus-compatible metrics
//! - `/status` - JSON status endpoint with detailed progress information
//!
//! The server runs in the background and does not block URL processing.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde::Serialize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::error_handling::ProcessingStats;

/// Shared state for the status server
#[derive(Clone)]
pub struct StatusState {
    pub total_urls: Arc<AtomicUsize>,
    pub completed_urls: Arc<AtomicUsize>,
    pub failed_urls: Arc<AtomicUsize>,
    pub start_time: Arc<Instant>,
    pub error_stats: Arc<ProcessingStats>,
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

/// Creates and starts the status server
pub async fn start_status_server(port: u16, state: StatusState) -> Result<(), anyhow::Error> {
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/status", get(status_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind status server to port {}: {}", port, e))?;

    log::info!("Status server listening on http://127.0.0.1:{}/", port);
    log::info!("  - Metrics: http://127.0.0.1:{}/metrics", port);
    log::info!("  - Status: http://127.0.0.1:{}/status", port);

    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow::anyhow!("Status server error: {}", e))?;

    Ok(())
}

/// Prometheus-compatible metrics endpoint
async fn metrics_handler(State(state): State<StatusState>) -> Response {
    let total = state.total_urls.load(Ordering::SeqCst);
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
"#,
        total,
        completed,
        failed,
        if total > 0 {
            (completed as f64 / total as f64) * 100.0
        } else {
            0.0
        },
        rate,
        total_errors,
        total_warnings,
        total_info
    );

    (StatusCode::OK, metrics).into_response()
}

/// JSON status endpoint with detailed progress information
async fn status_handler(State(state): State<StatusState>) -> Response {
    let total = state.total_urls.load(Ordering::SeqCst);
    let completed = state.completed_urls.load(Ordering::SeqCst);
    let failed = state.failed_urls.load(Ordering::SeqCst);
    let elapsed = state.start_time.elapsed().as_secs_f64();
    let rate = if elapsed > 0.0 {
        completed as f64 / elapsed
    } else {
        0.0
    };

    // Calculate percentage based on completed + failed (not total, since some URLs may not be attempted yet)
    let attempted = completed + failed;
    let percentage = if attempted > 0 {
        (completed as f64 / attempted as f64) * 100.0
    } else {
        0.0
    };

    use crate::error_handling::{ErrorType, InfoType, WarningType};

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
