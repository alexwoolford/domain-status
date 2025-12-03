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
            ((completed + failed) as f64 / total as f64) * 100.0
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
