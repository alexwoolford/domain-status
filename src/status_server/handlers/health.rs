//! Health check handler for orchestrators and reverse proxies.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

/// Returns 200 OK when the status server is up. No shared state required.
/// Useful for Kubernetes liveness probes, load balancers, or reverse proxies.
pub async fn health_handler() -> Response {
    (StatusCode::OK, "ok").into_response()
}
