//! Error type for status server handlers.
//!
//! Use when adding fallible handlers so that failures become consistent HTTP
//! responses and can be logged in one place (e.g. via `log_error_chain`).

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::fmt;

/// Error returned by status server handlers that can fail.
///
/// Implements `IntoResponse` so handlers can return `Result<T, StatusServerError>`
/// and get a consistent HTTP error response (e.g. 500 with body). Current
/// handlers (health, metrics, status) are infallible; use this when adding
/// new endpoints that may fail.
#[derive(Debug)]
#[allow(dead_code)] // Used when fallible handlers are added
pub struct StatusServerError {
    /// HTTP status code for the response.
    pub status: StatusCode,
    /// Message included in the response body and logs.
    pub message: String,
}

impl fmt::Display for StatusServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for StatusServerError {}

impl IntoResponse for StatusServerError {
    fn into_response(self) -> Response {
        log::error!("Status server error: {}", self.message);
        (self.status, self.message).into_response()
    }
}

impl StatusServerError {
    /// Internal server error (500).
    #[allow(dead_code)]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: msg.into(),
        }
    }

    /// Service unavailable (503), e.g. when the scan is not ready.
    #[allow(dead_code)]
    pub fn unavailable(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: msg.into(),
        }
    }
}
