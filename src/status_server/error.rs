//! Error types for the status server.
//!
//! Two distinct concerns live here:
//!
//! * `StatusServerError` — what fallible HTTP handlers return so they become
//!   consistent HTTP responses via [`axum::response::IntoResponse`]. Currently
//!   no handler is fallible; the type is kept so future endpoints can adopt
//!   `Result<T, StatusServerError>` without changes here.
//! * `StatusServerLifecycleError` — typed error returned by
//!   [`super::spawn_status_server`] and [`super::StatusServerHandle::shutdown`]
//!   so callers can branch on bind / serve / background-task failures
//!   without resorting to string matching against an opaque `anyhow::Error`.
#![allow(dead_code)]

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::fmt;
use thiserror::Error;

/// Error returned by status server handlers that can fail.
///
/// Implements `IntoResponse` so handlers can return `Result<T, StatusServerError>`
/// and get a consistent HTTP error response (e.g. 500 with body). Current
/// handlers (health, metrics, status) are infallible; use this when adding
/// new endpoints that may fail.
#[derive(Debug)]
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
    pub fn internal(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: msg.into(),
        }
    }

    /// Service unavailable (503), e.g. when the scan is not ready.
    pub fn unavailable(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: msg.into(),
        }
    }
}

/// Lifecycle errors for [`super::spawn_status_server`] and
/// [`super::StatusServerHandle::shutdown`].
///
/// Typed (rather than `anyhow::Error`) so library callers can branch on the
/// failure mode (port already bound, server-loop crash, background-task
/// panic) without parsing error messages.
///
/// Marked `#[non_exhaustive]` so adding new failure modes is not breaking.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum StatusServerLifecycleError {
    /// Failed to bind to the configured TCP port.
    #[error("Failed to bind status server to port {port}")]
    Bind {
        /// The port that was being bound.
        port: u16,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Axum's `serve` loop returned an error after the server started.
    #[error("Status server error during serve")]
    Serve(#[source] std::io::Error),

    /// The background `tokio::spawn` task panicked or was cancelled.
    #[error("Status server background task panicked")]
    BackgroundTask(#[from] tokio::task::JoinError),
}
