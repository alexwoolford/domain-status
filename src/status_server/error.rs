//! Lifecycle error types for the status server.
//!
//! [`StatusServerLifecycleError`] is returned by
//! [`super::spawn_status_server`] and [`super::StatusServerHandle::shutdown`]
//! so callers can branch on bind / serve / background-task failures
//! without resorting to string matching against an opaque `anyhow::Error`.
//!
//! Note: the `super::` references are written as plain code spans rather than
//! rustdoc intra-doc links because the parent `status_server` module is
//! private; rustdoc's `private-intra-doc-links` lint (escalated to error by
//! CI's `RUSTDOCFLAGS="-D warnings"` setting) would reject the bracketed
//! `super::...` form.

use thiserror::Error;

/// Lifecycle errors for `spawn_status_server` and `StatusServerHandle::shutdown`.
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
