//! HTTP status server for monitoring long-running jobs.
//!
//! Provides three endpoints:
//! - `/health` - Liveness check (200 OK when server is up)
//! - `/metrics` - Prometheus-compatible metrics
//! - `/status` - JSON status endpoint with detailed progress information
//!
//! The server runs in the background and does not block URL processing.

mod error;
mod handlers;
mod types;

#[allow(unused_imports)] // Re-exported for use when fallible handlers are added
pub use error::StatusServerError;
pub use error::StatusServerLifecycleError;

use axum::routing::get;
use axum::Router;
use tokio_util::sync::CancellationToken;

use handlers::{health_handler, metrics_handler, status_handler};
pub use types::StatusState;

/// Managed background status server with explicit shutdown semantics.
#[derive(Debug)]
pub struct StatusServerHandle {
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<Result<(), StatusServerLifecycleError>>,
}

impl StatusServerHandle {
    /// Gracefully stop the status server and wait for the task to exit.
    ///
    /// Returns a typed [`StatusServerLifecycleError`] so callers can branch
    /// on `Bind` / `Serve` / `BackgroundTask` failures without inspecting
    /// error message strings.
    pub async fn shutdown(self) -> Result<(), StatusServerLifecycleError> {
        self.shutdown.cancel();
        match self.task.await {
            Ok(result) => result,
            // `JoinError` -> `StatusServerLifecycleError::BackgroundTask` via
            // `#[from]`.
            Err(join_error) => Err(StatusServerLifecycleError::from(join_error)),
        }
    }
}

/// Build the status server router with the supplied shared state.
pub fn build_router(state: StatusState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .route("/status", get(status_handler))
        .with_state(state)
}

/// Creates, binds, and starts the status server as a managed background task.
pub async fn spawn_status_server(
    port: u16,
    state: StatusState,
) -> Result<StatusServerHandle, StatusServerLifecycleError> {
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .map_err(|source| StatusServerLifecycleError::Bind { port, source })?;

    log::info!("Status server listening on http://127.0.0.1:{port}/");
    log::info!("  - Health: http://127.0.0.1:{port}/health");
    log::info!("  - Metrics: http://127.0.0.1:{port}/metrics");
    log::info!("  - Status: http://127.0.0.1:{port}/status");

    let shutdown = CancellationToken::new();
    let shutdown_signal = shutdown.clone();
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                shutdown_signal.cancelled().await;
            })
            .await
            .map_err(StatusServerLifecycleError::Serve)
    });

    Ok(StatusServerHandle { shutdown, task })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ProcessingStats;
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use std::time::Instant;
    use tower::ServiceExt;

    fn create_test_state() -> StatusState {
        StatusState {
            total_urls: Arc::new(AtomicUsize::new(100)),
            total_urls_attempted: Arc::new(AtomicUsize::new(100)),
            completed_urls: Arc::new(AtomicUsize::new(50)),
            failed_urls: Arc::new(AtomicUsize::new(10)),
            skipped_urls: Arc::new(AtomicUsize::new(0)),
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
    async fn test_build_router_serves_health_endpoint() {
        let app = build_router(create_test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("health response");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_build_router_serves_status_endpoint() {
        let app = build_router(create_test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("status response");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_build_router_serves_metrics_endpoint() {
        let app = build_router(create_test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("metrics response");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_spawn_status_server_returns_bind_error_for_in_use_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let error = spawn_status_server(port, create_test_state())
            .await
            .expect_err("port already bound should fail");
        // The error must be the typed `Bind` variant (callers branch on
        // this; previously they had to parse the anyhow message string,
        // which is fragile).
        match &error {
            StatusServerLifecycleError::Bind {
                port: returned_port,
                source,
            } => {
                assert_eq!(*returned_port, port);
                // io::ErrorKind on bind contention is platform-dependent
                // (AddrInUse on most, PermissionDenied on Windows in some
                // cases); we just confirm an io::Error landed in `source`.
                let _ = source.kind();
            }
            other => panic!("expected StatusServerLifecycleError::Bind, got {other:?}"),
        }
        assert!(error.to_string().contains(&port.to_string()));
    }

    #[tokio::test]
    async fn test_spawned_status_server_shuts_down_cleanly() {
        let handle = spawn_status_server(0, create_test_state())
            .await
            .expect("status server should bind");
        handle.shutdown().await.expect("shutdown should succeed");
    }
}
