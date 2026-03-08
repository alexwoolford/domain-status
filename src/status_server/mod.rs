//! HTTP status server for monitoring long-running jobs.
//!
//! Provides three endpoints:
//! - `/health` - Liveness check (200 OK when server is up)
//! - `/metrics` - Prometheus-compatible metrics
//! - `/status` - JSON status endpoint with detailed progress information
//!
//! The server runs in the background and does not block URL processing.

mod handlers;
mod types;

use axum::routing::get;
use axum::Router;
use tokio_util::sync::CancellationToken;

use handlers::{health_handler, metrics_handler, status_handler};
pub use types::StatusState;

/// Managed background status server with explicit shutdown semantics.
#[derive(Debug)]
pub struct StatusServerHandle {
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
}

impl StatusServerHandle {
    /// Gracefully stop the status server and wait for the task to exit.
    pub async fn shutdown(self) -> Result<(), anyhow::Error> {
        self.shutdown.cancel();
        match self.task.await {
            Ok(result) => result,
            Err(join_error) => Err(anyhow::anyhow!(
                "Status server task failed to join: {}",
                join_error
            )),
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
) -> Result<StatusServerHandle, anyhow::Error> {
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind status server to port {}: {}", port, e))?;

    log::info!("Status server listening on http://127.0.0.1:{}/", port);
    log::info!("  - Health: http://127.0.0.1:{}/health", port);
    log::info!("  - Metrics: http://127.0.0.1:{}/metrics", port);
    log::info!("  - Status: http://127.0.0.1:{}/status", port);

    let shutdown = CancellationToken::new();
    let shutdown_signal = shutdown.clone();
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                shutdown_signal.cancelled().await;
            })
            .await
            .map_err(|e| anyhow::anyhow!("Status server error: {}", e))
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
            start_time: Arc::new(Instant::now()),
            error_stats: Arc::new(ProcessingStats::new()),
            timing_stats: None,
            request_limiter: None,
            db_circuit_breaker: Arc::new(
                crate::storage::circuit_breaker::DbWriteCircuitBreaker::default(),
            ),
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
        let message = error.to_string();
        assert!(message.contains("Failed to bind status server"));
        assert!(message.contains(&port.to_string()));
    }

    #[tokio::test]
    async fn test_spawned_status_server_shuts_down_cleanly() {
        let handle = spawn_status_server(0, create_test_state())
            .await
            .expect("status server should bind");
        handle.shutdown().await.expect("shutdown should succeed");
    }
}
