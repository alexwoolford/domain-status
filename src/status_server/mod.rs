//! HTTP status server for monitoring long-running jobs.
//!
//! Provides two endpoints:
//! - `/metrics` - Prometheus-compatible metrics
//! - `/status` - JSON status endpoint with detailed progress information
//!
//! The server runs in the background and does not block URL processing.

mod handlers;
mod types;

use axum::routing::get;
use axum::Router;

use handlers::{metrics_handler, status_handler};
pub use types::StatusState;

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
