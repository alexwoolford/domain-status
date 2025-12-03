//! Graceful shutdown handling.

use tokio_util::sync::CancellationToken;

/// Shuts down all background tasks gracefully.
///
/// Handles cancellation of logging task and rate limiter.
/// Records are now written directly to the database (no batching), so no flush is needed.
pub async fn shutdown_gracefully(
    cancel: CancellationToken,
    logging_task: Option<tokio::task::JoinHandle<()>>,
    rate_limiter_shutdown: Option<CancellationToken>,
) {
    // Signal logging task to stop and await it
    cancel.cancel();
    if let Some(logging_task) = logging_task {
        let _ = logging_task.await;
    }

    // Signal rate limiter to stop if it exists
    if let Some(shutdown) = rate_limiter_shutdown {
        shutdown.cancel();
    }
}
