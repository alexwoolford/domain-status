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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_shutdown_gracefully_no_tasks() {
        let cancel = CancellationToken::new();
        // Should not panic when no tasks are provided
        shutdown_gracefully(cancel, None, None).await;
    }

    #[tokio::test]
    async fn test_shutdown_gracefully_with_logging_task() {
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        // Create a simple task that runs until cancelled
        let logging_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(10));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Task running
                    }
                    _ = cancel_clone.cancelled() => {
                        break;
                    }
                }
            }
        });

        // Should wait for task to complete
        shutdown_gracefully(cancel, Some(logging_task), None).await;
    }

    #[tokio::test]
    async fn test_shutdown_gracefully_with_rate_limiter() {
        let cancel = CancellationToken::new();
        let rate_limiter_shutdown = CancellationToken::new();

        // Should cancel rate limiter
        shutdown_gracefully(cancel, None, Some(rate_limiter_shutdown.clone())).await;

        // Verify rate limiter was cancelled
        assert!(rate_limiter_shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn test_shutdown_gracefully_with_all_tasks() {
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let rate_limiter_shutdown = CancellationToken::new();

        let logging_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(10));
            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = cancel_clone.cancelled() => {
                        break;
                    }
                }
            }
        });

        // Should handle both tasks
        shutdown_gracefully(
            cancel,
            Some(logging_task),
            Some(rate_limiter_shutdown.clone()),
        )
        .await;

        // Verify rate limiter was cancelled
        assert!(rate_limiter_shutdown.is_cancelled());
    }
}
