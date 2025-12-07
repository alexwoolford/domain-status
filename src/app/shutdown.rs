//! Graceful shutdown handling.

use std::sync::Arc;
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;

/// Maximum time to wait for logging task to complete gracefully before aborting.
const SHUTDOWN_TIMEOUT_SECS: u64 = 2;

/// Shuts down all background tasks gracefully.
///
/// Handles cancellation of logging task and rate limiter.
/// Records are now written directly to the database (no batching), so no flush is needed.
///
/// The logging task is cancelled via `CancellationToken`, and if it doesn't complete
/// within `SHUTDOWN_TIMEOUT_SECS`, it is forcefully aborted using `JoinHandle::abort()`
/// as per AI_AGENTS.md requirements.
pub async fn shutdown_gracefully(
    cancel: CancellationToken,
    logging_task: Option<tokio::task::JoinHandle<()>>,
    rate_limiter_shutdown: Option<CancellationToken>,
) {
    // Signal logging task to stop
    cancel.cancel();

    // Try to await the logging task gracefully, but abort if it takes too long
    if let Some(logging_task) = logging_task {
        // Use tokio::sync::Mutex for async compatibility (avoids blocking the runtime)
        // Wrap the task in a mutex so we can extract it atomically in select! branches
        let task_handle = Arc::new(tokio::sync::Mutex::new(Some(logging_task)));

        // Wait up to SHUTDOWN_TIMEOUT_SECS for graceful shutdown
        let timeout_future = tokio::time::sleep(Duration::from_secs(SHUTDOWN_TIMEOUT_SECS));
        tokio::pin!(timeout_future);

        tokio::select! {
            result = async {
                // Extract task from mutex before awaiting (drop guard first)
                let task = {
                    let mut handle_guard = task_handle.lock().await;
                    handle_guard.take()
                };
                if let Some(task) = task {
                    task.await
                } else {
                    Ok(())
                }
            } => {
                // Task completed - handle result
                match result {
                    Ok(_) => {
                        // Task completed successfully
                    }
                    Err(e) => {
                        // Task panicked or was cancelled - log but continue
                        log::debug!("Logging task completed with error: {:?}", e);
                    }
                }
            }
            _ = timeout_future.as_mut() => {
                // Timeout - abort the task forcefully
                log::debug!(
                    "Logging task did not complete within {} seconds, aborting",
                    SHUTDOWN_TIMEOUT_SECS
                );
                // Extract task from mutex before aborting (drop guard first)
                // Note: tokio::select! ensures only one branch executes, so this is safe
                let task = {
                    let mut handle_guard = task_handle.lock().await;
                    handle_guard.take()
                };
                if let Some(task) = task {
                    task.abort();
                    // Try to await the aborted task to clean up
                    let _ = task.await;
                }
            }
        }
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

        // Should wait for task to complete gracefully
        shutdown_gracefully(cancel, Some(logging_task), None).await;
    }

    #[tokio::test]
    async fn test_shutdown_gracefully_with_stuck_task() {
        let cancel = CancellationToken::new();

        // Create a task that ignores cancellation (simulates a stuck task)
        let logging_task = tokio::spawn(async move {
            // This task will run forever, ignoring cancellation
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        // Should abort the task after timeout
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
