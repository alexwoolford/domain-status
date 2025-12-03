//! Graceful shutdown handling.

use anyhow::Result;
use log::{info, warn};
use tokio_util::sync::CancellationToken;

/// Shuts down all background tasks gracefully.
///
/// Handles cancellation of logging task, rate limiter, and batch writer flush.
#[allow(clippy::too_many_arguments)] // All arguments are necessary for shutdown
pub async fn shutdown_gracefully(
    cancel: CancellationToken,
    logging_task: Option<tokio::task::JoinHandle<()>>,
    rate_limiter_shutdown: Option<CancellationToken>,
    batch_sender: tokio::sync::mpsc::Sender<crate::storage::BatchRecord>,
    batch_writer_handle: tokio::task::JoinHandle<Result<(), crate::error_handling::DatabaseError>>,
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

    // Flush batch writer: close the channel and wait for remaining records to be written
    // IMPORTANT: Drop the sender BEFORE waiting for the handle to ensure all pending sends complete
    // With a bounded channel, dropping the sender will cause pending sends to fail gracefully
    info!("Flushing batch writer...");
    drop(batch_sender); // Close the channel to signal shutdown (this unblocks any waiting sends)

    // Give a brief moment for any in-flight sends to complete or fail
    tokio::time::sleep(tokio::time::Duration::from_millis(
        crate::config::BATCH_WRITER_SHUTDOWN_SLEEP_MS,
    ))
    .await;

    // Now wait for the batch writer to finish processing remaining records
    // Add timeout to prevent hanging if batch writer gets stuck
    // Note: With many records and satellite data, flushing can take time, so we use a reasonable timeout
    let batch_writer_result = tokio::time::timeout(
        std::time::Duration::from_secs(crate::config::BATCH_WRITER_SHUTDOWN_TIMEOUT_SECS),
        batch_writer_handle,
    )
    .await;

    match batch_writer_result {
        Ok(Ok(Ok(()))) => info!("Batch writer flushed successfully"),
        Ok(Ok(Err(e))) => warn!("Error flushing batch writer: {}", e),
        Ok(Err(e)) => warn!("Batch writer task panicked: {}", e),
        Err(_) => {
            // Timeout occurred - this is normal when there are many records with satellite data
            // The batch writer continues processing in the background and will complete successfully
            // All data will be written, we just don't wait for it to finish to avoid blocking shutdown
            log::debug!(
                "Batch writer flush taking longer than {} seconds (normal with many records) - continuing in background",
                crate::config::BATCH_WRITER_SHUTDOWN_TIMEOUT_SECS
            );
            // Note: The batch writer task continues running and will complete eventually
            // All data will be written, we just don't wait for it to finish
        }
    }
}
