//! Batch record queuing for database insertion.

use crate::storage::BatchRecord;

/// Queues a batch record for database insertion.
///
/// Handles backpressure and graceful shutdown scenarios.
pub async fn queue_batch_record(
    batch_record: BatchRecord,
    batch_sender: &Option<tokio::sync::mpsc::Sender<BatchRecord>>,
    final_url: &str,
) {
    if let Some(ref sender) = batch_sender {
        match sender.try_send(batch_record) {
            Ok(()) => {
                log::debug!("Record queued for batch insert for URL: {}", final_url);
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(record)) => {
                // Channel is full, use async send which will await
                // This provides backpressure: if DB writes are slow, producers will wait
                match sender.send(record).await {
                    Ok(()) => {
                        log::debug!("Record queued for batch insert for URL: {}", final_url);
                    }
                    Err(_) => {
                        // Channel closed during send - batch writer is shutting down
                        log::warn!(
                            "Failed to queue record for URL {}: channel closed (batch writer shutting down)",
                            final_url
                        );
                        // Don't fail the entire URL processing - just log and continue
                    }
                }
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                // Channel already closed - batch writer is shutting down
                log::warn!(
                    "Failed to queue record for URL {}: channel closed (batch writer shutting down)",
                    final_url
                );
            }
        }
    } else {
        log::warn!(
            "Batch writer not available, record for {} will not be saved",
            final_url
        );
    }
}
