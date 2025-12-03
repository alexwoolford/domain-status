//! Batched database write operations.
//!
//! This module implements a high-performance batch writer that:
//! - Collects records in memory batches
//! - Writes batches to the database efficiently
//! - Provides backpressure via bounded channels
//! - Handles graceful shutdown
//!
//! The batch writer runs in a separate task and receives records via an MPSC channel.

mod types;
mod writer;

pub use types::{BatchConfig, BatchRecord};
pub use writer::BatchWriter;

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use log;
use sqlx::SqlitePool;
use tokio::sync::mpsc;
use tokio::time::interval;

use crate::error_handling::DatabaseError;

/// Starts the batch writer task that processes records from a channel
///
/// Returns a sender that can be used to send records for batching,
/// and a handle that can be used to flush and shutdown the writer.
///
/// Uses a bounded channel to prevent memory exhaustion if the writer
/// can't keep up with producers. The channel size is configurable.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `config` - Batch writer configuration
/// * `batch_write_successes` - Optional counter for successful batch writes (for monitoring)
/// * `batch_write_failures` - Optional counter for failed batch writes (for monitoring)
pub fn start_batch_writer(
    pool: SqlitePool,
    config: BatchConfig,
    batch_write_successes: Option<Arc<AtomicUsize>>,
    batch_write_failures: Option<Arc<AtomicUsize>>,
) -> (
    mpsc::Sender<BatchRecord>,
    tokio::task::JoinHandle<Result<(), DatabaseError>>,
) {
    // Use bounded channel to prevent unbounded memory growth
    // Buffer size: 10x batch_size to allow reasonable buffering
    // This provides backpressure: if channel is full, send() will await
    let channel_size = config.batch_size * crate::config::CHANNEL_SIZE_MULTIPLIER;
    let (tx, mut rx) = mpsc::channel(channel_size);
    let mut writer = BatchWriter::new(pool, config);
    let flush_interval = Duration::from_secs(writer.config.flush_interval_secs);

    let handle = tokio::spawn(async move {
        let mut interval_timer = interval(flush_interval);

        loop {
            tokio::select! {
                // Receive a record from the channel
                record = rx.recv() => {
                    match record {
                        Some(record) => {
                            if let Err(e) = writer.add_record(record).await {
                                log::error!("Error adding record to batch: {}", e);
                                // Note: add_record errors are channel/configuration errors,
                                // not individual record insertion failures. Individual failures
                                // are tracked in flush() results.
                            }
                        }
                        None => {
                            // Channel closed, flush remaining records and exit
                            log::info!("Batch writer channel closed, flushing remaining records...");
                            match writer.flush().await {
                                Ok(result) => {
                                    // Update batch write counters if provided
                                    if let Some(ref successes) = batch_write_successes {
                                        successes.fetch_add(result.successful, Ordering::SeqCst);
                                    }
                                    if let Some(ref failures) = batch_write_failures {
                                        failures.fetch_add(result.failed, Ordering::SeqCst);
                                    }
                                    if result.failed > 0 {
                                        log::warn!(
                                            "Final flush: {} successful, {} failed",
                                            result.successful,
                                            result.failed
                                        );
                                    }
                                }
                                Err(e) => {
                                    log::error!("Error flushing final batch: {}", e);
                                    return Err(e);
                                }
                            }
                            log::info!("Batch writer shutdown complete");
                            return Ok(());
                        }
                    }
                }
                // Periodic flush based on time interval
                _ = interval_timer.tick() => {
                    if writer.should_flush_by_time() && !writer.buffer.is_empty() {
                        match writer.flush().await {
                            Ok(result) => {
                                // Update batch write counters if provided
                                if let Some(ref successes) = batch_write_successes {
                                    successes.fetch_add(result.successful, Ordering::SeqCst);
                                }
                                if let Some(ref failures) = batch_write_failures {
                                    failures.fetch_add(result.failed, Ordering::SeqCst);
                                }
                                if result.failed > 0 {
                                    log::warn!(
                                        "Periodic flush: {} successful, {} failed",
                                        result.successful,
                                        result.failed
                                    );
                                }
                            }
                            Err(e) => {
                                log::error!("Error during periodic flush: {}", e);
                            }
                        }
                    }
                }
            }
        }
    });

    (tx, handle)
}
