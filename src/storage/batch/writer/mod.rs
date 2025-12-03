//! Batch writer implementation.
//!
//! This module provides the BatchWriter struct and its methods for
//! collecting and flushing records to the database.

mod flush;

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;

use super::types::{BatchConfig, BatchRecord};

/// Batch writer that collects records and writes them in batches
pub struct BatchWriter {
    pool: SqlitePool,
    pub(crate) config: BatchConfig,
    pub(crate) buffer: Vec<BatchRecord>,
    last_flush: std::time::Instant,
}

impl BatchWriter {
    pub fn new(pool: SqlitePool, config: BatchConfig) -> Self {
        BatchWriter {
            pool,
            config,
            buffer: Vec::new(),
            last_flush: std::time::Instant::now(),
        }
    }

    /// Adds a record to the buffer and flushes if needed
    pub async fn add_record(&mut self, record: BatchRecord) -> Result<(), DatabaseError> {
        self.buffer.push(record);

        // Flush if buffer is full
        if self.buffer.len() >= self.config.batch_size {
            let _flush_result = self.flush().await?;
            // Note: We don't fail on flush errors here to prevent blocking the pipeline.
            // Failed records are logged and tracked in FlushResult for observability.
        }

        Ok(())
    }

    /// Checks if it's time to flush based on interval
    pub fn should_flush_by_time(&self) -> bool {
        self.last_flush.elapsed().as_secs() >= self.config.flush_interval_secs
    }
}
