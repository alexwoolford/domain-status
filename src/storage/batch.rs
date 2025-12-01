// storage/batch.rs
// Batched database write operations

use std::collections::HashMap;
use std::collections::HashSet;
use std::time::Duration;

use log;
use sqlx::SqlitePool;
use tokio::sync::mpsc;
use tokio::time::interval;

use crate::error_handling::DatabaseError;
use crate::geoip::GeoIpResult;
use crate::parse::{SocialMediaLink, StructuredData};
use crate::security::SecurityWarning;
use crate::whois::WhoisResult;

use super::insert;
use super::models::{UrlPartialFailureRecord, UrlRecord};

/// Configuration for batch writing
pub struct BatchConfig {
    /// Maximum number of records to batch before flushing
    pub batch_size: usize,
    /// Interval between automatic flushes (in seconds)
    pub flush_interval_secs: u64,
}

impl Default for BatchConfig {
    fn default() -> Self {
        BatchConfig {
            batch_size: 100,
            flush_interval_secs: 5,
        }
    }
}

/// Result of a batch flush operation.
///
/// Provides visibility into how many records were successfully inserted
/// and how many failed, enabling better observability and monitoring.
#[derive(Debug, Clone)]
pub struct FlushResult {
    /// Total number of records in the batch
    pub total: usize,
    /// Number of records successfully inserted
    pub successful: usize,
    /// Number of records that failed to insert
    pub failed: usize,
}

/// A complete record ready for batched insertion
pub struct BatchRecord {
    pub url_record: UrlRecord,
    pub security_headers: HashMap<String, String>,
    pub http_headers: HashMap<String, String>,
    pub oids: HashSet<String>,
    pub redirect_chain: Vec<String>,
    pub technologies: Vec<String>,
    pub geoip: Option<(String, GeoIpResult)>, // (ip_address, geoip_result)
    pub structured_data: Option<StructuredData>,
    pub social_media_links: Vec<SocialMediaLink>,
    pub security_warnings: Vec<SecurityWarning>,
    pub whois: Option<WhoisResult>,
    pub partial_failures: Vec<UrlPartialFailureRecord>, // DNS/TLS errors that didn't prevent processing
}

/// Batch writer that collects records and writes them in batches
pub struct BatchWriter {
    pool: SqlitePool,
    config: BatchConfig,
    buffer: Vec<BatchRecord>,
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

    /// Flushes all buffered records to the database
    ///
    /// Note: Each insert_url_record call starts its own transaction internally.
    /// We process records one-by-one, and if any record fails, we log and continue.
    /// This prevents one bad record from blocking the entire batch.
    /// TODO: Consider refactoring to use a single transaction for the entire batch
    /// for better atomicity, but this would require refactoring insert functions
    /// to accept a transaction instead of a pool.
    ///
    /// Returns a summary of successful and failed inserts for observability.
    pub async fn flush(&mut self) -> Result<FlushResult, DatabaseError> {
        if self.buffer.is_empty() {
            return Ok(FlushResult {
                total: 0,
                successful: 0,
                failed: 0,
            });
        }

        let count = self.buffer.len();
        log::debug!("Flushing batch of {} records to database", count);

        // Collect all records to process
        let records: Vec<BatchRecord> = self.buffer.drain(..).collect();

        let mut successful = 0;
        let mut failed = 0;

        // Process all records
        for record in records {
            // Insert main URL record
            let url_status_id = match insert::insert_url_record(
                &self.pool,
                &record.url_record,
                &record.security_headers,
                &record.http_headers,
                &record.oids,
                &record.redirect_chain,
                &record.technologies,
            )
            .await
            {
                Ok(id) => id,
                Err(e) => {
                    log::error!(
                        "Failed to insert URL record for {}: {}",
                        record.url_record.initial_domain,
                        e
                    );
                    failed += 1;
                    continue;
                }
            };

            successful += 1;

            // Insert partial failures (DNS/TLS errors that didn't prevent processing)
            for mut partial_failure in record.partial_failures {
                partial_failure.url_status_id = url_status_id;
                if let Err(e) =
                    insert::insert_url_partial_failure(&self.pool, &partial_failure).await
                {
                    log::warn!(
                        "Failed to insert partial failure for url_status_id {}: {}",
                        url_status_id,
                        e
                    );
                }
            }

            // Insert GeoIP data if available
            if let Some((ip_address, geoip_result)) = record.geoip {
                if let Err(e) =
                    insert::insert_geoip_data(&self.pool, url_status_id, &ip_address, &geoip_result)
                        .await
                {
                    log::warn!("Failed to insert GeoIP data for {}: {}", ip_address, e);
                }
            }

            // Insert structured data if available
            if let Some(structured_data) = record.structured_data {
                if let Err(e) =
                    insert::insert_structured_data(&self.pool, url_status_id, &structured_data)
                        .await
                {
                    log::warn!(
                        "Failed to insert structured data for url_status_id {}: {}",
                        url_status_id,
                        e
                    );
                }
            }

            // Insert social media links if available
            if !record.social_media_links.is_empty() {
                if let Err(e) = insert::insert_social_media_links(
                    &self.pool,
                    url_status_id,
                    &record.social_media_links,
                )
                .await
                {
                    log::warn!(
                        "Failed to insert social media links for url_status_id {}: {}",
                        url_status_id,
                        e
                    );
                }
            }

            // Insert security warnings if available
            if !record.security_warnings.is_empty() {
                if let Err(e) = insert::insert_security_warnings(
                    &self.pool,
                    url_status_id,
                    &record.security_warnings,
                )
                .await
                {
                    log::warn!(
                        "Failed to insert security warnings for url_status_id {}: {}",
                        url_status_id,
                        e
                    );
                }
            }

            // Insert WHOIS data if available
            if let Some(ref whois_result) = record.whois {
                if let Err(e) =
                    insert::insert_whois_data(&self.pool, url_status_id, whois_result).await
                {
                    log::warn!(
                        "Failed to insert WHOIS data for url_status_id {}: {}",
                        url_status_id,
                        e
                    );
                }
            }
        }

        self.last_flush = std::time::Instant::now();

        let result = FlushResult {
            total: count,
            successful,
            failed,
        };

        if failed > 0 {
            log::warn!(
                "Flush completed: {} successful, {} failed out of {} total",
                result.successful,
                result.failed,
                result.total
            );
        } else {
            log::debug!(
                "Successfully flushed {} records ({} total)",
                result.successful,
                result.total
            );
        }

        Ok(result)
    }

    /// Checks if it's time to flush based on interval
    pub fn should_flush_by_time(&self) -> bool {
        self.last_flush.elapsed().as_secs() >= self.config.flush_interval_secs
    }
}

/// Starts the batch writer task that processes records from a channel
///
/// Returns a sender that can be used to send records for batching,
/// and a handle that can be used to flush and shutdown the writer.
///
/// Uses a bounded channel to prevent memory exhaustion if the writer
/// can't keep up with producers. The channel size is configurable.
pub fn start_batch_writer(
    pool: SqlitePool,
    config: BatchConfig,
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
                            }
                        }
                        None => {
                            // Channel closed, flush remaining records and exit
                            log::info!("Batch writer channel closed, flushing remaining records...");
                            if let Err(e) = writer.flush().await {
                                log::error!("Error flushing final batch: {}", e);
                                return Err(e);
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
