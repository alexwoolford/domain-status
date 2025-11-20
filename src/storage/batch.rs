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

use super::insert;
use super::models::UrlRecord;

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
            self.flush().await?;
        }

        Ok(())
    }

    /// Flushes all buffered records to the database
    pub async fn flush(&mut self) -> Result<(), DatabaseError> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let count = self.buffer.len();
        log::debug!("Flushing batch of {} records to database", count);

        // Process all records in the buffer
        for record in self.buffer.drain(..) {
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
                    continue;
                }
            };

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
        }

        self.last_flush = std::time::Instant::now();
        log::debug!("Successfully flushed {} records", count);
        Ok(())
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
pub fn start_batch_writer(
    pool: SqlitePool,
    config: BatchConfig,
) -> (
    mpsc::UnboundedSender<BatchRecord>,
    tokio::task::JoinHandle<Result<(), DatabaseError>>,
) {
    let (tx, mut rx) = mpsc::unbounded_channel();
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
                        if let Err(e) = writer.flush().await {
                            log::error!("Error during periodic flush: {}", e);
                        }
                    }
                }
            }
        }
    });

    (tx, handle)
}
