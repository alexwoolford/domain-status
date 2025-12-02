//! Batch flushing logic.

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;
use crate::storage::insert;

use super::BatchWriter;
use crate::storage::batch::types::{BatchRecord, FlushResult};

impl BatchWriter {
    /// Flushes all buffered records to the database
    ///
    /// Note: Each insert_url_record call starts its own transaction internally.
    /// We process records one-by-one, and if any record fails, we log and continue.
    /// This prevents one bad record from blocking the entire batch.
    ///
    /// **Future improvement**:** Use a single transaction for the entire batch
    /// for better atomicity and performance. This would require refactoring insert
    /// functions to accept either a pool or a transaction (e.g., using generics or
    /// a trait). Current approach works correctly but is suboptimal for large batches.
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
                &record.subject_alternative_names,
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

            // Insert enrichment data
            Self::insert_enrichment_data(&self.pool, url_status_id, record).await;
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

    /// Inserts all enrichment data for a record.
    async fn insert_enrichment_data(
        pool: &SqlitePool,
        url_status_id: i64,
        record: BatchRecord,
    ) {
        // Insert partial failures (DNS/TLS errors that didn't prevent processing)
        for mut partial_failure in record.partial_failures {
            partial_failure.url_status_id = url_status_id;
            if let Err(e) =
                insert::insert_url_partial_failure(pool, &partial_failure).await
            {
                log::warn!(
                    "Failed to insert partial failure for url_status_id {}: {}",
                    url_status_id,
                    e
                );
            }
        }

        // Insert GeoIP data if available
        if let Some((ip_address, geoip_result)) = &record.geoip {
            if let Err(e) =
                insert::insert_geoip_data(pool, url_status_id, ip_address, geoip_result)
                    .await
            {
                log::warn!("Failed to insert GeoIP data for {}: {}", ip_address, e);
            }
        }

        // Insert structured data if available
        if let Some(structured_data) = &record.structured_data {
            if let Err(e) =
                insert::insert_structured_data(pool, url_status_id, structured_data)
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
                pool,
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
                pool,
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
                insert::insert_whois_data(pool, url_status_id, whois_result).await
            {
                log::warn!(
                    "Failed to insert WHOIS data for url_status_id {}: {}",
                    url_status_id,
                    e
                );
            }
        }

        // Insert analytics IDs if available
        if !record.analytics_ids.is_empty() {
            if let Err(e) =
                insert::insert_analytics_ids(pool, url_status_id, &record.analytics_ids)
                    .await
            {
                log::warn!(
                    "Failed to insert analytics IDs for url_status_id {}: {}",
                    url_status_id,
                    e
                );
            }
        }
    }
}

