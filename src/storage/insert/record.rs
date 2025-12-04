//! Direct record insertion (non-batched).
//!
//! This module provides functions to insert BatchRecord data directly into the database
//! without batching. This is more efficient than batching for SQLite WAL mode.

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;
use crate::storage::BatchRecord;

use crate::storage::insert;

/// Inserts a batch record directly into the database.
///
/// This function inserts the main URL record and all enrichment data immediately,
/// without buffering or batching. With SQLite WAL mode, this provides better
/// performance than batching since writes can proceed concurrently.
pub async fn insert_batch_record(
    pool: &SqlitePool,
    record: BatchRecord,
) -> Result<(), DatabaseError> {
    // Use reference instead of clone for error message (domain is already owned in record)
    let domain = &record.url_record.initial_domain;

    // Insert main URL record
    let url_status_id = insert::insert_url_record(
        pool,
        &record.url_record,
        &record.security_headers,
        &record.http_headers,
        &record.oids,
        &record.redirect_chain,
        &record.technologies,
        &record.subject_alternative_names,
    )
    .await
    .map_err(|e| {
        log::error!(
            "Failed to insert URL record for domain '{}': {} (SQL: INSERT INTO url_status ...)",
            domain,
            e
        );
        e
    })?;

    // Insert enrichment data
    // Note: Enrichment data is inserted AFTER the main transaction commits.
    // This design choice ensures that:
    // 1. Main URL record is always saved (even if enrichment fails)
    // 2. Enrichment data failures don't prevent URL processing
    // 3. Partial enrichment data is better than no data at all
    //
    // Trade-off: If enrichment insertion fails, we have inconsistent state (main record exists
    // but enrichment data is missing). This is acceptable because enrichment data is optional
    // and failures are logged for monitoring.
    insert_enrichment_data(pool, url_status_id, record).await;

    Ok(())
}

/// Inserts all enrichment data for a record.
///
/// This function inserts enrichment data (GeoIP, WHOIS, structured data, etc.) after the main
/// URL record has been committed. Failures are logged but don't propagate, ensuring that
/// enrichment data failures don't prevent URL processing.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - The ID of the main URL record
/// * `record` - The batch record containing enrichment data
async fn insert_enrichment_data(pool: &SqlitePool, url_status_id: i64, record: BatchRecord) {
    // Insert partial failures (DNS/TLS errors that didn't prevent processing)
    for mut partial_failure in record.partial_failures {
        partial_failure.url_status_id = url_status_id;
        if let Err(e) = insert::insert_url_partial_failure(pool, &partial_failure).await {
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
            insert::insert_geoip_data(pool, url_status_id, ip_address, geoip_result).await
        {
            log::warn!(
                "Failed to insert GeoIP data for IP '{}' (url_status_id {}): {}",
                ip_address,
                url_status_id,
                e
            );
        }
    }

    // Insert structured data if available
    if let Some(structured_data) = &record.structured_data {
        if let Err(e) = insert::insert_structured_data(pool, url_status_id, structured_data).await {
            log::warn!(
                "Failed to insert structured data for url_status_id {}: {}",
                url_status_id,
                e
            );
        }
    }

    // Insert social media links if available
    if !record.social_media_links.is_empty() {
        if let Err(e) =
            insert::insert_social_media_links(pool, url_status_id, &record.social_media_links).await
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
        if let Err(e) =
            insert::insert_security_warnings(pool, url_status_id, &record.security_warnings).await
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
        if let Err(e) = insert::insert_whois_data(pool, url_status_id, whois_result).await {
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
            insert::insert_analytics_ids(pool, url_status_id, &record.analytics_ids).await
        {
            log::warn!(
                "Failed to insert analytics IDs for url_status_id {}: {}",
                url_status_id,
                e
            );
        }
    }
}
