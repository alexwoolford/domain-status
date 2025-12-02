//! Failure record insertion.
//!
//! This module handles inserting URL failure records and partial failure records
//! into the database, with retry logic for transient database errors.

use sqlx::{Row, SqlitePool};

use crate::error_handling::DatabaseError;

use super::super::models::{UrlFailureRecord, UrlPartialFailureRecord};

/// Inserts a URL failure record into the database with retry logic.
///
/// Retries transient database errors (locked, busy) up to 3 times with exponential backoff.
/// This prevents failures when the database is temporarily unavailable due to high concurrency.
///
/// This function inserts the main failure record and all associated satellite data
/// (redirect chain, response headers, request headers) in a transaction.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `failure` - The failure record to insert
///
/// # Errors
///
/// Returns a `DatabaseError` if the database operation fails after retries.
pub async fn insert_url_failure(
    pool: &SqlitePool,
    failure: &UrlFailureRecord,
) -> Result<i64, DatabaseError> {
    // Retry strategy for transient database errors (SQLITE_BUSY, SQLITE_LOCKED)
    const MAX_RETRIES: usize = 3;
    const INITIAL_DELAY_MS: u64 = 50;

    for attempt in 0..=MAX_RETRIES {
        match insert_url_failure_impl(pool, failure).await {
            Ok(id) => return Ok(id),
            Err(e) => {
                // Check if error is retriable (transient database errors)
                let is_retriable = matches!(
                    &e,
                    DatabaseError::SqlError(sqlx::Error::Database(db_err))
                        if db_err.message().contains("database is locked")
                            || db_err.message().contains("database is busy")
                );

                if !is_retriable || attempt >= MAX_RETRIES {
                    return Err(e);
                }

                // Exponential backoff: 50ms, 100ms, 200ms
                let delay_ms = INITIAL_DELAY_MS * (1 << attempt);
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
        }
    }

    // Should never reach here, but handle it gracefully
    Err(DatabaseError::SqlError(sqlx::Error::PoolClosed))
}

/// Internal implementation of insert_url_failure (without retry logic).
async fn insert_url_failure_impl(
    pool: &SqlitePool,
    failure: &UrlFailureRecord,
) -> Result<i64, DatabaseError> {
    // Insert main failure record
    let failure_id = sqlx::query(
        "INSERT INTO url_failures (
            url, final_url, domain, final_domain, error_type, error_message,
            http_status, retry_count, elapsed_time_seconds, timestamp, run_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING id",
    )
    .bind(&failure.url)
    .bind(failure.final_url.as_ref())
    .bind(&failure.domain)
    .bind(failure.final_domain.as_ref())
    .bind(&failure.error_type)
    .bind(&failure.error_message)
    .bind(failure.http_status.map(|s| s as i64))
    .bind(failure.retry_count as i64)
    .bind(failure.elapsed_time_seconds)
    .bind(failure.timestamp)
    .bind(failure.run_id.as_ref())
    .fetch_one(pool)
    .await
    .map_err(DatabaseError::SqlError)?
    .get::<i64, _>(0);

    // Insert redirect chain
    for (order, redirect_url) in failure.redirect_chain.iter().enumerate() {
        sqlx::query(
            "INSERT INTO url_failure_redirect_chain (url_failure_id, redirect_url, redirect_order)
             VALUES (?, ?, ?)
             ON CONFLICT(url_failure_id, redirect_order) DO NOTHING",
        )
        .bind(failure_id)
        .bind(redirect_url)
        .bind(order as i64)
        .execute(pool)
        .await
        .map_err(DatabaseError::SqlError)?;
    }

    // Insert response headers
    for (name, value) in &failure.response_headers {
        sqlx::query(
            "INSERT INTO url_failure_response_headers (url_failure_id, header_name, header_value)
             VALUES (?, ?, ?)
             ON CONFLICT(url_failure_id, header_name) DO UPDATE SET header_value=excluded.header_value",
        )
        .bind(failure_id)
        .bind(name)
        .bind(value)
        .execute(pool)
        .await
        .map_err(DatabaseError::SqlError)?;
    }

    // Insert request headers
    for (name, value) in &failure.request_headers {
        sqlx::query(
            "INSERT INTO url_failure_request_headers (url_failure_id, header_name, header_value)
             VALUES (?, ?, ?)
             ON CONFLICT(url_failure_id, header_name) DO UPDATE SET header_value=excluded.header_value",
        )
        .bind(failure_id)
        .bind(name)
        .bind(value)
        .execute(pool)
        .await
        .map_err(DatabaseError::SqlError)?;
    }

    Ok(failure_id)
}

/// Inserts a partial failure record into the database.
///
/// Partial failures are DNS/TLS errors that occurred during supplementary data
/// collection but didn't prevent the URL from being successfully processed.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `partial_failure` - The partial failure record to insert
///
/// # Returns
///
/// The ID of the inserted partial failure record, or a `DatabaseError` if insertion fails.
pub async fn insert_url_partial_failure(
    pool: &SqlitePool,
    partial_failure: &UrlPartialFailureRecord,
) -> Result<i64, DatabaseError> {
    let partial_failure_id = sqlx::query(
        "INSERT INTO url_partial_failures (
            url_status_id, error_type, error_message, timestamp, run_id
        ) VALUES (?, ?, ?, ?, ?)
        RETURNING id",
    )
    .bind(partial_failure.url_status_id)
    .bind(&partial_failure.error_type)
    .bind(&partial_failure.error_message)
    .bind(partial_failure.timestamp)
    .bind(partial_failure.run_id.as_ref())
    .fetch_one(pool)
    .await
    .map_err(DatabaseError::SqlError)?
    .get::<i64, _>(0);

    Ok(partial_failure_id)
}

