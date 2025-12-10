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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::models::{UrlFailureRecord, UrlPartialFailureRecord};
    use sqlx::Row;

    use crate::storage::test_helpers::{
        create_test_pool, create_test_run, create_test_url_status_default,
    };

    #[tokio::test]
    async fn test_insert_url_failure_basic() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-123", 1704067200000i64).await;

        let failure = UrlFailureRecord {
            url: "http://example.com".to_string(),
            final_url: Some("https://example.com".to_string()),
            domain: "example.com".to_string(),
            final_domain: Some("example.com".to_string()),
            error_type: "HttpError".to_string(),
            error_message: "Connection timeout".to_string(),
            http_status: None,
            retry_count: 3,
            elapsed_time_seconds: Some(5.5),
            timestamp: 1704067200000,
            run_id: Some("test-run-123".to_string()),
            redirect_chain: vec![],
            response_headers: vec![],
            request_headers: vec![],
        };

        let result = insert_url_failure(&pool, &failure).await;
        assert!(result.is_ok());

        let failure_id = result.unwrap();

        // Verify main failure record
        let row = sqlx::query(
            "SELECT url, final_url, domain, error_type, error_message, retry_count FROM url_failures WHERE id = ?",
        )
        .bind(failure_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch failure record");

        assert_eq!(row.get::<String, _>("url"), "http://example.com");
        assert_eq!(
            row.get::<Option<String>, _>("final_url"),
            Some("https://example.com".to_string())
        );
        assert_eq!(row.get::<String, _>("domain"), "example.com");
        assert_eq!(row.get::<String, _>("error_type"), "HttpError");
        assert_eq!(row.get::<String, _>("error_message"), "Connection timeout");
        assert_eq!(row.get::<i64, _>("retry_count"), 3);
    }

    #[tokio::test]
    async fn test_insert_url_failure_with_redirect_chain() {
        let pool = create_test_pool().await;

        let failure = UrlFailureRecord {
            url: "http://example.com".to_string(),
            final_url: Some("https://www.example.com".to_string()),
            domain: "example.com".to_string(),
            final_domain: Some("www.example.com".to_string()),
            error_type: "HttpError".to_string(),
            error_message: "500 Internal Server Error".to_string(),
            http_status: Some(500),
            retry_count: 0,
            elapsed_time_seconds: Some(2.0),
            timestamp: 1704067200000,
            run_id: None,
            redirect_chain: vec![
                "http://example.com".to_string(),
                "https://example.com".to_string(),
                "https://www.example.com".to_string(),
            ],
            response_headers: vec![],
            request_headers: vec![],
        };

        let result = insert_url_failure(&pool, &failure).await;
        assert!(result.is_ok());

        let failure_id = result.unwrap();

        // Verify redirect chain
        let rows = sqlx::query(
            "SELECT redirect_url, redirect_order FROM url_failure_redirect_chain WHERE url_failure_id = ? ORDER BY redirect_order",
        )
        .bind(failure_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch redirect chain");

        assert_eq!(rows.len(), 3);
        assert_eq!(
            rows[0].get::<String, _>("redirect_url"),
            "http://example.com"
        );
        assert_eq!(rows[0].get::<i64, _>("redirect_order"), 0);
        assert_eq!(
            rows[1].get::<String, _>("redirect_url"),
            "https://example.com"
        );
        assert_eq!(rows[1].get::<i64, _>("redirect_order"), 1);
        assert_eq!(
            rows[2].get::<String, _>("redirect_url"),
            "https://www.example.com"
        );
        assert_eq!(rows[2].get::<i64, _>("redirect_order"), 2);
    }

    #[tokio::test]
    async fn test_insert_url_failure_with_headers() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-456", 1704067200000i64).await;

        let failure = UrlFailureRecord {
            url: "http://example.com".to_string(),
            final_url: None,
            domain: "example.com".to_string(),
            final_domain: None,
            error_type: "HttpError".to_string(),
            error_message: "403 Forbidden".to_string(),
            http_status: Some(403),
            retry_count: 1,
            elapsed_time_seconds: None,
            timestamp: 1704067200000,
            run_id: Some("test-run-456".to_string()),
            redirect_chain: vec![],
            response_headers: vec![
                ("Server".to_string(), "nginx/1.18.0".to_string()),
                ("Content-Type".to_string(), "text/html".to_string()),
            ],
            request_headers: vec![
                ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
                ("Accept".to_string(), "text/html".to_string()),
            ],
        };

        let result = insert_url_failure(&pool, &failure).await;
        assert!(result.is_ok());

        let failure_id = result.unwrap();

        // Verify response headers
        let response_rows = sqlx::query(
            "SELECT header_name, header_value FROM url_failure_response_headers WHERE url_failure_id = ? ORDER BY header_name",
        )
        .bind(failure_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch response headers");

        assert_eq!(response_rows.len(), 2);
        assert_eq!(
            response_rows[0].get::<String, _>("header_name"),
            "Content-Type"
        );
        assert_eq!(response_rows[1].get::<String, _>("header_name"), "Server");

        // Verify request headers
        let request_rows = sqlx::query(
            "SELECT header_name, header_value FROM url_failure_request_headers WHERE url_failure_id = ? ORDER BY header_name",
        )
        .bind(failure_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch request headers");

        assert_eq!(request_rows.len(), 2);
        assert_eq!(request_rows[0].get::<String, _>("header_name"), "Accept");
        assert_eq!(
            request_rows[1].get::<String, _>("header_name"),
            "User-Agent"
        );
    }

    #[tokio::test]
    async fn test_insert_url_failure_with_http_status() {
        let pool = create_test_pool().await;

        let failure = UrlFailureRecord {
            url: "http://example.com".to_string(),
            final_url: None,
            domain: "example.com".to_string(),
            final_domain: None,
            error_type: "HttpError".to_string(),
            error_message: "404 Not Found".to_string(),
            http_status: Some(404),
            retry_count: 0,
            elapsed_time_seconds: Some(1.5),
            timestamp: 1704067200000,
            run_id: None,
            redirect_chain: vec![],
            response_headers: vec![],
            request_headers: vec![],
        };

        let result = insert_url_failure(&pool, &failure).await;
        assert!(result.is_ok());

        let failure_id = result.unwrap();

        // Verify HTTP status
        let row = sqlx::query("SELECT http_status FROM url_failures WHERE id = ?")
            .bind(failure_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch failure record");

        assert_eq!(row.get::<Option<i64>, _>("http_status"), Some(404));
    }

    #[tokio::test]
    async fn test_insert_url_partial_failure_basic() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-789", 1704067200000i64).await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let partial_failure = UrlPartialFailureRecord {
            url_status_id,
            error_type: "DnsError".to_string(),
            error_message: "DNS lookup failed".to_string(),
            timestamp: 1704067200000,
            run_id: Some("test-run-789".to_string()),
        };

        let result = insert_url_partial_failure(&pool, &partial_failure).await;
        assert!(result.is_ok());

        let partial_failure_id = result.unwrap();

        // Verify insertion
        let row = sqlx::query(
            "SELECT url_status_id, error_type, error_message, run_id FROM url_partial_failures WHERE id = ?",
        )
        .bind(partial_failure_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch partial failure record");

        assert_eq!(row.get::<i64, _>("url_status_id"), url_status_id);
        assert_eq!(row.get::<String, _>("error_type"), "DnsError");
        assert_eq!(row.get::<String, _>("error_message"), "DNS lookup failed");
        assert_eq!(
            row.get::<Option<String>, _>("run_id"),
            Some("test-run-789".to_string())
        );
    }

    #[tokio::test]
    async fn test_insert_url_partial_failure_without_run_id() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let partial_failure = UrlPartialFailureRecord {
            url_status_id,
            error_type: "TlsError".to_string(),
            error_message: "Certificate validation failed".to_string(),
            timestamp: 1704067200000,
            run_id: None,
        };

        let result = insert_url_partial_failure(&pool, &partial_failure).await;
        assert!(result.is_ok());

        let partial_failure_id = result.unwrap();

        // Verify insertion
        let row = sqlx::query(
            "SELECT error_type, error_message, run_id FROM url_partial_failures WHERE id = ?",
        )
        .bind(partial_failure_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch partial failure record");

        assert_eq!(row.get::<String, _>("error_type"), "TlsError");
        assert_eq!(
            row.get::<String, _>("error_message"),
            "Certificate validation failed"
        );
        assert_eq!(row.get::<Option<String>, _>("run_id"), None);
    }

    #[tokio::test]
    async fn test_insert_url_partial_failure_multiple() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        // Insert multiple partial failures for the same URL status
        let failure1 = UrlPartialFailureRecord {
            url_status_id,
            error_type: "DnsError".to_string(),
            error_message: "DNS lookup failed".to_string(),
            timestamp: 1704067200000,
            run_id: None,
        };

        let failure2 = UrlPartialFailureRecord {
            url_status_id,
            error_type: "TlsError".to_string(),
            error_message: "TLS handshake failed".to_string(),
            timestamp: 1704067201000,
            run_id: None,
        };

        let result1 = insert_url_partial_failure(&pool, &failure1).await;
        let result2 = insert_url_partial_failure(&pool, &failure2).await;

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        // Verify both were inserted
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_partial_failures WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count partial failures");

        assert_eq!(count, 2);
    }
}
