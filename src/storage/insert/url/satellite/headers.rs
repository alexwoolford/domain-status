//! HTTP header insertion (security headers, HTTP headers) for satellite tables.

use sqlx::Sqlite;
use sqlx::Transaction;

use super::super::super::utils::build_batch_insert_query;

/// Inserts security headers into url_security_headers table using batch insert.
pub(crate) async fn insert_security_headers(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    security_headers: &std::collections::HashMap<String, String>,
) {
    if security_headers.is_empty() {
        return;
    }

    // Convert HashMap to Vec for consistent ordering
    let headers: Vec<(&String, &String)> = security_headers.iter().collect();

    // Batch insert: build VALUES clause for all security headers
    let query = build_batch_insert_query(
        "url_security_headers",
        &["url_status_id", "header_name", "header_value"],
        headers.len(),
        Some("ON CONFLICT(url_status_id, header_name) DO UPDATE SET header_value=excluded.header_value"),
    );

    let mut query_builder = sqlx::query(&query);
    for (header_name, header_value) in &headers {
        query_builder = query_builder
            .bind(url_status_id)
            .bind(*header_name)
            .bind(*header_value);
    }

    if let Err(e) = query_builder.execute(&mut **tx).await {
        log::warn!(
            "Failed to batch insert {} security headers for url_status_id {}: {}",
            headers.len(),
            url_status_id,
            e
        );
    }
}

/// Inserts HTTP headers into url_http_headers table using batch insert.
pub(crate) async fn insert_http_headers(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    http_headers: &std::collections::HashMap<String, String>,
) {
    if http_headers.is_empty() {
        return;
    }

    // Convert HashMap to Vec for consistent ordering
    let headers: Vec<(&String, &String)> = http_headers.iter().collect();

    // Batch insert: build VALUES clause for all HTTP headers
    let query = build_batch_insert_query(
        "url_http_headers",
        &["url_status_id", "header_name", "header_value"],
        headers.len(),
        Some("ON CONFLICT(url_status_id, header_name) DO UPDATE SET header_value=excluded.header_value"),
    );

    let mut query_builder = sqlx::query(&query);
    for (header_name, header_value) in &headers {
        query_builder = query_builder
            .bind(url_status_id)
            .bind(*header_name)
            .bind(*header_value);
    }

    if let Err(e) = query_builder.execute(&mut **tx).await {
        log::warn!(
            "Failed to batch insert {} HTTP headers for url_status_id {}: {}",
            headers.len(),
            url_status_id,
            e
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::migrations::run_migrations;
    use sqlx::{Row, SqlitePool};
    use std::collections::HashMap;

    async fn create_test_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");
        pool
    }

    async fn create_test_url_status(pool: &SqlitePool) -> i64 {
        sqlx::query(
            "INSERT INTO url_status (domain, final_domain, ip_address, status, status_description, response_time, title, timestamp, is_mobile_friendly) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind("example.com")
        .bind("example.com")
        .bind("93.184.216.34")
        .bind(200i64)
        .bind("OK")
        .bind(0.123f64)
        .bind("Test Page")
        .bind(1704067200000i64)
        .bind(true)
        .fetch_one(pool)
        .await
        .expect("Failed to insert test URL status")
        .get::<i64, _>(0)
    }

    #[tokio::test]
    async fn test_insert_security_headers_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let mut security_headers = HashMap::new();
        security_headers.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=31536000".to_string(),
        );
        security_headers.insert(
            "Content-Security-Policy".to_string(),
            "default-src 'self'".to_string(),
        );

        insert_security_headers(&mut tx, url_status_id, &security_headers).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify insertion
        let rows = sqlx::query(
            "SELECT header_name, header_value FROM url_security_headers WHERE url_status_id = ? ORDER BY header_name",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch security headers");

        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].get::<String, _>("header_name"),
            "Content-Security-Policy"
        );
        assert_eq!(
            rows[1].get::<String, _>("header_name"),
            "Strict-Transport-Security"
        );
    }

    #[tokio::test]
    async fn test_insert_security_headers_upsert() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx1 = pool.begin().await.expect("Failed to start transaction");
        let mut security_headers1 = HashMap::new();
        security_headers1.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=31536000".to_string(),
        );
        insert_security_headers(&mut tx1, url_status_id, &security_headers1).await;
        tx1.commit().await.expect("Failed to commit transaction");

        // Insert again with updated value
        let mut tx2 = pool.begin().await.expect("Failed to start transaction");
        let mut security_headers2 = HashMap::new();
        security_headers2.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=63072000".to_string(),
        );
        insert_security_headers(&mut tx2, url_status_id, &security_headers2).await;
        tx2.commit().await.expect("Failed to commit transaction");

        // Verify updated value
        let row = sqlx::query(
            "SELECT header_value FROM url_security_headers WHERE url_status_id = ? AND header_name = 'Strict-Transport-Security'",
        )
        .bind(url_status_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch security header");

        assert_eq!(row.get::<String, _>("header_value"), "max-age=63072000");
    }

    #[tokio::test]
    async fn test_insert_http_headers_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let mut http_headers = HashMap::new();
        http_headers.insert("Server".to_string(), "nginx/1.18.0".to_string());
        http_headers.insert("X-Powered-By".to_string(), "PHP/7.4".to_string());

        insert_http_headers(&mut tx, url_status_id, &http_headers).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify insertion
        let rows = sqlx::query(
            "SELECT header_name, header_value FROM url_http_headers WHERE url_status_id = ? ORDER BY header_name",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch HTTP headers");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<String, _>("header_name"), "Server");
        assert_eq!(rows[1].get::<String, _>("header_name"), "X-Powered-By");
    }
}
