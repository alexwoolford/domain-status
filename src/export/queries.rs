//! Shared database queries for export functionality.
//!
//! This module centralizes all export-related queries to ensure consistency
//! between CSV and JSONL export formats.
//!
//! All helper functions used by both CSV and JSONL exports are defined here
//! to prevent duplication and ensure both formats stay in sync.

use anyhow::Result;
use sqlx::{QueryBuilder, Row, SqlitePool};
use std::io::{self, ErrorKind, Write};

use crate::storage::DbPool;

/// Wrapper around a Write that ignores broken pipe errors (EPIPE).
/// This allows graceful handling when stdout is piped to a command that exits early.
pub(crate) struct IgnoreBrokenPipe<W: Write> {
    inner: W,
}

impl<W: Write> IgnoreBrokenPipe<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self { inner }
    }
}

impl<W: Write> Write for IgnoreBrokenPipe<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf).or_else(|e| {
            if e.kind() == ErrorKind::BrokenPipe {
                // Ignore broken pipe - downstream command closed the pipe
                Ok(buf.len())
            } else {
                Err(e)
            }
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush().or_else(|e| {
            if e.kind() == ErrorKind::BrokenPipe {
                Ok(())
            } else {
                Err(e)
            }
        })
    }
}

/// Helper: Fetch a list of string values from a query that returns a single column.
/// Returns (joined_string, count).
pub(crate) async fn fetch_string_list(
    pool: &DbPool,
    query: &str,
    url_status_id: i64,
) -> Result<(String, usize)> {
    let rows = sqlx::query(query)
        .bind(url_status_id)
        .fetch_all(pool.as_ref())
        .await?;

    let items: Vec<String> = rows.iter().map(|r| r.get::<String, _>(0)).collect();
    let count = items.len();
    let joined = items.join(",");
    Ok((joined, count))
}

/// Helper: Fetch a count from a query.
pub(crate) async fn fetch_count_query(
    pool: &DbPool,
    query: &str,
    url_status_id: i64,
) -> Result<i64> {
    sqlx::query_scalar::<_, i64>(query)
        .bind(url_status_id)
        .fetch_one(pool.as_ref())
        .await
        .map_err(Into::into)
}

/// Helper: Fetch key-value pairs and format as "key:value" strings.
/// Returns (joined_string, count).
pub(crate) async fn fetch_key_value_list(
    pool: &DbPool,
    query: &str,
    key_field: &str,
    value_field: &str,
    url_status_id: i64,
) -> Result<(String, usize)> {
    let rows = sqlx::query(query)
        .bind(url_status_id)
        .fetch_all(pool.as_ref())
        .await?;

    let items: Vec<String> = rows
        .iter()
        .map(|r| {
            let key: String = r.get(key_field);
            let value: String = r.get(value_field);
            format!("{}:{}", key, value)
        })
        .collect();
    let count = items.len();
    let joined = items.join(",");
    Ok((joined, count))
}

/// Helper: Fetch filtered HTTP headers and format as "name:value" strings.
/// Returns (joined_string, total_count).
/// The joined string contains only filtered headers (separated by semicolons),
/// but the count is the total number of headers in the table.
pub(crate) async fn fetch_filtered_http_headers(
    pool: &DbPool,
    table: &str,
    url_status_id: i64,
    allowed_headers: &[&str],
) -> Result<(String, i64)> {
    // Build query with IN clause for allowed headers
    // Use QueryBuilder to safely construct the query
    let mut query_builder = sqlx::QueryBuilder::new(&format!(
        "SELECT header_name, header_value FROM {} WHERE url_status_id = ",
        table
    ));

    query_builder.push_bind(url_status_id);
    query_builder.push(" AND header_name IN (");

    // Add placeholders for each allowed header
    let mut separated = query_builder.separated(", ");
    for header in allowed_headers {
        separated.push_bind(*header);
    }
    separated.push_unseparated(") ORDER BY header_name");

    let rows = query_builder.build().fetch_all(pool.as_ref()).await?;

    let items: Vec<String> = rows
        .iter()
        .map(|r| {
            let name: String = r.get("header_name");
            let value: String = r.get("header_value");
            format!("{}:{}", name, value)
        })
        .collect();
    let joined = items.join(";");

    // Get total count (all headers, not just filtered)
    let total_count = fetch_count_query(
        pool,
        &format!("SELECT COUNT(*) FROM {} WHERE url_status_id = ?", table),
        url_status_id,
    )
    .await?;

    Ok((joined, total_count))
}

/// Builds WHERE clause for export queries based on filter parameters.
/// Modifies the query builder in place.
pub(crate) fn build_where_clause<'a>(
    query_builder: &mut QueryBuilder<'a, sqlx::Sqlite>,
    run_id: Option<&'a str>,
    domain: Option<&'a str>,
    status: Option<u16>,
    since: Option<i64>,
) {
    let mut has_where = false;

    if let Some(run_id) = run_id {
        query_builder.push(" WHERE us.run_id = ");
        query_builder.push_bind(run_id);
        has_where = true;
    }

    if let Some(domain) = domain {
        if has_where {
            query_builder.push(" AND ");
        } else {
            query_builder.push(" WHERE ");
            has_where = true;
        }
        query_builder.push("(us.initial_domain = ");
        query_builder.push_bind(domain);
        query_builder.push(" OR us.final_domain = ");
        query_builder.push_bind(domain);
        query_builder.push(")");
    }

    if let Some(status) = status {
        if has_where {
            query_builder.push(" AND ");
        } else {
            query_builder.push(" WHERE ");
            has_where = true;
        }
        query_builder.push("us.http_status = ");
        query_builder.push_bind(status);
    }

    if let Some(since) = since {
        if has_where {
            query_builder.push(" AND ");
        } else {
            query_builder.push(" WHERE ");
        }
        query_builder.push("us.observed_at_ms >= ");
        query_builder.push_bind(since);
    }
}

// The following functions return structured data (not formatted strings).
// They are reserved for future use (e.g., Parquet export) and are not yet used by CSV/JSONL.
// CSV/JSONL use the helper functions above (fetch_string_list, fetch_key_value_list, etc.)
// which format data for their specific output formats.

/// Fetches redirect chain for a URL status record.
#[allow(dead_code)] // Reserved for future use (Parquet export, etc.)
pub async fn fetch_redirect_chain(
    pool: &SqlitePool,
    url_status_id: i64,
) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT redirect_url FROM url_redirect_chain WHERE url_status_id = ? ORDER BY sequence_order",
    )
    .bind(url_status_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .iter()
        .map(|r| r.get::<String, _>("redirect_url"))
        .collect())
}

/// Fetches technologies with optional versions for a URL status record.
#[allow(dead_code)] // Reserved for future use (Parquet export, etc.)
pub async fn fetch_technologies(
    pool: &SqlitePool,
    url_status_id: i64,
) -> Result<Vec<(String, Option<String>)>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT technology_name, technology_version FROM url_technologies
         WHERE url_status_id = ? ORDER BY technology_name, technology_version",
    )
    .bind(url_status_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get::<String, _>("technology_name"),
                r.get::<Option<String>, _>("technology_version"),
            )
        })
        .collect())
}

/// Fetches certificate SANs for a URL status record.
#[allow(dead_code)] // Reserved for future use (Parquet export, etc.)
pub async fn fetch_certificate_sans(
    pool: &SqlitePool,
    url_status_id: i64,
) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT san_value FROM url_certificate_sans WHERE url_status_id = ? ORDER BY san_value",
    )
    .bind(url_status_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .iter()
        .map(|r| r.get::<String, _>("san_value"))
        .collect())
}

/// Fetches OIDs for a URL status record.
#[allow(dead_code)] // Reserved for future use (Parquet export, etc.)
pub async fn fetch_oids(pool: &SqlitePool, url_status_id: i64) -> Result<Vec<String>, sqlx::Error> {
    let rows =
        sqlx::query("SELECT oid FROM url_certificate_oids WHERE url_status_id = ? ORDER BY oid")
            .bind(url_status_id)
            .fetch_all(pool)
            .await?;

    Ok(rows.iter().map(|r| r.get::<String, _>("oid")).collect())
}

/// Fetches analytics IDs for a URL status record.
#[allow(dead_code)] // Reserved for future use (Parquet export, etc.)
pub async fn fetch_analytics_ids(
    pool: &SqlitePool,
    url_status_id: i64,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT provider, tracking_id FROM url_analytics_ids
         WHERE url_status_id = ? ORDER BY provider, tracking_id",
    )
    .bind(url_status_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get::<String, _>("provider"),
                r.get::<String, _>("tracking_id"),
            )
        })
        .collect())
}

/// Fetches social media links for a URL status record.
#[allow(dead_code)] // Reserved for future use (Parquet export, etc.)
pub async fn fetch_social_media_links(
    pool: &SqlitePool,
    url_status_id: i64,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT platform, profile_url FROM url_social_media_links
         WHERE url_status_id = ? ORDER BY platform, profile_url",
    )
    .bind(url_status_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get::<String, _>("platform"),
                r.get::<String, _>("profile_url"),
            )
        })
        .collect())
}

/// Fetches security warnings for a URL status record.
#[allow(dead_code)] // Reserved for future use (Parquet export, etc.)
pub async fn fetch_security_warnings(
    pool: &SqlitePool,
    url_status_id: i64,
) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT warning_code FROM url_security_warnings
         WHERE url_status_id = ? ORDER BY warning_code",
    )
    .bind(url_status_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .iter()
        .map(|r| r.get::<String, _>("warning_code"))
        .collect())
}

/// Fetches structured data types for a URL status record.
#[allow(dead_code)] // Reserved for future use (Parquet export, etc.)
pub async fn fetch_structured_data_types(
    pool: &SqlitePool,
    url_status_id: i64,
) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT DISTINCT data_type FROM url_structured_data
         WHERE url_status_id = ? ORDER BY data_type",
    )
    .bind(url_status_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .iter()
        .map(|r| r.get::<String, _>("data_type"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;

    async fn create_test_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        // Create minimal schema for testing
        sqlx::query(
            "CREATE TABLE url_status (
                id INTEGER PRIMARY KEY,
                initial_domain TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "CREATE TABLE url_redirect_chain (
                id INTEGER PRIMARY KEY,
                url_status_id INTEGER NOT NULL,
                redirect_url TEXT NOT NULL,
                sequence_order INTEGER NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "CREATE TABLE url_technologies (
                id INTEGER PRIMARY KEY,
                url_status_id INTEGER NOT NULL,
                technology_name TEXT NOT NULL,
                technology_version TEXT
            )",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "CREATE TABLE url_analytics_ids (
                id INTEGER PRIMARY KEY,
                url_status_id INTEGER NOT NULL,
                provider TEXT NOT NULL,
                tracking_id TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();

        pool
    }

    #[tokio::test]
    async fn test_fetch_redirect_chain() {
        let pool = create_test_pool().await;

        sqlx::query("INSERT INTO url_redirect_chain (url_status_id, redirect_url, sequence_order) VALUES (1, 'https://a.com', 1), (1, 'https://b.com', 2)")
            .execute(&pool)
            .await
            .unwrap();

        let chain = fetch_redirect_chain(&pool, 1).await.unwrap();
        assert_eq!(chain, vec!["https://a.com", "https://b.com"]);
    }

    #[tokio::test]
    async fn test_fetch_redirect_chain_empty() {
        let pool = create_test_pool().await;
        let chain = fetch_redirect_chain(&pool, 999).await.unwrap();
        assert!(chain.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_technologies() {
        let pool = create_test_pool().await;

        sqlx::query("INSERT INTO url_technologies (url_status_id, technology_name, technology_version) VALUES (1, 'WordPress', '6.0'), (1, 'PHP', NULL)")
            .execute(&pool)
            .await
            .unwrap();

        let techs = fetch_technologies(&pool, 1).await.unwrap();
        assert_eq!(techs.len(), 2);
        assert!(techs.contains(&("PHP".to_string(), None)));
        assert!(techs.contains(&("WordPress".to_string(), Some("6.0".to_string()))));
    }

    #[tokio::test]
    async fn test_fetch_analytics_ids() {
        let pool = create_test_pool().await;

        sqlx::query("INSERT INTO url_analytics_ids (url_status_id, provider, tracking_id) VALUES (1, 'Google Analytics', 'UA-12345')")
            .execute(&pool)
            .await
            .unwrap();

        let ids = fetch_analytics_ids(&pool, 1).await.unwrap();
        assert_eq!(
            ids,
            vec![("Google Analytics".to_string(), "UA-12345".to_string())]
        );
    }

    #[tokio::test]
    async fn test_fetch_string_list_empty() {
        // Test fetch_string_list with no results
        let pool = create_test_pool().await;
        let pool_arc = Arc::new(pool);

        let (result, count) = fetch_string_list(
            &pool_arc,
            "SELECT redirect_url FROM url_redirect_chain WHERE url_status_id = ?",
            999,
        )
        .await
        .expect("Should succeed with empty result");

        assert_eq!(result, "");
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_fetch_string_list_multiple() {
        // Test fetch_string_list with multiple results
        let pool = create_test_pool().await;
        let pool_arc = Arc::new(pool);

        sqlx::query("INSERT INTO url_redirect_chain (url_status_id, redirect_url, sequence_order) VALUES (1, 'https://a.com', 1), (1, 'https://b.com', 2), (1, 'https://c.com', 3)")
            .execute(&*pool_arc)
            .await
            .unwrap();

        let (result, count) = fetch_string_list(
            &pool_arc,
            "SELECT redirect_url FROM url_redirect_chain WHERE url_status_id = ? ORDER BY sequence_order",
            1,
        )
        .await
        .expect("Should succeed");

        assert_eq!(result, "https://a.com,https://b.com,https://c.com");
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn test_fetch_count_query_zero() {
        // Test fetch_count_query with zero count
        let pool = create_test_pool().await;
        let pool_arc = Arc::new(pool);

        let count = fetch_count_query(
            &pool_arc,
            "SELECT COUNT(*) FROM url_redirect_chain WHERE url_status_id = ?",
            999,
        )
        .await
        .expect("Should succeed");

        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_fetch_count_query_non_zero() {
        // Test fetch_count_query with non-zero count
        let pool = create_test_pool().await;
        let pool_arc = Arc::new(pool);

        sqlx::query("INSERT INTO url_redirect_chain (url_status_id, redirect_url, sequence_order) VALUES (1, 'https://a.com', 1), (1, 'https://b.com', 2)")
            .execute(&*pool_arc)
            .await
            .unwrap();

        let count = fetch_count_query(
            &pool_arc,
            "SELECT COUNT(*) FROM url_redirect_chain WHERE url_status_id = ?",
            1,
        )
        .await
        .expect("Should succeed");

        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn test_fetch_key_value_list_empty() {
        // Test fetch_key_value_list with no results
        let pool = create_test_pool().await;
        let pool_arc = Arc::new(pool);

        let (result, count) = fetch_key_value_list(
            &pool_arc,
            "SELECT provider, tracking_id FROM url_analytics_ids WHERE url_status_id = ?",
            "provider",
            "tracking_id",
            999,
        )
        .await
        .expect("Should succeed with empty result");

        assert_eq!(result, "");
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_fetch_key_value_list_multiple() {
        // Test fetch_key_value_list with multiple results
        let pool = create_test_pool().await;
        let pool_arc = Arc::new(pool);

        sqlx::query("INSERT INTO url_analytics_ids (url_status_id, provider, tracking_id) VALUES (1, 'Google Analytics', 'UA-12345'), (1, 'Facebook Pixel', '123456789')")
            .execute(&*pool_arc)
            .await
            .unwrap();

        let (result, count) = fetch_key_value_list(
            &pool_arc,
            "SELECT provider, tracking_id FROM url_analytics_ids WHERE url_status_id = ? ORDER BY provider",
            "provider",
            "tracking_id",
            1,
        )
        .await
        .expect("Should succeed");

        assert!(result.contains("Facebook Pixel:123456789"));
        assert!(result.contains("Google Analytics:UA-12345"));
        assert_eq!(count, 2);
    }

    #[test]
    fn test_build_where_clause_no_filters() {
        // Test build_where_clause with no filters
        let mut query_builder = sqlx::QueryBuilder::new("SELECT * FROM url_status");
        build_where_clause(&mut query_builder, None, None, None, None);
        // Verify the query can be built (no panic)
        let _query = query_builder.build();
        // The query should be valid SQL even with no WHERE clause
    }

    #[test]
    fn test_build_where_clause_run_id_only() {
        // Test build_where_clause with only run_id
        let mut query_builder = sqlx::QueryBuilder::new("SELECT * FROM url_status");
        build_where_clause(&mut query_builder, Some("test-run-1"), None, None, None);
        // Verify the query can be built
        let _query = query_builder.build();
    }

    #[test]
    fn test_build_where_clause_domain_only() {
        // Test build_where_clause with only domain
        let mut query_builder = sqlx::QueryBuilder::new("SELECT * FROM url_status");
        build_where_clause(&mut query_builder, None, Some("example.com"), None, None);
        // Verify the query can be built
        let _query = query_builder.build();
    }

    #[test]
    fn test_build_where_clause_status_only() {
        // Test build_where_clause with only status
        let mut query_builder = sqlx::QueryBuilder::new("SELECT * FROM url_status");
        build_where_clause(&mut query_builder, None, None, Some(404), None);
        // Verify the query can be built
        let _query = query_builder.build();
    }

    #[test]
    fn test_build_where_clause_since_only() {
        // Test build_where_clause with only since
        let mut query_builder = sqlx::QueryBuilder::new("SELECT * FROM url_status");
        build_where_clause(&mut query_builder, None, None, None, Some(1704067200000i64));
        // Verify the query can be built
        let _query = query_builder.build();
    }

    #[test]
    fn test_build_where_clause_all_filters() {
        // Test build_where_clause with all filters
        let mut query_builder = sqlx::QueryBuilder::new("SELECT * FROM url_status");
        build_where_clause(
            &mut query_builder,
            Some("test-run-1"),
            Some("example.com"),
            Some(200),
            Some(1704067200000i64),
        );
        // Verify the query can be built with all filters
        let _query = query_builder.build();
    }

    #[tokio::test]
    async fn test_fetch_filtered_http_headers_empty() {
        // Test fetch_filtered_http_headers with no matching headers
        let pool = create_test_pool().await;
        let pool_arc = Arc::new(pool);

        // Create a table for headers (simplified schema)
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS url_http_headers (
                id INTEGER PRIMARY KEY,
                url_status_id INTEGER NOT NULL,
                header_name TEXT NOT NULL,
                header_value TEXT NOT NULL
            )",
        )
        .execute(&*pool_arc)
        .await
        .unwrap();

        let (result, count) = fetch_filtered_http_headers(
            &pool_arc,
            "url_http_headers",
            999,
            &["Content-Type", "Server"],
        )
        .await
        .expect("Should succeed with empty result");

        assert_eq!(result, "");
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_fetch_filtered_http_headers_with_matches() {
        // Test fetch_filtered_http_headers with matching headers
        let pool = create_test_pool().await;
        let pool_arc = Arc::new(pool);

        // Create a table for headers
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS url_http_headers (
                id INTEGER PRIMARY KEY,
                url_status_id INTEGER NOT NULL,
                header_name TEXT NOT NULL,
                header_value TEXT NOT NULL
            )",
        )
        .execute(&*pool_arc)
        .await
        .unwrap();

        // Insert headers (some matching, some not)
        sqlx::query("INSERT INTO url_http_headers (url_status_id, header_name, header_value) VALUES (1, 'Content-Type', 'text/html'), (1, 'Server', 'nginx'), (1, 'X-Custom', 'value')")
            .execute(&*pool_arc)
            .await
            .unwrap();

        let (result, total_count) = fetch_filtered_http_headers(
            &pool_arc,
            "url_http_headers",
            1,
            &["Content-Type", "Server"],
        )
        .await
        .expect("Should succeed");

        // Result should contain only filtered headers (Content-Type and Server)
        assert!(result.contains("Content-Type:text/html"));
        assert!(result.contains("Server:nginx"));
        assert!(!result.contains("X-Custom")); // Should not include non-filtered header
                                               // Total count should be 3 (all headers), but result string only has filtered ones
        assert_eq!(total_count, 3);
    }
}
