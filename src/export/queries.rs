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
        query_builder.push("(us.domain = ");
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
        query_builder.push("us.status = ");
        query_builder.push_bind(status);
    }

    if let Some(since) = since {
        if has_where {
            query_builder.push(" AND ");
        } else {
            query_builder.push(" WHERE ");
        }
        query_builder.push("us.timestamp >= ");
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
        "SELECT url FROM url_redirect_chain WHERE url_status_id = ? ORDER BY sequence_order",
    )
    .bind(url_status_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.iter().map(|r| r.get::<String, _>("url")).collect())
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
        "SELECT domain_name FROM url_certificate_sans WHERE url_status_id = ? ORDER BY domain_name",
    )
    .bind(url_status_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .iter()
        .map(|r| r.get::<String, _>("domain_name"))
        .collect())
}

/// Fetches OIDs for a URL status record.
#[allow(dead_code)] // Reserved for future use (Parquet export, etc.)
pub async fn fetch_oids(pool: &SqlitePool, url_status_id: i64) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query("SELECT oid FROM url_oids WHERE url_status_id = ? ORDER BY oid")
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
        "SELECT platform, url FROM url_social_media_links
         WHERE url_status_id = ? ORDER BY platform, url",
    )
    .bind(url_status_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .iter()
        .map(|r| (r.get::<String, _>("platform"), r.get::<String, _>("url")))
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
                url TEXT NOT NULL,
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

        sqlx::query("INSERT INTO url_redirect_chain (url_status_id, url, sequence_order) VALUES (1, 'https://a.com', 1), (1, 'https://b.com', 2)")
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
}
