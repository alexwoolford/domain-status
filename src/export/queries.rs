//! Shared database queries for export functionality.
//!
//! This module centralizes all export-related queries to ensure consistency
//! between CSV and JSONL export formats.

// Allow dead code while incrementally migrating csv.rs and jsonl.rs to use these
#![allow(dead_code)]

use sqlx::{Row, SqlitePool};

/// Fetches redirect chain for a URL status record.
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
pub async fn fetch_oids(pool: &SqlitePool, url_status_id: i64) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query("SELECT oid FROM url_oids WHERE url_status_id = ? ORDER BY oid")
        .bind(url_status_id)
        .fetch_all(pool)
        .await?;

    Ok(rows.iter().map(|r| r.get::<String, _>("oid")).collect())
}

/// Fetches analytics IDs for a URL status record.
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

/// Fetches count from a satellite table for a URL status record.
pub async fn fetch_count(
    pool: &SqlitePool,
    table: &str,
    url_status_id: i64,
) -> Result<i64, sqlx::Error> {
    let query = format!(
        "SELECT COUNT(*) as cnt FROM {} WHERE url_status_id = ?",
        table
    );
    let row = sqlx::query(&query)
        .bind(url_status_id)
        .fetch_one(pool)
        .await?;

    Ok(row.get::<i64, _>("cnt"))
}

/// Fetches header key-value pairs for a URL status record.
pub async fn fetch_headers(
    pool: &SqlitePool,
    table: &str,
    url_status_id: i64,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    let query = format!(
        "SELECT header_name, header_value FROM {} WHERE url_status_id = ?",
        table
    );
    let rows = sqlx::query(&query)
        .bind(url_status_id)
        .fetch_all(pool)
        .await?;

    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get::<String, _>("header_name"),
                r.get::<String, _>("header_value"),
            )
        })
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

    #[tokio::test]
    async fn test_fetch_count() {
        let pool = create_test_pool().await;

        sqlx::query("INSERT INTO url_technologies (url_status_id, technology_name) VALUES (1, 'A'), (1, 'B')")
            .execute(&pool)
            .await
            .unwrap();

        let count = fetch_count(&pool, "url_technologies", 1).await.unwrap();
        assert_eq!(count, 2);
    }
}
