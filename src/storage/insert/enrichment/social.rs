//! Social media links insertion.

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;
use crate::parse::SocialMediaLink;

/// Inserts social media links into the database.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - Foreign key to url_status.id
/// * `links` - Vector of social media links extracted from HTML
pub async fn insert_social_media_links(
    pool: &SqlitePool,
    url_status_id: i64,
    links: &[SocialMediaLink],
) -> Result<(), DatabaseError> {
    for link in links {
        if let Err(e) = sqlx::query(
            "INSERT INTO url_social_media_links (url_status_id, platform, url, identifier)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(url_status_id, platform, url) DO UPDATE SET
             identifier=excluded.identifier",
        )
        .bind(url_status_id)
        .bind(&link.platform)
        .bind(&link.url)
        .bind(&link.identifier)
        .execute(pool)
        .await
        {
            log::warn!(
                "Failed to insert social media link {} for platform {}: {}",
                link.url,
                link.platform,
                e
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::SocialMediaLink;
    use crate::storage::migrations::run_migrations;
    use sqlx::{Row, SqlitePool};

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
            "INSERT INTO url_status (domain, final_domain, ip_address, status, status_description, response_time, title, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind("example.com")
        .bind("example.com")
        .bind("93.184.216.34")
        .bind(200i64)
        .bind("OK")
        .bind(0.123f64)
        .bind("Test Page")
        .bind(1704067200000i64)
        .fetch_one(pool)
        .await
        .expect("Failed to insert test URL status")
        .get::<i64, _>(0)
    }

    #[tokio::test]
    async fn test_insert_social_media_links_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let links = vec![
            SocialMediaLink {
                platform: "Twitter".to_string(),
                url: "https://twitter.com/example".to_string(),
                identifier: Some("example".to_string()),
            },
            SocialMediaLink {
                platform: "LinkedIn".to_string(),
                url: "https://linkedin.com/company/example".to_string(),
                identifier: Some("example".to_string()),
            },
        ];

        let result = insert_social_media_links(&pool, url_status_id, &links).await;
        assert!(result.is_ok());

        // Verify insertion
        let rows = sqlx::query(
            "SELECT platform, url, identifier FROM url_social_media_links WHERE url_status_id = ? ORDER BY platform",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch social media links");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<String, _>("platform"), "LinkedIn");
        assert_eq!(
            rows[0].get::<String, _>("url"),
            "https://linkedin.com/company/example"
        );
        assert_eq!(rows[1].get::<String, _>("platform"), "Twitter");
        assert_eq!(
            rows[1].get::<String, _>("url"),
            "https://twitter.com/example"
        );
    }

    #[tokio::test]
    async fn test_insert_social_media_links_empty() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let links = vec![];

        let result = insert_social_media_links(&pool, url_status_id, &links).await;
        assert!(result.is_ok());

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM url_social_media_links WHERE url_status_id = ?",
        )
        .bind(url_status_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to count social media links");

        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_insert_social_media_links_upsert() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut link = SocialMediaLink {
            platform: "Twitter".to_string(),
            url: "https://twitter.com/example".to_string(),
            identifier: Some("example".to_string()),
        };

        // Insert first time
        let result1 = insert_social_media_links(&pool, url_status_id, &[link.clone()]).await;
        assert!(result1.is_ok());

        // Update identifier and insert again (should upsert)
        link.identifier = Some("updated_example".to_string());
        let result2 = insert_social_media_links(&pool, url_status_id, &[link.clone()]).await;
        assert!(result2.is_ok());

        // Verify only one row exists and it was updated
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM url_social_media_links WHERE url_status_id = ?",
        )
        .bind(url_status_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to count social media links");

        assert_eq!(count, 1);

        let row =
            sqlx::query("SELECT identifier FROM url_social_media_links WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to fetch updated social media link");

        assert_eq!(
            row.get::<Option<String>, _>("identifier"),
            Some("updated_example".to_string())
        );
    }

    #[tokio::test]
    async fn test_insert_social_media_links_no_identifier() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let links = vec![SocialMediaLink {
            platform: "GitHub".to_string(),
            url: "https://github.com/example".to_string(),
            identifier: None,
        }];

        let result = insert_social_media_links(&pool, url_status_id, &links).await;
        assert!(result.is_ok());

        let row =
            sqlx::query("SELECT identifier FROM url_social_media_links WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to fetch social media link");

        assert_eq!(row.get::<Option<String>, _>("identifier"), None);
    }
}
