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
            "INSERT INTO url_social_media_links (url_status_id, platform, profile_url, identifier)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(url_status_id, platform, profile_url) DO UPDATE SET
             identifier=excluded.identifier",
        )
        .bind(url_status_id)
        .bind(link.platform.as_str())
        .bind(&link.url)
        .bind(&link.identifier)
        .execute(pool)
        .await
        {
            log::warn!(
                "Failed to insert social media link {} for platform {}: {}",
                link.url,
                link.platform.as_str(),
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
    use crate::parse::SocialPlatform;
    use sqlx::Row;

    use crate::storage::test_helpers::{create_test_pool, create_test_url_status_default};

    #[tokio::test]
    async fn test_insert_social_media_links_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let links = vec![
            SocialMediaLink {
                platform: SocialPlatform::Twitter,
                url: "https://twitter.com/example".to_string(),
                identifier: Some("example".to_string()),
            },
            SocialMediaLink {
                platform: SocialPlatform::LinkedIn,
                url: "https://linkedin.com/company/example".to_string(),
                identifier: Some("example".to_string()),
            },
        ];

        let result = insert_social_media_links(&pool, url_status_id, &links).await;
        assert!(result.is_ok());

        // Verify insertion
        let rows = sqlx::query(
            "SELECT platform, profile_url, identifier FROM url_social_media_links WHERE url_status_id = ? ORDER BY platform",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch social media links");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<String, _>("platform"), "LinkedIn");
        assert_eq!(
            rows[0].get::<String, _>("profile_url"),
            "https://linkedin.com/company/example"
        );
        assert_eq!(rows[1].get::<String, _>("platform"), "Twitter");
        assert_eq!(
            rows[1].get::<String, _>("profile_url"),
            "https://twitter.com/example"
        );
    }

    #[tokio::test]
    async fn test_insert_social_media_links_empty() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

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
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut link = SocialMediaLink {
            platform: SocialPlatform::Twitter,
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
        let url_status_id = create_test_url_status_default(&pool).await;

        let links = vec![SocialMediaLink {
            platform: SocialPlatform::GitHub,
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
