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
