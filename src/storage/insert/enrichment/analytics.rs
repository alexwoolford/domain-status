//! Analytics IDs insertion.

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;

/// Inserts analytics/tracking IDs for a URL status record.
///
/// This function inserts analytics IDs (Google Analytics, Facebook Pixel, GTM, AdSense)
/// into the `url_analytics_ids` table. These IDs enable graph analysis by linking
/// domains that share the same tracking IDs (indicating common ownership or management).
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - Foreign key to url_status.id
/// * `analytics_ids` - Vector of AnalyticsId structs (provider, id)
pub async fn insert_analytics_ids(
    pool: &SqlitePool,
    url_status_id: i64,
    analytics_ids: &[crate::parse::AnalyticsId],
) -> Result<(), DatabaseError> {
    for analytics_id in analytics_ids {
        sqlx::query(
            "INSERT INTO url_analytics_ids (url_status_id, provider, tracking_id)
             VALUES (?, ?, ?)
             ON CONFLICT(url_status_id, provider, tracking_id) DO NOTHING",
        )
        .bind(url_status_id)
        .bind(&analytics_id.provider)
        .bind(&analytics_id.id)
        .execute(pool)
        .await
        .map_err(DatabaseError::SqlError)?;
    }

    Ok(())
}

