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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::AnalyticsId;
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
    async fn test_insert_analytics_ids_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let analytics_ids = vec![
            AnalyticsId {
                provider: "Google Analytics".to_string(),
                id: "UA-123456-1".to_string(),
            },
            AnalyticsId {
                provider: "Google Tag Manager".to_string(),
                id: "GTM-XXXXX".to_string(),
            },
        ];

        let result = insert_analytics_ids(&pool, url_status_id, &analytics_ids).await;
        assert!(result.is_ok());

        // Verify insertion
        let rows = sqlx::query(
            "SELECT provider, tracking_id FROM url_analytics_ids WHERE url_status_id = ? ORDER BY provider",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch analytics IDs");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<String, _>("provider"), "Google Analytics");
        assert_eq!(rows[0].get::<String, _>("tracking_id"), "UA-123456-1");
        assert_eq!(rows[1].get::<String, _>("provider"), "Google Tag Manager");
        assert_eq!(rows[1].get::<String, _>("tracking_id"), "GTM-XXXXX");
    }

    #[tokio::test]
    async fn test_insert_analytics_ids_empty() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let analytics_ids = vec![];

        let result = insert_analytics_ids(&pool, url_status_id, &analytics_ids).await;
        assert!(result.is_ok());

        // Verify no rows inserted
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_analytics_ids WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count analytics IDs");

        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_insert_analytics_ids_duplicate() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let analytics_ids = vec![AnalyticsId {
            provider: "Google Analytics".to_string(),
            id: "UA-123456-1".to_string(),
        }];

        // Insert first time
        let result1 = insert_analytics_ids(&pool, url_status_id, &analytics_ids).await;
        assert!(result1.is_ok());

        // Insert again (should not create duplicate due to ON CONFLICT DO NOTHING)
        let result2 = insert_analytics_ids(&pool, url_status_id, &analytics_ids).await;
        assert!(result2.is_ok());

        // Verify only one row exists
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_analytics_ids WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count analytics IDs");

        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_insert_analytics_ids_multiple_providers() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let analytics_ids = vec![
            AnalyticsId {
                provider: "Google Analytics".to_string(),
                id: "UA-123456-1".to_string(),
            },
            AnalyticsId {
                provider: "Google Analytics".to_string(),
                id: "UA-789012-3".to_string(),
            },
            AnalyticsId {
                provider: "Facebook Pixel".to_string(),
                id: "123456789".to_string(),
            },
        ];

        let result = insert_analytics_ids(&pool, url_status_id, &analytics_ids).await;
        assert!(result.is_ok());

        // Verify all inserted
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_analytics_ids WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count analytics IDs");

        assert_eq!(count, 3);
    }
}
