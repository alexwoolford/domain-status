//! Technology insertion for url_technologies table.

use sqlx::Sqlite;
use sqlx::Transaction;

use crate::fingerprint;

/// Inserts technologies into url_technologies table.
pub(crate) async fn insert_technologies(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    technologies: &[String],
) {
    log::debug!(
        "Inserting {} technologies for url_status_id {}: {:?}",
        technologies.len(),
        url_status_id,
        technologies
    );

    // Batch optimization: Pre-fetch categories for unique technologies to avoid
    // repeated ruleset lookups. This reduces lock contention since get_technology_category
    // acquires a read lock on the ruleset for each call.
    // Deduplicate technologies first (common case: same tech detected multiple times)
    let unique_techs: std::collections::HashSet<&str> =
        technologies.iter().map(|s| s.as_str()).collect();
    let mut category_map = std::collections::HashMap::new();
    for tech in &unique_techs {
        category_map.insert(*tech, fingerprint::get_technology_category(tech).await);
    }

    let mut inserted_count = 0;
    let mut conflict_count = 0;
    for tech in technologies {
        // Use pre-fetched category
        let category = category_map.get(tech.as_str()).cloned().flatten();

        match sqlx::query(
            "INSERT INTO url_technologies (url_status_id, technology_name, technology_category)
             VALUES (?, ?, ?)
             ON CONFLICT(url_status_id, technology_name) DO NOTHING",
        )
        .bind(url_status_id)
        .bind(tech)
        .bind(&category)
        .execute(&mut **tx)
        .await
        {
            Ok(result) => {
                if result.rows_affected() > 0 {
                    inserted_count += 1;
                } else {
                    conflict_count += 1;
                    log::debug!(
                        "Technology '{}' already exists for url_status_id {} (conflict)",
                        tech,
                        url_status_id
                    );
                }
            }
            Err(e) => {
                log::warn!(
                    "Failed to insert technology '{}' for url_status_id {}: {}",
                    tech,
                    url_status_id,
                    e
                );
            }
        }
    }

    log::debug!(
        "Inserted {} technologies for url_status_id {} ({} conflicts, {} total)",
        inserted_count,
        url_status_id,
        conflict_count,
        technologies.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
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
    async fn test_insert_technologies_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let technologies = vec!["WordPress".to_string(), "PHP".to_string()];

        insert_technologies(&mut tx, url_status_id, &technologies).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify insertion
        let rows = sqlx::query(
            "SELECT technology_name, technology_category FROM url_technologies WHERE url_status_id = ? ORDER BY technology_name",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch technologies");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<String, _>("technology_name"), "PHP");
        assert_eq!(rows[1].get::<String, _>("technology_name"), "WordPress");
    }

    #[tokio::test]
    async fn test_insert_technologies_duplicates() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let technologies = vec!["WordPress".to_string(), "WordPress".to_string()];

        insert_technologies(&mut tx, url_status_id, &technologies).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify only one entry (ON CONFLICT DO NOTHING)
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_technologies WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count technologies");

        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_insert_technologies_empty() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let technologies = vec![];

        insert_technologies(&mut tx, url_status_id, &technologies).await;
        tx.commit().await.expect("Failed to commit transaction");

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_technologies WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count technologies");

        assert_eq!(count, 0);
    }
}
