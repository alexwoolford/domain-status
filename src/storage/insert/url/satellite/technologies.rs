//! Technology insertion for url_technologies table.

use sqlx::Sqlite;
use sqlx::Transaction;

use crate::fingerprint::{self, DetectedTechnology};

/// Inserts technologies into url_technologies table.
pub(crate) async fn insert_technologies(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    technologies: &[DetectedTechnology],
) {
    log::debug!(
        "Inserting {} technologies for url_status_id {}",
        technologies.len(),
        url_status_id
    );

    // Deduplicate technologies and pre-fetch categories in a single pass.
    // This avoids sending duplicate INSERT queries to SQLite and reduces
    // lock contention from repeated get_technology_category calls.
    let mut seen = std::collections::HashSet::new();
    let mut deduped: Vec<(&DetectedTechnology, Option<String>)> = Vec::new();
    for tech in technologies {
        let key = if let Some(ref version) = tech.version {
            format!("{}:{}", tech.name, version)
        } else {
            tech.name.clone()
        };
        if seen.insert(key) {
            let category = fingerprint::get_technology_category(&tech.name).await;
            deduped.push((tech, category));
        }
    }

    let mut inserted_count = 0;
    let mut conflict_count = 0;
    for (tech, category) in &deduped {
        // Insert with separate name and version columns
        // Use INSERT OR IGNORE since we have unique indexes that handle NULL versions
        match sqlx::query(
            "INSERT OR IGNORE INTO url_technologies (url_status_id, technology_name, technology_version, technology_category)
             VALUES (?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind(&tech.name)
        .bind(&tech.version)
        .bind(category)
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
                        tech.name,
                        url_status_id
                    );
                }
            }
            Err(e) => {
                log::warn!(
                    "Failed to insert technology '{}' for url_status_id {}: {}",
                    tech.name,
                    url_status_id,
                    e
                );
            }
        }
    }

    log::debug!(
        "Inserted {} technologies for url_status_id {} ({} conflicts, {} unique from {} total)",
        inserted_count,
        url_status_id,
        conflict_count,
        deduped.len(),
        technologies.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;

    use crate::storage::test_helpers::{create_test_pool, create_test_url_status_default};

    #[tokio::test]
    async fn test_insert_technologies_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let technologies = vec![
            crate::fingerprint::DetectedTechnology {
                name: "WordPress".to_string(),
                version: None,
            },
            crate::fingerprint::DetectedTechnology {
                name: "PHP".to_string(),
                version: None,
            },
        ];

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
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let technologies = vec![
            crate::fingerprint::DetectedTechnology {
                name: "WordPress".to_string(),
                version: None,
            },
            crate::fingerprint::DetectedTechnology {
                name: "WordPress".to_string(),
                version: None,
            },
        ];

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
    async fn test_insert_technologies_with_versions() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let technologies = vec![
            crate::fingerprint::DetectedTechnology {
                name: "WordPress".to_string(),
                version: None,
            },
            crate::fingerprint::DetectedTechnology {
                name: "WordPress".to_string(),
                version: Some("6.9".to_string()),
            },
            crate::fingerprint::DetectedTechnology {
                name: "PHP".to_string(),
                version: Some("8.1".to_string()),
            },
        ];

        insert_technologies(&mut tx, url_status_id, &technologies).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify all three entries (WordPress without version, WordPress:6.9, PHP:8.1)
        let rows = sqlx::query(
            "SELECT technology_name, technology_version FROM url_technologies WHERE url_status_id = ? ORDER BY technology_name, technology_version",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch technologies");

        assert_eq!(rows.len(), 3);
        // WordPress without version should come first (NULL sorts first)
        assert_eq!(rows[0].get::<String, _>("technology_name"), "PHP");
        assert_eq!(
            rows[0].get::<Option<String>, _>("technology_version"),
            Some("8.1".to_string())
        );
        assert_eq!(rows[1].get::<String, _>("technology_name"), "WordPress");
        assert_eq!(rows[1].get::<Option<String>, _>("technology_version"), None);
        assert_eq!(rows[2].get::<String, _>("technology_name"), "WordPress");
        assert_eq!(
            rows[2].get::<Option<String>, _>("technology_version"),
            Some("6.9".to_string())
        );
    }

    #[tokio::test]
    async fn test_insert_technologies_empty() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

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
