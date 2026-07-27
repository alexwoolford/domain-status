//! Technology insertion for `url_technologies` table.

use sqlx::Sqlite;
use sqlx::Transaction;

use crate::fingerprint::DetectedTechnology;

use super::super::super::utils::build_batch_insert_query;

/// Inserts technologies into `url_technologies` table using batch INSERT.
pub(crate) async fn insert_technologies(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    technologies: &[DetectedTechnology],
) {
    if technologies.is_empty() {
        return;
    }

    log::debug!(
        "Inserting {} technologies for url_status_id {}",
        technologies.len(),
        url_status_id
    );

    // Deduplicate technologies and drop header-derived protocol flags (HTTP/3, HSTS)
    // that belong in headers/TLS columns, not the stack inventory.
    let mut seen = std::collections::HashSet::new();
    let mut deduped: Vec<&DetectedTechnology> = Vec::new();
    for tech in technologies {
        if tech.name.eq_ignore_ascii_case("HTTP/3") || tech.name.eq_ignore_ascii_case("HSTS") {
            continue;
        }
        let key = if let Some(ref version) = tech.version {
            format!("{}:{}", tech.name, version)
        } else {
            tech.name.clone()
        };
        if seen.insert(key) {
            deduped.push(tech);
        }
    }

    if deduped.is_empty() {
        return;
    }

    // Batch INSERT all technologies in a single query
    let query_str = build_batch_insert_query(
        "url_technologies",
        &[
            "url_status_id",
            "technology_name",
            "technology_version",
            "technology_category",
            "is_implied",
        ],
        deduped.len(),
        Some("ON CONFLICT DO NOTHING"),
    );

    let mut query = sqlx::query(&query_str);
    for tech in &deduped {
        query = query
            .bind(url_status_id)
            .bind(&tech.name)
            .bind(&tech.version)
            .bind(&tech.category)
            .bind(i64::from(tech.is_implied));
    }

    match query.execute(&mut **tx).await {
        Ok(result) => {
            log::debug!(
                "Batch inserted {} technologies for url_status_id {} ({} rows affected, {} unique from {} total)",
                deduped.len(),
                url_status_id,
                result.rows_affected(),
                deduped.len(),
                technologies.len()
            );
        }
        Err(e) => {
            log::warn!(
                "Failed to batch insert {} technologies for url_status_id {}: {}",
                deduped.len(),
                url_status_id,
                e
            );
        }
    }
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
                category: None,
                is_implied: false,
            },
            crate::fingerprint::DetectedTechnology {
                name: "PHP".to_string(),
                version: None,
                category: None,
                is_implied: false,
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
                category: None,
                is_implied: false,
            },
            crate::fingerprint::DetectedTechnology {
                name: "WordPress".to_string(),
                version: None,
                category: None,
                is_implied: false,
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
                category: None,
                is_implied: false,
            },
            crate::fingerprint::DetectedTechnology {
                name: "WordPress".to_string(),
                version: Some("6.9".to_string()),
                category: None,
                is_implied: false,
            },
            crate::fingerprint::DetectedTechnology {
                name: "PHP".to_string(),
                version: Some("8.1".to_string()),
                category: None,
                is_implied: false,
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

    #[tokio::test]
    async fn test_insert_technologies_is_implied() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let technologies = vec![
            crate::fingerprint::DetectedTechnology {
                name: "WordPress".to_string(),
                version: None,
                category: Some("CMS".to_string()),
                is_implied: false,
            },
            crate::fingerprint::DetectedTechnology {
                name: "MySQL".to_string(),
                version: None,
                category: Some("Databases".to_string()),
                is_implied: true,
            },
        ];

        insert_technologies(&mut tx, url_status_id, &technologies).await;
        tx.commit().await.expect("Failed to commit transaction");

        let rows = sqlx::query(
            "SELECT technology_name, is_implied FROM url_technologies WHERE url_status_id = ? ORDER BY technology_name",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch technologies");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<String, _>("technology_name"), "MySQL");
        assert_eq!(rows[0].get::<i64, _>("is_implied"), 1);
        assert_eq!(rows[1].get::<String, _>("technology_name"), "WordPress");
        assert_eq!(rows[1].get::<i64, _>("is_implied"), 0);
    }

    #[tokio::test]
    async fn test_insert_technologies_skips_http3_and_hsts() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let technologies = vec![
            crate::fingerprint::DetectedTechnology {
                name: "HTTP/3".to_string(),
                version: None,
                category: None,
                is_implied: false,
            },
            crate::fingerprint::DetectedTechnology {
                name: "HSTS".to_string(),
                version: None,
                category: None,
                is_implied: false,
            },
            crate::fingerprint::DetectedTechnology {
                name: "nginx".to_string(),
                version: None,
                category: Some("Web servers".to_string()),
                is_implied: false,
            },
        ];

        insert_technologies(&mut tx, url_status_id, &technologies).await;
        tx.commit().await.expect("Failed to commit transaction");

        let names: Vec<String> = sqlx::query_scalar(
            "SELECT technology_name FROM url_technologies WHERE url_status_id = ? ORDER BY technology_name",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("fetch");

        assert_eq!(names, vec!["nginx".to_string()]);
    }
}
