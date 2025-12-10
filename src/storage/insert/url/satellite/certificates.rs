//! Certificate-related insertion (OIDs, SANs) for satellite tables.

use sqlx::Sqlite;
use sqlx::Transaction;

use super::super::super::utils::build_batch_insert_query;

/// Inserts OIDs into url_oids table using batch insert.
pub(crate) async fn insert_oids(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    oids: &std::collections::HashSet<String>,
) {
    if oids.is_empty() {
        return;
    }

    // Convert HashSet to Vec for consistent ordering
    let oids_vec: Vec<&String> = oids.iter().collect();

    // Batch insert: build VALUES clause for all OIDs
    let query = build_batch_insert_query(
        "url_oids",
        &["url_status_id", "oid"],
        oids_vec.len(),
        Some("ON CONFLICT(url_status_id, oid) DO NOTHING"),
    );

    let mut query_builder = sqlx::query(&query);
    for oid in &oids_vec {
        query_builder = query_builder.bind(url_status_id).bind(*oid);
    }

    if let Err(e) = query_builder.execute(&mut **tx).await {
        log::warn!(
            "Failed to batch insert {} OIDs for url_status_id {}: {}",
            oids_vec.len(),
            url_status_id,
            e
        );
    }
}

/// Inserts certificate Subject Alternative Names (SANs) into url_certificate_sans table using batch insert.
pub(crate) async fn insert_certificate_sans(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    subject_alternative_names: &[String],
) {
    if subject_alternative_names.is_empty() {
        return;
    }

    // SANs are stored in a separate table to enable graph analysis (linking domains sharing certificates)
    // Batch insert: build VALUES clause for all SANs
    let query = build_batch_insert_query(
        "url_certificate_sans",
        &["url_status_id", "domain_name"],
        subject_alternative_names.len(),
        Some("ON CONFLICT(url_status_id, domain_name) DO NOTHING"),
    );

    let mut query_builder = sqlx::query(&query);
    for san in subject_alternative_names {
        query_builder = query_builder.bind(url_status_id).bind(san);
    }

    if let Err(e) = query_builder.execute(&mut **tx).await {
        log::warn!(
            "Failed to batch insert {} certificate SANs for url_status_id {}: {}",
            subject_alternative_names.len(),
            url_status_id,
            e
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;
    use std::collections::HashSet;

    use crate::storage::test_helpers::{create_test_pool, create_test_url_status_default};

    #[tokio::test]
    async fn test_insert_oids_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let mut oids = HashSet::new();
        oids.insert("1.3.6.1.4.1.311".to_string());
        oids.insert("1.2.840.113549".to_string());

        insert_oids(&mut tx, url_status_id, &oids).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify insertion
        let rows = sqlx::query("SELECT oid FROM url_oids WHERE url_status_id = ? ORDER BY oid")
            .bind(url_status_id)
            .fetch_all(&pool)
            .await
            .expect("Failed to fetch OIDs");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<String, _>("oid"), "1.2.840.113549");
        assert_eq!(rows[1].get::<String, _>("oid"), "1.3.6.1.4.1.311");
    }

    #[tokio::test]
    async fn test_insert_oids_duplicates() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let mut oids = HashSet::new();
        oids.insert("1.3.6.1.4.1.311".to_string());
        oids.insert("1.3.6.1.4.1.311".to_string()); // Duplicate (HashSet will dedupe)

        insert_oids(&mut tx, url_status_id, &oids).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify only one entry
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_oids WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count OIDs");

        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_insert_certificate_sans_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let sans = vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
            "*.example.com".to_string(),
        ];

        insert_certificate_sans(&mut tx, url_status_id, &sans).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify insertion
        let rows = sqlx::query(
            "SELECT domain_name FROM url_certificate_sans WHERE url_status_id = ? ORDER BY domain_name",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch certificate SANs");

        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].get::<String, _>("domain_name"), "*.example.com");
        assert_eq!(rows[1].get::<String, _>("domain_name"), "example.com");
        assert_eq!(rows[2].get::<String, _>("domain_name"), "www.example.com");
    }

    #[tokio::test]
    async fn test_insert_certificate_sans_duplicates() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let sans = vec![
            "example.com".to_string(),
            "example.com".to_string(), // Duplicate
        ];

        insert_certificate_sans(&mut tx, url_status_id, &sans).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify only one entry (ON CONFLICT DO NOTHING)
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_certificate_sans WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count certificate SANs");

        assert_eq!(count, 1);
    }
}
