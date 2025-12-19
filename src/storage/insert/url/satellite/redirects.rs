//! Redirect chain insertion for satellite tables.

use sqlx::Sqlite;
use sqlx::Transaction;

use super::super::super::utils::build_batch_insert_query;

/// Inserts redirect chain into url_redirect_chain table using batch insert.
pub(crate) async fn insert_redirect_chain(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    redirect_chain: &[String],
) {
    if redirect_chain.is_empty() {
        return;
    }

    // Batch insert: build VALUES clause for all redirects
    // Preserve sequence order (redirects happen in order, 1-based)
    let query = build_batch_insert_query(
        "url_redirect_chain",
        &["url_status_id", "sequence_order", "redirect_url"],
        redirect_chain.len(),
        Some("ON CONFLICT(url_status_id, sequence_order) DO UPDATE SET redirect_url=excluded.redirect_url"),
    );

    let mut query_builder = sqlx::query(&query);
    for (index, url) in redirect_chain.iter().enumerate() {
        let sequence_order = (index + 1) as i32; // 1-based ordering
        query_builder = query_builder
            .bind(url_status_id)
            .bind(sequence_order)
            .bind(url);
    }

    if let Err(e) = query_builder.execute(&mut **tx).await {
        log::warn!(
            "Failed to batch insert {} redirect chain URLs for url_status_id {}: {}",
            redirect_chain.len(),
            url_status_id,
            e
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;

    use crate::storage::test_helpers::{create_test_pool, create_test_url_status_default};

    #[tokio::test]
    async fn test_insert_redirect_chain_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let redirect_chain = vec![
            "http://example.com".to_string(),
            "https://example.com".to_string(),
            "https://www.example.com".to_string(),
        ];

        insert_redirect_chain(&mut tx, url_status_id, &redirect_chain).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify insertion with correct sequence order
        let rows = sqlx::query(
            "SELECT sequence_order, redirect_url FROM url_redirect_chain WHERE url_status_id = ? ORDER BY sequence_order",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch redirect chain");

        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].get::<i32, _>("sequence_order"), 1);
        assert_eq!(
            rows[0].get::<String, _>("redirect_url"),
            "http://example.com"
        );
        assert_eq!(rows[1].get::<i32, _>("sequence_order"), 2);
        assert_eq!(
            rows[1].get::<String, _>("redirect_url"),
            "https://example.com"
        );
        assert_eq!(rows[2].get::<i32, _>("sequence_order"), 3);
        assert_eq!(
            rows[2].get::<String, _>("redirect_url"),
            "https://www.example.com"
        );
    }
}
