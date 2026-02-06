//! Shared tests for satellite table insertions.

use std::collections::{HashMap, HashSet};

use super::{
    insert_certificate_sans, insert_http_headers, insert_mx_records, insert_nameservers,
    insert_oids, insert_redirect_chain, insert_security_headers, insert_technologies,
    insert_txt_records,
};

use crate::storage::test_helpers::{create_test_pool, create_test_url_status_default};

// Large test function handling comprehensive satellite table insertion with all empty cases.
// Consider refactoring into smaller focused test functions in Phase 4.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn test_insert_empty_collections() {
    let pool = create_test_pool().await;
    let url_status_id = create_test_url_status_default(&pool).await;

    let mut tx = pool.begin().await.expect("Failed to start transaction");

    // Test all empty cases
    insert_technologies(&mut tx, url_status_id, &[]).await;
    insert_nameservers(&mut tx, url_status_id, &None).await;
    insert_txt_records(&mut tx, url_status_id, &None).await;
    insert_mx_records(&mut tx, url_status_id, &None).await;
    insert_security_headers(&mut tx, url_status_id, &HashMap::new()).await;
    insert_http_headers(&mut tx, url_status_id, &HashMap::new()).await;
    insert_oids(&mut tx, url_status_id, &HashSet::new()).await;
    insert_redirect_chain(&mut tx, url_status_id, &[]).await;
    insert_certificate_sans(&mut tx, url_status_id, &[]).await;

    tx.commit().await.expect("Failed to commit transaction");

    // Verify no rows inserted
    let counts = vec![
        (
            "url_technologies",
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM url_technologies WHERE url_status_id = ?",
            )
            .bind(url_status_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        ),
        (
            "url_nameservers",
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM url_nameservers WHERE url_status_id = ?",
            )
            .bind(url_status_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        ),
        (
            "url_txt_records",
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM url_txt_records WHERE url_status_id = ?",
            )
            .bind(url_status_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        ),
        (
            "url_mx_records",
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM url_mx_records WHERE url_status_id = ?",
            )
            .bind(url_status_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        ),
        (
            "url_security_headers",
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM url_security_headers WHERE url_status_id = ?",
            )
            .bind(url_status_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        ),
        (
            "url_http_headers",
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM url_http_headers WHERE url_status_id = ?",
            )
            .bind(url_status_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        ),
        (
            "url_certificate_oids",
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM url_certificate_oids WHERE url_status_id = ?",
            )
            .bind(url_status_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        ),
        (
            "url_redirect_chain",
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM url_redirect_chain WHERE url_status_id = ?",
            )
            .bind(url_status_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        ),
        (
            "url_certificate_sans",
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM url_certificate_sans WHERE url_status_id = ?",
            )
            .bind(url_status_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        ),
    ];

    for (table, count) in counts {
        assert_eq!(count, 0, "Table {} should have no rows", table);
    }
}
