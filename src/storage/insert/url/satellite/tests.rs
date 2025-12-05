//! Shared tests for satellite table insertions.

use crate::storage::migrations::run_migrations;
use sqlx::{Row, SqlitePool};
use std::collections::{HashMap, HashSet};

use super::{
    insert_certificate_sans, insert_http_headers, insert_mx_records, insert_nameservers,
    insert_oids, insert_redirect_chain, insert_security_headers, insert_technologies,
    insert_txt_records,
};

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
async fn test_insert_empty_collections() {
    let pool = create_test_pool().await;
    let url_status_id = create_test_url_status(&pool).await;

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
            "url_oids",
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM url_oids WHERE url_status_id = ?")
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
