//! Adversarial Resiliency Tests - DESIGNED TO BREAK THE SYSTEM
//!
//! These tests are intentionally aggressive and try to exploit potential weaknesses:
//! - Connection pool exhaustion during rollbacks
//! - Race conditions between checkpoints and transactions
//! - Resource leaks from cancelled tasks
//! - Deadlocks from concurrent operations
//!
//! **If these tests pass, we haven't found the bugs yet. Keep trying harder.**

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use domain_status::{insert_url_record, run_migrations, UrlRecord, UrlRecordInsertParams};
use sqlx::SqlitePool;
use tokio::time::{sleep, timeout};

//-----------------------------------------------------------------------------
// Test Helpers
//-----------------------------------------------------------------------------

async fn create_test_pool_with_limits(max_connections: u32) -> SqlitePool {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;

    let options = SqliteConnectOptions::from_str("sqlite::memory:")
        .expect("Failed to create options")
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await
        .expect("Failed to create pool");

    run_migrations(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}

fn create_test_record(domain: &str) -> UrlRecord {
    use chrono::NaiveDate;

    UrlRecord {
        initial_domain: domain.to_string(),
        final_domain: domain.to_string(),
        ip_address: "93.184.216.34".to_string(),
        reverse_dns_name: Some("example.com".to_string()),
        status: 200,
        status_desc: "OK".to_string(),
        response_time: 0.123,
        title: format!("Test {}", domain),
        keywords: Some("test".to_string()),
        description: Some("Test record".to_string()),
        tls_version: Some("TLSv1.3".to_string()),
        ssl_cert_subject: Some(format!("CN={}", domain)),
        ssl_cert_issuer: Some("CN=Test CA".to_string()),
        ssl_cert_valid_from: NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0),
        ssl_cert_valid_to: NaiveDate::from_ymd_opt(2025, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0),
        is_mobile_friendly: true,
        timestamp: chrono::Utc::now().timestamp_millis(),
        nameservers: Some(r#"["ns1.example.com"]"#.to_string()),
        txt_records: Some(r#"["v=spf1 include:_spf.example.com ~all"]"#.to_string()),
        mx_records: Some(r#"[{"priority": 10, "hostname": "mail.example.com"}]"#.to_string()),
        spf_record: Some("v=spf1 include:_spf.example.com ~all".to_string()),
        dmarc_record: Some("v=DMARC1; p=quarantine".to_string()),
        cipher_suite: Some("TLS_AES_128_GCM_SHA256".to_string()),
        key_algorithm: Some("RSA".to_string()),
        run_id: Some("test-run-1".to_string()),
    }
}

async fn create_test_run(pool: &SqlitePool, run_id: &str) {
    sqlx::query("INSERT INTO runs (run_id, start_time_ms) VALUES (?, ?) ON CONFLICT DO NOTHING")
        .bind(run_id)
        .bind(chrono::Utc::now().timestamp_millis())
        .execute(pool)
        .await
        .expect("Failed to create test run");
}

//-----------------------------------------------------------------------------
// ATTACK 1: Connection Pool Exhaustion During Rollback
//-----------------------------------------------------------------------------
// Hypothesis: If all connections are busy, cancelled tasks can't rollback
// and will deadlock waiting for a connection.
//
// Expected: This test should HANG or PANIC if the bug exists.

#[tokio::test]
#[ignore] // Remove ignore to run this test
async fn test_connection_pool_exhaustion_during_cancellation() {
    // Create pool with VERY limited connections (same as max workers)
    let pool = create_test_pool_with_limits(5).await;
    create_test_run(&pool, "test-run-1").await;

    // Spawn MORE tasks than available connections
    let mut tasks = Vec::new();
    for i in 0..10 {
        let pool_clone = pool.clone();
        let task = tokio::spawn(async move {
            let record = create_test_record(&format!("example-{}.com", i));
            let security_headers = std::collections::HashMap::new();
            let http_headers = std::collections::HashMap::new();
            let oids = std::collections::HashSet::new();

            // Cancel after tiny delay - should trigger rollback
            timeout(
                Duration::from_micros(100),
                insert_url_record(UrlRecordInsertParams {
                    pool: &pool_clone,
                    record: &record,
                    security_headers: &security_headers,
                    http_headers: &http_headers,
                    oids: &oids,
                    redirect_chain: &[],
                    technologies: &[],
                    subject_alternative_names: &[],
                }),
            )
            .await
        });
        tasks.push(task);
    }

    // Wait for all tasks with timeout - if deadlock occurs, this will panic
    let result =
        tokio::time::timeout(Duration::from_secs(5), futures::future::join_all(tasks)).await;

    assert!(
        result.is_ok(),
        "DEADLOCK DETECTED: Tasks didn't complete within timeout"
    );

    // Verify database is still responsive
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM url_status")
        .fetch_one(&pool)
        .await
        .expect("Database should still be responsive");

    // Should have 0 or very few records (most cancelled)
    assert!(count.0 < 10, "Most inserts should have been cancelled");
}

//-----------------------------------------------------------------------------
// ATTACK 2: Checkpoint While Transactions Are Active
//-----------------------------------------------------------------------------
// Hypothesis: PRAGMA wal_checkpoint(TRUNCATE) requires exclusive lock.
// If transactions are active, checkpoint might block them or vice versa.
//
// Expected: This test should DEADLOCK or cause database corruption.

#[tokio::test]
#[ignore] // Remove ignore to run this test
async fn test_checkpoint_during_active_transactions() {
    let pool = create_test_pool_with_limits(10).await;
    create_test_run(&pool, "test-run-1").await;

    let checkpoint_pool = pool.clone();

    // Start aggressive checkpoint loop
    let checkpoint_task = tokio::spawn(async move {
        for _i in 0..20 {
            let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
                .execute(&checkpoint_pool)
                .await;

            // Checkpoint very frequently to maximize conflict probability
            sleep(Duration::from_millis(5)).await;
        }
    });

    // Simultaneously start many long-running transactions
    let mut write_tasks = Vec::new();
    for i in 0..20 {
        let pool_clone = pool.clone();
        let task = tokio::spawn(async move {
            let record = create_test_record(&format!("checkpoint-{}.com", i));
            let security_headers = std::collections::HashMap::new();
            let http_headers = std::collections::HashMap::new();
            let oids = std::collections::HashSet::new();

            insert_url_record(UrlRecordInsertParams {
                pool: &pool_clone,
                record: &record,
                security_headers: &security_headers,
                http_headers: &http_headers,
                oids: &oids,
                redirect_chain: &[],
                technologies: &[],
                subject_alternative_names: &[],
            })
            .await
        });
        write_tasks.push(task);
    }

    // Both checkpoint and writes should complete without deadlock
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        futures::future::join_all(write_tasks),
    )
    .await;

    assert!(result.is_ok(), "DEADLOCK: Checkpoint and writes deadlocked");

    checkpoint_task.abort(); // Stop checkpointing

    // Verify database integrity
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM url_status")
        .fetch_one(&pool)
        .await
        .expect("Database corrupted after checkpoint collision");

    println!(
        "Successfully inserted {} records during aggressive checkpointing",
        count.0
    );
}

//-----------------------------------------------------------------------------
// ATTACK 3: Cascade Cancellation During Satellite Writes
//-----------------------------------------------------------------------------
// Hypothesis: If we cancel EXACTLY during satellite writes (after main insert
// but before satellites), we might get partial data.
//
// Expected: Should find orphaned satellite records or foreign key violations.

#[tokio::test]
#[ignore] // Remove ignore to run this test
async fn test_cascade_cancellation_timing_attack() {
    let pool = create_test_pool_with_limits(10).await;
    create_test_run(&pool, "test-run-1").await;

    let success_count = Arc::new(AtomicU64::new(0));
    let cancel_count = Arc::new(AtomicU64::new(0));

    // Run 100 iterations to increase probability of hitting the timing window
    for iteration in 0..100 {
        let pool_clone = pool.clone();
        let success = success_count.clone();
        let cancel = cancel_count.clone();

        let task = tokio::spawn(async move {
            let record = create_test_record(&format!("timing-{}.com", iteration));
            let mut security_headers = std::collections::HashMap::new();
            security_headers.insert("X-Frame-Options".to_string(), "DENY".to_string());

            let mut http_headers = std::collections::HashMap::new();
            http_headers.insert("Content-Type".to_string(), "text/html".to_string());

            let oids = std::collections::HashSet::new();

            // Use variable timeout to hit different timing windows
            let timeout_micros = 10 + (iteration % 50);

            let result = timeout(
                Duration::from_micros(timeout_micros),
                insert_url_record(UrlRecordInsertParams {
                    pool: &pool_clone,
                    record: &record,
                    security_headers: &security_headers,
                    http_headers: &http_headers,
                    oids: &oids,
                    redirect_chain: &[],
                    technologies: &[],
                    subject_alternative_names: &[],
                }),
            )
            .await;

            match result {
                Ok(Ok(_)) => success.fetch_add(1, Ordering::Relaxed),
                _ => cancel.fetch_add(1, Ordering::Relaxed),
            };
        });

        let _ = task.await;
    }

    println!(
        "Success: {}, Cancelled: {}",
        success_count.load(Ordering::Relaxed),
        cancel_count.load(Ordering::Relaxed)
    );

    // Check for orphaned satellite records (CRITICAL BUG if found)
    let orphaned_headers: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM url_security_headers
         WHERE url_status_id NOT IN (SELECT id FROM url_status)",
    )
    .fetch_one(&pool)
    .await
    .expect("Failed to check for orphans");

    assert_eq!(
        orphaned_headers.0, 0,
        "BUG FOUND: {} orphaned security_headers records exist!",
        orphaned_headers.0
    );

    let orphaned_http: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM url_http_headers
         WHERE url_status_id NOT IN (SELECT id FROM url_status)",
    )
    .fetch_one(&pool)
    .await
    .expect("Failed to check for orphans");

    assert_eq!(
        orphaned_http.0, 0,
        "BUG FOUND: {} orphaned http_headers records exist!",
        orphaned_http.0
    );
}

//-----------------------------------------------------------------------------
// ATTACK 4: Resource Leak Detection
//-----------------------------------------------------------------------------
// Hypothesis: Cancelled tasks might leak connections, not properly releasing
// them back to the pool.
//
// Expected: Pool should become exhausted and hang.

#[tokio::test]
#[ignore] // Remove ignore to run this test
async fn test_connection_leak_from_cancellations() {
    let pool = create_test_pool_with_limits(3).await; // Very small pool
    create_test_run(&pool, "test-run-1").await;

    // Cancel 100 tasks - if connections leak, pool will be exhausted
    for i in 0..100 {
        let pool_clone = pool.clone();
        let task = tokio::spawn(async move {
            let record = create_test_record(&format!("leak-{}.com", i));
            let security_headers = std::collections::HashMap::new();
            let http_headers = std::collections::HashMap::new();
            let oids = std::collections::HashSet::new();

            timeout(
                Duration::from_micros(1),
                insert_url_record(UrlRecordInsertParams {
                    pool: &pool_clone,
                    record: &record,
                    security_headers: &security_headers,
                    http_headers: &http_headers,
                    oids: &oids,
                    redirect_chain: &[],
                    technologies: &[],
                    subject_alternative_names: &[],
                }),
            )
            .await
        });

        let _ = task.await;
    }

    // If connections were leaked, this will hang waiting for a connection
    let record = create_test_record("final-test.com");
    let security_headers = std::collections::HashMap::new();
    let http_headers = std::collections::HashMap::new();
    let oids = std::collections::HashSet::new();

    let final_insert = tokio::time::timeout(
        Duration::from_secs(2),
        insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &[],
            technologies: &[],
            subject_alternative_names: &[],
        }),
    )
    .await;

    assert!(
        final_insert.is_ok(),
        "BUG FOUND: Connection leak detected - final insert timed out waiting for connection"
    );
}

//-----------------------------------------------------------------------------
// ATTACK 5: Concurrent Reads During Rollback
//-----------------------------------------------------------------------------
// Hypothesis: Reading from a table while a transaction is rolling back
// might expose partial/inconsistent data.
//
// Expected: Reads should see consistent snapshots (all or nothing).

#[tokio::test]
#[ignore] // Remove ignore to run this test
async fn test_read_consistency_during_rollback() {
    let pool = create_test_pool_with_limits(10).await;
    create_test_run(&pool, "test-run-1").await;

    let inconsistencies = Arc::new(AtomicU64::new(0));

    // Spawn writer that will be cancelled
    for i in 0..50 {
        let pool_clone = pool.clone();
        let write_task = tokio::spawn(async move {
            let record = create_test_record(&format!("consistency-{}.com", i));
            let security_headers = std::collections::HashMap::new();
            let http_headers = std::collections::HashMap::new();
            let oids = std::collections::HashSet::new();

            timeout(
                Duration::from_micros(50),
                insert_url_record(UrlRecordInsertParams {
                    pool: &pool_clone,
                    record: &record,
                    security_headers: &security_headers,
                    http_headers: &http_headers,
                    oids: &oids,
                    redirect_chain: &[],
                    technologies: &[],
                    subject_alternative_names: &[],
                }),
            )
            .await
        });

        // Simultaneously spawn readers checking for consistency
        let read_pool = pool.clone();
        let inconsistency_counter = inconsistencies.clone();
        let read_task = tokio::spawn(async move {
            // Check if url_status count matches url_security_headers grouped count
            let url_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM url_status")
                .fetch_one(&read_pool)
                .await
                .unwrap_or((0,));

            let header_parents: (i64,) =
                sqlx::query_as("SELECT COUNT(DISTINCT url_status_id) FROM url_security_headers")
                    .fetch_one(&read_pool)
                    .await
                    .unwrap_or((0,));

            // If there are headers but no corresponding url_status, we have inconsistency
            if header_parents.0 > url_count.0 {
                inconsistency_counter.fetch_add(1, Ordering::Relaxed);
            }
        });

        let _ = tokio::join!(write_task, read_task);
    }

    let inconsistency_count = inconsistencies.load(Ordering::Relaxed);
    assert_eq!(
        inconsistency_count, 0,
        "BUG FOUND: {} read inconsistencies detected during rollbacks",
        inconsistency_count
    );
}
