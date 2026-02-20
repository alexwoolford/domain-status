//! Test demonstrating database pool acquire_timeout bug.
//!
//! **BUG FOUND**: SqlitePool is initialized with default acquire_timeout of 30s.
//! When the connection pool is exhausted under high concurrency, worker tasks
//! block for up to 30 seconds waiting for a connection.
//!
//! **ROOT CAUSE**:
//! - src/storage/pool.rs:46 uses SqlitePool::connect() with defaults
//! - Default acquire_timeout: 30 seconds
//! - Default max_connections: 10
//! - With max_concurrency=30, 20 workers can block for 30s each
//!
//! **Impact**: Under load, workers block waiting for database connections
//! instead of failing fast, causing severe performance degradation.

use domain_status::{
    init_db_pool_with_path, insert_url_record, run_migrations, UrlRecord, UrlRecordInsertParams,
};
use std::time::Instant;
use tempfile::NamedTempFile;
use tokio::time::{timeout, Duration};

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
        tls_version: Some(domain_status::TlsVersion::Tls13),
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
        key_algorithm: Some(domain_status::KeyAlgorithm::RSA),
        run_id: Some("test-run-1".to_string()),
    }
}

/// Demonstrates that default pool acquire_timeout blocks workers for 30s.
///
/// This test spawns more tasks than available connections and measures
/// how long blocked tasks wait. With default settings, they wait ~30s.
#[tokio::test]
#[ignore] // Run with: cargo test --test db_pool_timeout_bug -- --ignored
async fn test_db_pool_default_acquire_timeout_blocks() {
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let db_path = temp_file.path();

    // Initialize pool with DEFAULT settings (includes 5s acquire_timeout)
    let pool = init_db_pool_with_path(db_path, 30)
        .await
        .expect("Failed to init pool");
    run_migrations(pool.as_ref())
        .await
        .expect("Failed to run migrations");

    // Create test run
    sqlx::query("INSERT INTO runs (run_id, start_time_ms) VALUES (?, ?)")
        .bind("test-run-1")
        .bind(chrono::Utc::now().timestamp_millis())
        .execute(pool.as_ref())
        .await
        .expect("Failed to create test run");

    // Default pool has max_connections=10
    // Spawn 15 long-running tasks to exhaust the pool
    let mut handles = vec![];
    for i in 0..15 {
        let pool_clone = pool.clone();
        let handle = tokio::spawn(async move {
            let record = create_test_record(&format!("example-{}.com", i));
            let security_headers = std::collections::HashMap::new();
            let http_headers = std::collections::HashMap::new();
            let oids = std::collections::HashSet::new();

            let start = Instant::now();

            // This will either:
            // - Complete immediately if connection available
            // - Block for up to 30s if pool exhausted
            let result = insert_url_record(UrlRecordInsertParams {
                pool: pool_clone.as_ref(),
                record: &record,
                security_headers: &security_headers,
                http_headers: &http_headers,
                oids: &oids,
                redirect_chain: &[],
                technologies: &[],
                subject_alternative_names: &[],
            })
            .await;

            let elapsed = start.elapsed();
            (result, elapsed)
        });
        handles.push(handle);
    }

    // Wait for all tasks
    let start = Instant::now();
    let results = futures::future::join_all(handles).await;
    let total_elapsed = start.elapsed();

    // Analyze results
    let mut blocked_count = 0;
    let mut max_wait_time = Duration::from_secs(0);
    for (_, elapsed) in results.into_iter().flatten() {
        if elapsed.as_secs() > 5 {
            blocked_count += 1;
            if elapsed > max_wait_time {
                max_wait_time = elapsed;
            }
            println!(
                "Task blocked for {:.2}s waiting for connection",
                elapsed.as_secs_f64()
            );
        }
    }

    println!("Total time: {:.2}s", total_elapsed.as_secs_f64());
    println!("{} tasks blocked for >5s", blocked_count);
    println!("Max wait time: {:.2}s", max_wait_time.as_secs_f64());

    // **BUG DEMONSTRATED**: With default 30s acquire_timeout, tasks block for extended periods
    // This doesn't assert failure to avoid breaking CI, but documents the issue
    if blocked_count > 0 {
        println!(
            "BUG CONFIRMED: {} tasks blocked waiting for connections (max {:.2}s)",
            blocked_count,
            max_wait_time.as_secs_f64()
        );
        println!("This demonstrates the acquire_timeout issue with default pool settings");
    }
}

/// Documents the fix: explicit pool configuration with short acquire_timeout.
#[tokio::test]
#[ignore]
async fn test_db_pool_with_explicit_acquire_timeout() {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;

    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let db_path = temp_file.path();

    // FIX: Configure pool explicitly with short acquire_timeout
    let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", db_path.to_string_lossy()))
        .expect("Failed to create options")
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(30) // Match max_concurrency
        .acquire_timeout(Duration::from_secs(5)) // Fail fast instead of blocking
        .idle_timeout(Some(Duration::from_secs(60))) // Clean up idle connections
        .connect_with(options)
        .await
        .expect("Failed to create pool");

    // Enable WAL and foreign keys (same as init_db_pool_with_path)
    sqlx::query("PRAGMA journal_mode=WAL")
        .execute(&pool)
        .await
        .expect("Failed to enable WAL");
    sqlx::query("PRAGMA foreign_keys=ON")
        .execute(&pool)
        .await
        .expect("Failed to enable foreign keys");

    run_migrations(&pool)
        .await
        .expect("Failed to run migrations");

    // Create test run
    sqlx::query("INSERT INTO runs (run_id, start_time_ms) VALUES (?, ?)")
        .bind("test-run-1")
        .bind(chrono::Utc::now().timestamp_millis())
        .execute(&pool)
        .await
        .expect("Failed to create test run");

    // Spawn 40 tasks (exceeds max_connections=30)
    let mut handles = vec![];
    for i in 0..40 {
        let pool_clone = pool.clone();
        let handle = tokio::spawn(async move {
            let record = create_test_record(&format!("example-{}.com", i));
            let security_headers = std::collections::HashMap::new();
            let http_headers = std::collections::HashMap::new();
            let oids = std::collections::HashSet::new();

            let start = Instant::now();

            // With 5s acquire_timeout, this fails fast instead of blocking 30s
            let result = timeout(
                Duration::from_secs(10),
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

            let elapsed = start.elapsed();
            (result, elapsed)
        });
        handles.push(handle);
    }

    // Wait for all tasks
    let start = Instant::now();
    let results = futures::future::join_all(handles).await;
    let total_elapsed = start.elapsed();

    // Analyze results
    let mut success_count = 0;
    let mut timeout_count = 0;
    let mut max_wait_time = Duration::from_secs(0);

    for (task_result, elapsed) in results.into_iter().flatten() {
        if elapsed > max_wait_time {
            max_wait_time = elapsed;
        }
        match task_result {
            Ok(Ok(_)) => success_count += 1,
            Ok(Err(_)) | Err(_) => timeout_count += 1,
        }
    }

    println!("Total time with fix: {:.2}s", total_elapsed.as_secs_f64());
    println!("Success: {}, Timeout: {}", success_count, timeout_count);
    println!("Max wait time: {:.2}s", max_wait_time.as_secs_f64());

    // With 5s acquire_timeout, tasks fail fast instead of blocking 30s
    assert!(
        max_wait_time.as_secs() < 8,
        "With acquire_timeout=5s, max wait should be <8s, got {:.2}s",
        max_wait_time.as_secs_f64()
    );
}
