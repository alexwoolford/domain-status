//! Regression: production pool `acquire_timeout` is 5s (not sqlx’s 30s default).
//!
//! `init_db_pool_with_path` sizes the pool to `--max-concurrency` and fails
//! acquire fast so workers do not park for half a minute when connections are
//! exhausted. This test uses that production constructor.

use domain_status::{
    init_db_pool_with_path, insert_url_record, run_migrations, UrlRecord, UrlRecordInsertParams,
};
use std::time::Instant;
use tempfile::NamedTempFile;
use tokio::time::Duration;

fn create_test_record(domain: &str) -> UrlRecord {
    let mut record = UrlRecord::test_default();
    record.initial_domain = domain.to_string();
    record.final_domain = domain.to_string();
    record.reverse_dns_name = Some("example.com".to_string());
    record.response_time = 0.123;
    record.title = format!("Test {domain}");
    record.description = Some("Test record".to_string());
    record.tls_version = Some(domain_status::TlsVersion::Tls13);
    record.ssl_cert_subject = Some(format!("CN={domain}"));
    record.ssl_cert_issuer = Some("CN=Test CA".to_string());
    record.timestamp = 1_704_067_200_000;
    record.run_id = Some("test-run-1".to_string());
    record
}

/// Concurrent inserts through the production pool must not wait ~30s for a connection.
#[tokio::test]
#[ignore = "contention timing; run with --ignored"]
async fn test_production_pool_acquire_timeout_fails_fast() {
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let pool = init_db_pool_with_path(temp_file.path(), 30)
        .await
        .expect("Failed to init pool");
    run_migrations(pool.as_ref())
        .await
        .expect("Failed to run migrations");

    sqlx::query("INSERT INTO runs (run_id, start_time_ms) VALUES (?, ?)")
        .bind("test-run-1")
        .bind(chrono::Utc::now().timestamp_millis())
        .execute(pool.as_ref())
        .await
        .expect("Failed to create test run");

    let mut handles = vec![];
    for i in 0..40 {
        let pool_clone = pool.clone();
        let handle = tokio::spawn(async move {
            let record = create_test_record(&format!("example-{i}.com"));
            let security_headers = std::collections::HashMap::new();
            let http_headers = std::collections::HashMap::new();
            let oids = std::collections::HashSet::new();
            let start = Instant::now();
            let result = insert_url_record(UrlRecordInsertParams::with_empty_satellites(
                pool_clone.as_ref(),
                &record,
                &security_headers,
                &http_headers,
                &oids,
            ))
            .await;
            (result.is_ok(), start.elapsed())
        });
        handles.push(handle);
    }

    let results = futures::future::join_all(handles).await;
    let mut max_wait_time = Duration::from_secs(0);
    let mut success_count = 0;
    for (ok, elapsed) in results.into_iter().flatten() {
        if elapsed > max_wait_time {
            max_wait_time = elapsed;
        }
        if ok {
            success_count += 1;
        }
    }

    assert!(
        success_count > 0,
        "expected some inserts to succeed through the production pool"
    );
    assert!(
        max_wait_time.as_secs() < 8,
        "production acquire_timeout is 5s; max wait should be <8s, got {:.2}s",
        max_wait_time.as_secs_f64()
    );
}
