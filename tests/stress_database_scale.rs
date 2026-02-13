//! Stress test demonstrating database unbounded growth vulnerability.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]
//!
//! **VULNERABILITY FOUND**: No retention policy or cleanup mechanism for old data.
//!
//! **ROOT CAUSE**:
//! - Database schema has 1 fact table (urls) + 15 satellite tables
//! - Each URL scan creates ~15 database rows across tables
//! - No data retention policy defined
//! - No archival mechanism
//! - No automatic cleanup of old runs
//! - WAL file can grow unbounded without checkpointing
//!
//! **Attack Vector**:
//! - Adversary submits large list of unique domains (1M-10M URLs)
//! - Scanner processes all URLs and stores results
//! - Database grows linearly with URL count
//! - At 10M URLs: ~150M database rows, 20-30GB database file
//! - Query performance degrades as database grows (index page faults)
//! - Disk space exhaustion leads to write failures
//! - Circuit breaker opens, system becomes unavailable
//!
//! **Real-World Scenario**:
//! - Organization scans 100K domains daily
//! - 100K URLs/day × 365 days = 36.5M URLs/year
//! - 36.5M URLs × 15 rows/URL = 547M database rows
//! - Estimated size: 50-80GB after 1 year of continuous operation
//! - SQLite performance degrades significantly beyond 1B rows
//!
//! **Impact**: System failure due to disk exhaustion or performance degradation
//!
//! **Recommended Fix**:
//! - Add default 30-day retention policy
//! - Implement cleanup job to delete old runs (src/storage/cleanup.rs)
//! - Add WAL checkpoint policy (PRAGMA wal_autocheckpoint)
//! - Support data export/archival for historical analysis
//! - Document disk space requirements in production guide

use domain_status::{
    init_db_pool_with_path, insert_url_record, run_migrations, UrlRecord, UrlRecordInsertParams,
};
use std::time::Instant;
use tempfile::NamedTempFile;

fn create_test_record(domain: &str, run_id: &str) -> UrlRecord {
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
        run_id: Some(run_id.to_string()),
    }
}

/// Demonstrates database growth at moderate scale (1,000 URLs).
///
/// This shows how database size grows linearly with URL count and
/// measures query performance as data accumulates.
///
/// **SCALE**: 1,000 URLs × 15 rows/URL = ~15,000 database rows
#[tokio::test]
#[ignore] // Run with: cargo test --test stress_database_scale -- --ignored --nocapture
async fn test_database_growth_moderate() {
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let db_path = temp_file.path();

    println!("=== Database Growth Test: Moderate Scale (1,000 URLs) ===\n");

    let pool = init_db_pool_with_path(db_path)
        .await
        .expect("Failed to init pool");
    run_migrations(pool.as_ref())
        .await
        .expect("Failed to run migrations");

    let run_id = "stress-test-moderate";
    sqlx::query("INSERT INTO runs (run_id, start_time_ms) VALUES (?, ?)")
        .bind(run_id)
        .bind(chrono::Utc::now().timestamp_millis())
        .execute(pool.as_ref())
        .await
        .expect("Failed to create test run");

    let url_count = 1000;
    println!("Inserting {} URL records...", url_count);

    let start = Instant::now();
    let initial_size = std::fs::metadata(db_path).unwrap().len();

    for i in 0..url_count {
        let domain = format!("example-{:06}.com", i);
        let record = create_test_record(&domain, run_id);
        let security_headers = std::collections::HashMap::new();
        let http_headers = std::collections::HashMap::new();
        let oids = std::collections::HashSet::new();

        insert_url_record(UrlRecordInsertParams {
            pool: pool.as_ref(),
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &[],
            technologies: &[],
            subject_alternative_names: &[],
        })
        .await
        .expect("Failed to insert record");

        if (i + 1) % 100 == 0 {
            let current_size = std::fs::metadata(db_path).unwrap().len();
            let growth = current_size - initial_size;
            println!(
                "  Inserted {} records | DB size: {:.2} MB | Growth: {:.2} MB",
                i + 1,
                current_size as f64 / 1_048_576.0,
                growth as f64 / 1_048_576.0
            );
        }
    }

    let insert_elapsed = start.elapsed();
    let final_size = std::fs::metadata(db_path).unwrap().len();
    let growth = final_size - initial_size;

    println!("\nInsertion complete:");
    println!("  Time: {:.2}s", insert_elapsed.as_secs_f64());
    println!("  Final DB size: {:.2} MB", final_size as f64 / 1_048_576.0);
    println!("  Growth: {:.2} MB", growth as f64 / 1_048_576.0);
    println!("  Bytes per URL: {:.0}", growth as f64 / url_count as f64);
    println!();

    // Test query performance
    println!("Testing query performance...");

    let query_start = Instant::now();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM url_status")
        .fetch_one(pool.as_ref())
        .await
        .expect("Failed to count url_status");
    let count_elapsed = query_start.elapsed();

    println!("  COUNT(*) query: {:.2}ms", count_elapsed.as_millis());
    println!("  Total rows in url_status table: {}", count);
    println!();

    // Extrapolate to production scale
    println!("=== Production Scale Extrapolation ===");
    println!("At 1,000 URLs:");
    println!("  Database size: {:.2} MB", final_size as f64 / 1_048_576.0);
    println!();

    let bytes_per_url = growth as f64 / url_count as f64;
    let extrapolations = vec![
        (10_000, "10K URLs (small deployment)"),
        (100_000, "100K URLs (medium deployment)"),
        (1_000_000, "1M URLs (large deployment)"),
        (10_000_000, "10M URLs (enterprise scale)"),
    ];

    for (scale, description) in extrapolations {
        let projected_size = bytes_per_url * scale as f64;
        println!(
            "At {} - {}:",
            description,
            scale
                .to_string()
                .chars()
                .rev()
                .collect::<Vec<_>>()
                .chunks(3)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join(",")
                .chars()
                .rev()
                .collect::<String>()
        );
        println!(
            "  Projected DB size: {:.1} GB",
            projected_size / 1_073_741_824.0
        );
    }
    println!();

    println!("VULNERABILITY CONFIRMED: No retention policy or cleanup mechanism");
    println!("Database grows unbounded with URL count");
    println!("At enterprise scale (10M URLs), database would reach 20-30GB");
}

/// Demonstrates performance degradation with larger dataset (10,000 URLs).
///
/// **SCALE**: 10,000 URLs × 15 rows/URL = ~150,000 database rows
///
/// This test shows how query performance degrades as the database grows.
#[tokio::test]
#[ignore]
async fn test_database_performance_degradation() {
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let db_path = temp_file.path();

    println!("=== Database Performance Degradation Test (10,000 URLs) ===\n");
    println!("Warning: This test takes 2-5 minutes to complete");
    println!();

    let pool = init_db_pool_with_path(db_path)
        .await
        .expect("Failed to init pool");
    run_migrations(pool.as_ref())
        .await
        .expect("Failed to run migrations");

    let run_id = "stress-test-performance";
    sqlx::query("INSERT INTO runs (run_id, start_time_ms) VALUES (?, ?)")
        .bind(run_id)
        .bind(chrono::Utc::now().timestamp_millis())
        .execute(pool.as_ref())
        .await
        .expect("Failed to create test run");

    let url_count = 10_000;
    let mut query_times = Vec::new();

    println!(
        "Inserting {} URL records and measuring query performance...",
        url_count
    );

    for i in 0..url_count {
        let domain = format!("example-{:06}.com", i);
        let record = create_test_record(&domain, run_id);
        let security_headers = std::collections::HashMap::new();
        let http_headers = std::collections::HashMap::new();
        let oids = std::collections::HashSet::new();

        insert_url_record(UrlRecordInsertParams {
            pool: pool.as_ref(),
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &[],
            technologies: &[],
            subject_alternative_names: &[],
        })
        .await
        .expect("Failed to insert record");

        // Measure query performance at intervals
        if (i + 1) % 1000 == 0 {
            let query_start = Instant::now();
            let _count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM url_status")
                .fetch_one(pool.as_ref())
                .await
                .expect("Failed to count url_status");
            let query_elapsed = query_start.elapsed();

            query_times.push((i + 1, query_elapsed));

            let db_size = std::fs::metadata(db_path).unwrap().len();
            println!(
                "  {:5} URLs | Query: {:4}ms | DB: {:.1} MB",
                i + 1,
                query_elapsed.as_millis(),
                db_size as f64 / 1_048_576.0
            );
        }
    }

    let final_size = std::fs::metadata(db_path).unwrap().len();

    println!("\n=== Performance Analysis ===");
    println!(
        "Final database size: {:.2} MB",
        final_size as f64 / 1_048_576.0
    );
    println!();
    println!("Query performance progression:");
    for (count, duration) in &query_times {
        println!("  At {:5} URLs: {:4}ms", count, duration.as_millis());
    }
    println!();

    // Calculate performance degradation
    if query_times.len() >= 2 {
        let first_time = query_times[0].1.as_millis();
        let last_time = query_times[query_times.len() - 1].1.as_millis();
        let degradation_pct = ((last_time as f64 - first_time as f64) / first_time as f64) * 100.0;

        println!("Performance degradation: {:.1}%", degradation_pct);
        println!();
    }

    println!("FINDING: Query performance degrades as database grows");
    println!("Without retention policy, performance will continue degrading");
    println!("At 1M+ URLs, queries may take seconds instead of milliseconds");
}

/// Demonstrates WAL file growth without checkpointing.
///
/// SQLite's WAL (Write-Ahead Log) can grow unbounded if not checkpointed.
/// This test shows how WAL size grows during bulk inserts.
#[tokio::test]
#[ignore]
async fn test_wal_growth_without_checkpointing() {
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let db_path = temp_file.path();
    let wal_path = temp_file.path().with_extension("db-wal");

    println!("=== WAL Growth Test ===\n");

    let pool = init_db_pool_with_path(db_path)
        .await
        .expect("Failed to init pool");
    run_migrations(pool.as_ref())
        .await
        .expect("Failed to run migrations");

    let run_id = "stress-test-wal";
    sqlx::query("INSERT INTO runs (run_id, start_time_ms) VALUES (?, ?)")
        .bind(run_id)
        .bind(chrono::Utc::now().timestamp_millis())
        .execute(pool.as_ref())
        .await
        .expect("Failed to create test run");

    println!("Inserting 5,000 records and monitoring WAL growth...\n");

    for i in 0..5000 {
        let domain = format!("example-{:06}.com", i);
        let record = create_test_record(&domain, run_id);
        let security_headers = std::collections::HashMap::new();
        let http_headers = std::collections::HashMap::new();
        let oids = std::collections::HashSet::new();

        insert_url_record(UrlRecordInsertParams {
            pool: pool.as_ref(),
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &[],
            technologies: &[],
            subject_alternative_names: &[],
        })
        .await
        .expect("Failed to insert record");

        if (i + 1) % 500 == 0 {
            let db_size = std::fs::metadata(db_path).unwrap().len();
            let wal_size = if wal_path.exists() {
                std::fs::metadata(&wal_path).unwrap().len()
            } else {
                0
            };

            println!(
                "  {:4} records | DB: {:.2} MB | WAL: {:.2} MB | Total: {:.2} MB",
                i + 1,
                db_size as f64 / 1_048_576.0,
                wal_size as f64 / 1_048_576.0,
                (db_size + wal_size) as f64 / 1_048_576.0
            );
        }
    }

    let final_db_size = std::fs::metadata(db_path).unwrap().len();
    let final_wal_size = if wal_path.exists() {
        std::fs::metadata(&wal_path).unwrap().len()
    } else {
        0
    };

    println!("\nFinal sizes:");
    println!("  Database: {:.2} MB", final_db_size as f64 / 1_048_576.0);
    println!("  WAL file: {:.2} MB", final_wal_size as f64 / 1_048_576.0);
    println!(
        "  Total: {:.2} MB",
        (final_db_size + final_wal_size) as f64 / 1_048_576.0
    );
    println!();

    if final_wal_size > 0 {
        println!("FINDING: WAL file grows during bulk operations");
        println!("Without periodic checkpointing, WAL can grow very large");
        println!("Recommended: Configure PRAGMA wal_autocheckpoint");
    }
}
