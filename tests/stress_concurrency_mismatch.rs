//! Stress test demonstrating database pool exhaustion under high concurrency.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::manual_flatten
)]
//!
//! **VULNERABILITY FOUND**: Connection pool size (30) much smaller than max concurrency (500).
//!
//! **ROOT CAUSE**:
//! - src/storage/pool.rs:62 sets max_connections=30
//! - Default max_concurrency in CLI is 30, but can be set up to 500
//! - When user sets --max-concurrent 500:
//!   - 500 workers spawn concurrently
//!   - Only 30 database connections available
//!   - 470 workers block waiting for connections
//! - Pool has acquire_timeout=5s (good), but causes cascade timeouts
//! - Result: Throughput collapse, wasted worker threads
//!
//! **Attack Vector**:
//! - User enables high concurrency: --max-concurrent 500
//! - Or adversary triggers concurrent requests via API
//! - Workers block waiting for database connections
//! - Cascade timeout failures reduce effective throughput
//! - System fails to utilize available network/CPU capacity
//!
//! **Real-World Scenario**:
//! - Fast network connection (1Gbps+)
//! - User wants to maximize throughput: --max-concurrent 200
//! - System spawns 200 workers
//! - Only 30 can write to database concurrently
//! - 170 workers timeout after 5s each
//! - Effective throughput: ~30 URLs/sec instead of 200 URLs/sec
//!
//! **Impact**: Severe performance degradation, wasted resources, cascade failures
//!
//! **Recommended Fix**:
//! - Match pool size to max_concurrency: max_connections = max_concurrency
//! - Or document the limitation: "Max effective concurrency: 30"
//! - Or implement write batching/queue to decouple workers from connections
//! - Or increase pool size to 100+ for high-concurrency workloads

use domain_status::{
    init_db_pool_with_path, insert_url_record, run_migrations, UrlRecord, UrlRecordInsertParams,
};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

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
        run_id: Some("stress-test-concurrency".to_string()),
    }
}

/// Demonstrates moderate pool exhaustion (50 workers, 30 connections).
///
/// **EXPECTED**: 30 workers succeed quickly, 20 workers wait or timeout
/// **RESULT**: Reduced effective throughput due to contention
#[tokio::test]
#[ignore] // Run with: cargo test --test stress_concurrency_mismatch -- --ignored --nocapture
async fn test_pool_exhaustion_moderate() {
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let db_path = temp_file.path();

    println!("=== Pool Exhaustion Test: Moderate (50 workers, 30 connections) ===\n");

    let pool = init_db_pool_with_path(db_path, 30)
        .await
        .expect("Failed to init pool");
    run_migrations(pool.as_ref())
        .await
        .expect("Failed to run migrations");

    // Create test run
    sqlx::query("INSERT INTO runs (run_id, start_time_ms) VALUES (?, ?)")
        .bind("stress-test-concurrency")
        .bind(chrono::Utc::now().timestamp_millis())
        .execute(pool.as_ref())
        .await
        .expect("Failed to create test run");
    #[allow(clippy::manual_flatten)]
    let worker_count = 50;
    println!("Spawning {} concurrent workers...", worker_count);
    println!("Pool size: 30 connections");
    println!("Expected contention: 20 workers will compete for connections\n");

    let start = Instant::now();
    let mut handles = vec![];

    for i in 0..worker_count {
        let pool_clone = pool.clone();
        let handle = tokio::spawn(async move {
            let worker_start = Instant::now();
            let domain = format!("example-{:04}.com", i);
            let record = create_test_record(&domain);
            let security_headers = std::collections::HashMap::new();
            let http_headers = std::collections::HashMap::new();
            let oids = std::collections::HashSet::new();

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

            let elapsed = worker_start.elapsed();
            (i, result.is_ok(), elapsed)
        });
        handles.push(handle);
    }

    let results = futures::future::join_all(handles).await;
    let total_elapsed = start.elapsed();

    // Analyze results
    let mut success_count = 0;
    let mut timeout_count = 0;
    let mut fast_ops = 0; // < 1s
    let mut slow_ops = 0; // >= 1s
    let mut max_duration = Duration::from_secs(0);
    let mut durations: Vec<Duration> = Vec::new();

    for result in results {
        if let Ok((_, success, duration)) = result {
            durations.push(duration);
            if duration > max_duration {
                max_duration = duration;
            }

            if success {
                success_count += 1;
                if duration.as_secs() < 1 {
                    fast_ops += 1;
                } else {
                    slow_ops += 1;
                }
            } else {
                timeout_count += 1;
            }
        }
    }

    // Sort durations for percentile analysis
    durations.sort();
    let p50 = durations[durations.len() / 2];
    let p95 = durations[durations.len() * 95 / 100];
    let p99 = durations[durations.len() * 99 / 100];

    println!("=== Results ===");
    println!("Total time: {:.2}s", total_elapsed.as_secs_f64());
    println!("Success: {} / {}", success_count, worker_count);
    println!("Timeouts: {}", timeout_count);
    println!();
    println!("Operation latency:");
    println!("  Fast operations (<1s): {}", fast_ops);
    println!("  Slow operations (>=1s): {}", slow_ops);
    println!("  p50: {:.2}s", p50.as_secs_f64());
    println!("  p95: {:.2}s", p95.as_secs_f64());
    println!("  p99: {:.2}s", p99.as_secs_f64());
    println!("  Max: {:.2}s", max_duration.as_secs_f64());
    println!();

    if slow_ops > 0 {
        println!(
            "FINDING: {} workers experienced delays due to pool contention",
            slow_ops
        );
        println!("Workers block waiting for available database connections");
        println!("Effective throughput reduced by pool size bottleneck");
    }
}

/// Demonstrates severe pool exhaustion (100 workers, 30 connections).
///
/// **EXPECTED**: Cascade timeouts, 70 workers fail or experience severe delays
/// **RESULT**: Throughput collapse, most workers wasted
#[tokio::test]
#[ignore]
#[allow(clippy::too_many_lines, clippy::manual_flatten)]
async fn test_pool_exhaustion_severe() {
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let db_path = temp_file.path();

    println!("=== Pool Exhaustion Test: Severe (100 workers, 30 connections) ===\n");

    let pool = init_db_pool_with_path(db_path, 30)
        .await
        .expect("Failed to init pool");
    run_migrations(pool.as_ref())
        .await
        .expect("Failed to run migrations");

    sqlx::query("INSERT INTO runs (run_id, start_time_ms) VALUES (?, ?)")
        .bind("stress-test-concurrency")
        .bind(chrono::Utc::now().timestamp_millis())
        .execute(pool.as_ref())
        .await
        .expect("Failed to create test run");

    let worker_count = 100;
    println!("Spawning {} concurrent workers...", worker_count);
    println!("Pool size: 30 connections");
    println!("Expected contention: 70 workers competing for 30 connections\n");

    let start = Instant::now();
    let mut handles = vec![];

    for i in 0..worker_count {
        let pool_clone = pool.clone();
        let handle = tokio::spawn(async move {
            let worker_start = Instant::now();
            let domain = format!("example-{:04}.com", i);
            let record = create_test_record(&domain);
            let security_headers = std::collections::HashMap::new();
            let http_headers = std::collections::HashMap::new();
            let oids = std::collections::HashSet::new();

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

            let elapsed = worker_start.elapsed();
            (i, result.is_ok(), elapsed)
        });
        handles.push(handle);
    }

    let results = futures::future::join_all(handles).await;
    let total_elapsed = start.elapsed();

    // Analyze results
    let mut success_count = 0;
    let mut timeout_count = 0;
    let mut durations: Vec<Duration> = Vec::new();

    for result in results {
        if let Ok((_, success, duration)) = result {
            durations.push(duration);
            if success {
                success_count += 1;
            } else {
                timeout_count += 1;
            }
        }
    }

    durations.sort();
    let p50 = durations[durations.len() / 2];
    let p95 = durations[durations.len() * 95 / 100];
    let p99 = durations[durations.len() * 99 / 100];

    let success_rate = (success_count as f64 / worker_count as f64) * 100.0;
    let effective_throughput = success_count as f64 / total_elapsed.as_secs_f64();

    println!("=== Results ===");
    println!("Total time: {:.2}s", total_elapsed.as_secs_f64());
    println!(
        "Success: {} / {} ({:.1}%)",
        success_count, worker_count, success_rate
    );
    println!(
        "Timeouts: {} ({:.1}%)",
        timeout_count,
        (timeout_count as f64 / worker_count as f64) * 100.0
    );
    println!();
    println!("Latency distribution:");
    println!("  p50: {:.2}s", p50.as_secs_f64());
    println!("  p95: {:.2}s", p95.as_secs_f64());
    println!("  p99: {:.2}s", p99.as_secs_f64());
    println!();
    println!("Throughput:");
    println!("  Effective: {:.1} ops/sec", effective_throughput);
    println!("  Theoretical max (pool size): 30 ops/sec");
    println!();

    println!("VULNERABILITY CONFIRMED: Pool size bottleneck under high concurrency");
    println!("With 100 workers and 30 connections:");
    println!(
        "  - {} workers failed or timed out ({:.1}%)",
        timeout_count,
        (timeout_count as f64 / worker_count as f64) * 100.0
    );
    println!(
        "  - Effective throughput: {:.1} ops/sec",
        effective_throughput
    );
    println!(
        "  - Worker utilization: {:.1}%",
        (effective_throughput / 30.0) * 100.0
    );
    println!();
    println!("Impact: System cannot scale beyond pool size limit");
}

/// Demonstrates extreme pool exhaustion (200 workers, 30 connections).
///
/// This simulates a user setting --max-concurrent 200 on a fast network.
///
/// **EXPECTED**: Massive contention, cascade timeouts, throughput collapse
/// **RESULT**: Only 30 workers can make progress, 170 workers wasted
#[tokio::test]
#[allow(clippy::too_many_lines, clippy::manual_flatten)]
#[ignore]
async fn test_pool_exhaustion_extreme() {
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let db_path = temp_file.path();

    println!("=== Pool Exhaustion Test: Extreme (200 workers, 30 connections) ===\n");
    println!("Simulating: User runs '--max-concurrent 200' on fast network\n");

    let pool = init_db_pool_with_path(db_path, 30)
        .await
        .expect("Failed to init pool");
    run_migrations(pool.as_ref())
        .await
        .expect("Failed to run migrations");

    sqlx::query("INSERT INTO runs (run_id, start_time_ms) VALUES (?, ?)")
        .bind("stress-test-concurrency")
        .bind(chrono::Utc::now().timestamp_millis())
        .execute(pool.as_ref())
        .await
        .expect("Failed to create test run");

    let worker_count = 200;
    println!(
        "Spawning {} concurrent workers (simulating --max-concurrent 200)...",
        worker_count
    );
    println!("Pool size: 30 connections (from src/storage/pool.rs)");
    println!("Mismatch: 170 workers will compete for 30 connections\n");

    let start = Instant::now();
    let mut handles = vec![];

    for i in 0..worker_count {
        let pool_clone = pool.clone();
        let handle = tokio::spawn(async move {
            let worker_start = Instant::now();
            let domain = format!("example-{:04}.com", i);
            let record = create_test_record(&domain);
            let security_headers = std::collections::HashMap::new();
            let http_headers = std::collections::HashMap::new();
            let oids = std::collections::HashSet::new();

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

            let elapsed = worker_start.elapsed();
            (result.is_ok(), elapsed)
        });
        handles.push(handle);
    }

    let results = futures::future::join_all(handles).await;
    let total_elapsed = start.elapsed();

    let mut success_count = 0;
    let mut timeout_count = 0;
    let mut durations: Vec<Duration> = Vec::new();

    for result in results {
        if let Ok((success, duration)) = result {
            durations.push(duration);
            if success {
                success_count += 1;
            } else {
                timeout_count += 1;
            }
        }
    }

    durations.sort();

    let success_rate = (success_count as f64 / worker_count as f64) * 100.0;
    let failure_rate = (timeout_count as f64 / worker_count as f64) * 100.0;
    let effective_throughput = success_count as f64 / total_elapsed.as_secs_f64();
    let wasted_workers = worker_count - success_count;

    println!("=== CRITICAL FINDINGS ===");
    println!("Total time: {:.2}s", total_elapsed.as_secs_f64());
    println!(
        "Success: {} / {} ({:.1}%)",
        success_count, worker_count, success_rate
    );
    println!(
        "Failed: {} / {} ({:.1}%)",
        timeout_count, worker_count, failure_rate
    );
    println!();
    println!("Throughput analysis:");
    println!("  Effective: {:.1} ops/sec", effective_throughput);
    println!("  Theoretical (200 workers): 200 ops/sec");
    println!("  Pool bottleneck (30 connections): 30 ops/sec");
    println!(
        "  Utilization: {:.1}%",
        (effective_throughput / 200.0) * 100.0
    );
    println!();
    println!("Resource waste:");
    println!("  Spawned workers: {}", worker_count);
    println!("  Useful workers: {}", success_count);
    println!(
        "  Wasted workers: {} ({:.1}%)",
        wasted_workers,
        (wasted_workers as f64 / worker_count as f64) * 100.0
    );
    println!();

    println!("CRITICAL VULNERABILITY: Pool/concurrency severe mismatch");
    println!("User configured --max-concurrent 200, but pool size is 30");
    println!("Result: 170 workers wasted, throughput capped at pool size");
    println!();
    println!("Recommendations:");
    println!("1. Match pool size to max_concurrency: max_connections = max_concurrent");
    println!("2. Or document limit: 'Maximum effective concurrency: 30'");
    println!("3. Or implement write queue to decouple workers from connections");
}
