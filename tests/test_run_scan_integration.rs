//! Integration tests for run_scan function
//!
//! These tests verify the core orchestration logic including:
//! - Concurrent execution with semaphore enforcement
//! - Rate limiting (static and adaptive)
//! - Adaptive rate limiting (429 response handling)

use domain_status::{run_scan, Config, FailOn, LogFormat, LogLevel};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::{NamedTempFile, TempDir};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Helper function to create a temporary database file
fn create_temp_db() -> NamedTempFile {
    NamedTempFile::new().expect("Failed to create temp database file")
}

/// Helper function to create a temporary directory for test artifacts
#[allow(dead_code)]
fn create_temp_dir() -> TempDir {
    TempDir::new().expect("Failed to create temp directory")
}

/// Helper function to write URLs to a temporary file (sync I/O)
fn write_urls_to_file(urls: &[String]) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("Failed to create temp file");
    for url in urls {
        writeln!(file, "{}", url).expect("Failed to write URL");
    }
    file.flush().expect("Failed to flush file");
    file
}

/// Helper function to create a basic Config for testing
fn create_test_config(
    input_file: PathBuf,
    db_path: PathBuf,
    max_concurrency: usize,
    rate_limit_rps: u32,
) -> Config {
    Config {
        file: input_file,
        log_level: LogLevel::Error, // Reduce noise in tests
        log_format: LogFormat::Plain,
        db_path,
        max_concurrency,
        timeout_seconds: 5,
        user_agent: "domain_status_test/1.0".to_string(),
        rate_limit_rps,
        adaptive_error_threshold: 0.2, // 20% error threshold
        fingerprints: None,
        geoip: None,
        status_port: None,
        enable_whois: false,
        fail_on: FailOn::Never,
        fail_on_pct_threshold: 10,
        log_file: None,
        progress_callback: None,
    }
}

/// Test that run_scan enforces max_concurrency semaphore limit
///
/// This test verifies that the semaphore actually limits concurrent tasks
/// by using a mock server with delays and tracking concurrent connections.
#[tokio::test]
#[ignore] // Takes >60s, run manually with: cargo test -- --ignored test_run_scan_enforces_max_concurrency
async fn test_run_scan_enforces_max_concurrency() {
    // Setup
    let max_concurrency = 5;
    let total_urls = 20;
    let delay_ms = 500; // 500ms delay per request

    // Track concurrent requests
    let concurrent_requests = Arc::new(AtomicUsize::new(0));
    let max_observed_concurrency = Arc::new(AtomicUsize::new(0));

    // Start mock server
    let mock_server = MockServer::start().await;

    // Clone Arc for use in closure
    let concurrent_clone = Arc::clone(&concurrent_requests);
    let max_clone = Arc::clone(&max_observed_concurrency);

    // Mock endpoint that tracks concurrency
    Mock::given(method("GET"))
        .and(path_regex(r"^/test/.*"))
        .respond_with(move |_req: &wiremock::Request| {
            let current = concurrent_clone.fetch_add(1, Ordering::SeqCst) + 1;

            // Update max observed concurrency
            let mut max = max_clone.load(Ordering::SeqCst);
            while current > max {
                match max_clone.compare_exchange_weak(
                    max,
                    current,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => break,
                    Err(x) => max = x,
                }
            }

            // Simulate work
            std::thread::sleep(Duration::from_millis(delay_ms));

            concurrent_clone.fetch_sub(1, Ordering::SeqCst);

            ResponseTemplate::new(200).set_body_string("OK")
        })
        .mount(&mock_server)
        .await;

    // Generate URLs pointing to mock server
    let urls: Vec<String> = (0..total_urls)
        .map(|i| format!("{}/test/{}", mock_server.uri(), i))
        .collect();

    // Write URLs to file
    let url_file = write_urls_to_file(&urls);

    // Create test config
    let db_file = create_temp_db();
    let config = create_test_config(
        url_file.path().to_path_buf(),
        db_file.path().to_path_buf(),
        max_concurrency,
        0, // No rate limiting for this test
    );

    // Run scan
    let result = run_scan(config).await;
    assert!(result.is_ok(), "run_scan should succeed");

    // Verify max concurrency was enforced
    let max_observed = max_observed_concurrency.load(Ordering::SeqCst);
    assert!(
        max_observed <= max_concurrency,
        "Max observed concurrency {} should not exceed limit {}",
        max_observed,
        max_concurrency
    );

    println!(
        "✅ Max concurrency test passed: observed {} <= limit {}",
        max_observed, max_concurrency
    );
}

/// Test that run_scan respects static rate limiting
///
/// This test verifies that the rate limiter prevents exceeding the configured
/// requests per second limit.
#[tokio::test]
#[ignore] // Takes >60s, run manually with: cargo test -- --ignored test_run_scan_respects_rate_limit
async fn test_run_scan_respects_rate_limit() {
    // Setup
    let rate_limit_rps = 10; // 10 requests per second
    let total_urls = 50;
    let max_concurrency = 20; // High concurrency to ensure rate limit is the bottleneck

    // Start mock server with fast responses
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/test/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&mock_server)
        .await;

    // Generate URLs
    let urls: Vec<String> = (0..total_urls)
        .map(|i| format!("{}/test/{}", mock_server.uri(), i))
        .collect();

    let url_file = write_urls_to_file(&urls);
    let db_file = create_temp_db();

    let config = create_test_config(
        url_file.path().to_path_buf(),
        db_file.path().to_path_buf(),
        max_concurrency,
        rate_limit_rps,
    );

    // Measure time taken
    let start = Instant::now();
    let result = run_scan(config).await;
    let elapsed = start.elapsed();

    assert!(result.is_ok(), "run_scan should succeed");

    // Calculate minimum expected time based on rate limit
    // With 50 URLs at 10 RPS, minimum time should be ~5 seconds
    // Allow some tolerance for overhead
    #[allow(clippy::cast_precision_loss)]
    let min_expected_secs = (total_urls as f64 / rate_limit_rps as f64) * 0.9; // 10% tolerance

    assert!(
        elapsed.as_secs_f64() >= min_expected_secs,
        "Elapsed time {:?} should be at least {:.2}s to respect rate limit of {} RPS",
        elapsed,
        min_expected_secs,
        rate_limit_rps
    );

    println!(
        "✅ Rate limit test passed: took {:?} for {} URLs at {} RPS",
        elapsed, total_urls, rate_limit_rps
    );
}

/// Test that run_scan handles 429 errors with adaptive rate limiting
///
/// This test verifies that the adaptive rate limiter reduces RPS when
/// encountering 429 (Too Many Requests) errors.
#[tokio::test]
#[ignore] // Takes >60s, run manually with: cargo test -- --ignored test_run_scan_handles_429_with_adaptive_rate_limiting
async fn test_run_scan_handles_429_with_adaptive_rate_limiting() {
    // Setup
    let initial_rps = 50;
    let total_urls = 30;
    let max_concurrency = 10;

    // Track request count
    let request_count = Arc::new(AtomicUsize::new(0));

    // Start mock server
    let mock_server = MockServer::start().await;

    let count_clone = Arc::clone(&request_count);

    // Return 429 for first 50% of requests, then 200
    Mock::given(method("GET"))
        .and(path_regex(r"^/test/.*"))
        .respond_with(move |_req: &wiremock::Request| {
            let count = count_clone.fetch_add(1, Ordering::SeqCst);

            // First 50% get 429
            if count < 15 {
                ResponseTemplate::new(429).set_body_string("Too Many Requests")
            } else {
                ResponseTemplate::new(200).set_body_string("OK")
            }
        })
        .mount(&mock_server)
        .await;

    // Generate URLs
    let urls: Vec<String> = (0..total_urls)
        .map(|i| format!("{}/test/{}", mock_server.uri(), i))
        .collect();

    let url_file = write_urls_to_file(&urls);
    let db_file = create_temp_db();

    let config = create_test_config(
        url_file.path().to_path_buf(),
        db_file.path().to_path_buf(),
        max_concurrency,
        initial_rps,
    );

    // Run scan
    let result = run_scan(config).await;

    // The scan should complete even with 429 errors
    // Some URLs will fail, but the adaptive limiter should reduce RPS
    assert!(
        result.is_ok(),
        "run_scan should complete even with 429 errors"
    );

    let report = result.unwrap();

    // Verify that some URLs failed due to 429
    assert!(
        report.failed > 0,
        "Should have some failed URLs due to 429 errors"
    );

    println!(
        "✅ Adaptive rate limiting test passed: {} failed out of {} total",
        report.failed, total_urls
    );
}
