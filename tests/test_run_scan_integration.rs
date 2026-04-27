//! Integration tests for `run_scan` function
//!
//! These tests verify the core orchestration logic including:
//! - Concurrent execution with semaphore enforcement
//! - Rate limiting (static RPS)

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
        log_level_filter_override: None,
        log_format: LogFormat::Plain,
        db_path,
        max_concurrency,
        timeout_seconds: 5,
        user_agent: "domain_status_test/1.0".to_string(),
        rate_limit_rps,
        fingerprints: None,
        geoip: None,
        status_port: None,
        enable_whois: false,
        fail_on: FailOn::Never,
        fail_on_pct_threshold: 10,
        log_file: None,
        progress_callback: None,
        dependency_overrides: None,
        allow_localhost_for_tests: true, // Mock server is 127.0.0.1; required for rate-limit and concurrency tests
        drain_timeout_secs: 10,
    }
}

/// Test that `run_scan` enforces `max_concurrency` semaphore limit
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

/// Test that `run_scan` respects static rate limiting
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

    // Minimum expected time: rate limiting should prevent finishing in a single burst.
    // Use 50% of theoretical minimum so we verify throttling without flaking on CI timing.
    #[allow(clippy::cast_precision_loss)]
    let min_expected_secs = (f64::from(total_urls) / f64::from(rate_limit_rps)) * 0.5;

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

/// Regression test for the drain-timeout silent-loss bug.
///
/// Background: when the drain phase fires (`drain_timeout_secs` after the input
/// queue is exhausted), in-flight tasks are aborted. Before the fix that
/// records `url_failures` rows for drain-timeout aborts, those URLs were
/// silently lost — the failed counter incremented but no DB row was written,
/// so users had no way to find which URLs had failed or retry them.
///
/// Setup: a wiremock server that delays every response longer than the drain
/// timeout. With `drain_timeout_secs=1` and a 10 s response delay, every URL
/// is guaranteed to still be in flight when drain fires. We then assert the
/// recorded `url_failures` rows match the input URLs exactly.
///
/// `#[ignore]` rationale: `run_scan` calls `init_ruleset` which fetches the
/// fingerprint rules from GitHub, hitting the unauthenticated 60/hr rate
/// limit on shared CI runners (observed: macOS leg of the matrix flaked
/// while ubuntu/windows passed). The same pattern is used by the sibling
/// `test_run_scan_enforces_max_concurrency` and `test_run_scan_respects_rate_limit`
/// tests in this file. The e2e job runs `cargo test ... -- --ignored` on
/// every push and same-repo PR, so the regression gate stays active for
/// merges to main.
///
/// FOLLOWUP: make the fingerprint init network-independent (write a minimal
/// fingerprint JSON to a temp file and pass its path via `Config.fingerprints`)
/// so this test can run in the regular Test Suite matrix and gate PRs from
/// forks.
#[tokio::test]
#[ignore = "needs network for fingerprint ruleset; runs in e2e job via --ignored"]
async fn test_run_scan_drain_timeout_records_failures() {
    let total_urls: usize = 5;
    let drain_timeout_secs: u64 = 1;
    // Server delay must be longer than drain_timeout_secs so tasks are still
    // mid-fetch when the deadline fires. Bump well above the 1s drain so
    // background scheduling can't make the test flaky on slow CI.
    let response_delay = Duration::from_secs(10);

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/slow/.*"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("OK")
                .set_delay(response_delay),
        )
        .mount(&mock_server)
        .await;

    let urls: Vec<String> = (0..total_urls)
        .map(|i| format!("{}/slow/{i}", mock_server.uri()))
        .collect();
    let url_file = write_urls_to_file(&urls);
    let db_file = create_temp_db();

    let mut config = create_test_config(
        url_file.path().to_path_buf(),
        db_file.path().to_path_buf(),
        total_urls, // permit every URL to start
        0,          // no rate limit
    );
    config.drain_timeout_secs = drain_timeout_secs;
    // Per-request HTTP timeout must be long enough that the *drain* fires first.
    // Otherwise reqwest would time out each task individually before drain runs,
    // which is a different code path than the one we're testing.
    config.timeout_seconds = 60;

    // Run scan; the drain phase should kick in ~drain_timeout_secs after the
    // queue empties (well before the per-URL HTTP timeout).
    let report = run_scan(config).await.expect("run_scan should complete");

    // Every URL should be accounted for: success + failure + skipped == input.
    assert_eq!(
        report.total_urls, total_urls,
        "report.total_urls should equal input URL count"
    );
    let accounted = report.successful + report.failed + report.skipped;
    assert_eq!(
        accounted, total_urls,
        "every input URL must be accounted for in the report (was {accounted}/{total_urls})"
    );

    // None of these URLs could possibly succeed within the drain window, so
    // every one of them must land in url_failures with a drain-timeout reason.
    assert_eq!(
        report.failed, total_urls,
        "all {total_urls} URLs should have failed at drain timeout"
    );

    // Open the DB and verify the url_failures rows were actually written —
    // this is the bug that prompted the fix: previously the failed counter
    // ticked up but the rows were silently dropped.
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", db_file.path().display()))
        .await
        .expect("open scan DB");
    let row_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM url_failures")
        .fetch_one(&pool)
        .await
        .expect("query url_failures count");
    assert_eq!(
        row_count, total_urls as i64,
        "url_failures must contain a row per abandoned URL (this is the regression \
         that the drain-timeout fix addresses; the failure counter alone is not enough)"
    );

    // Each row should be tagged with the drain-timeout error type and reason.
    // We match on substrings so the exact phrasing of the error message can
    // evolve without breaking the regression gate.
    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT attempted_url, error_type, error_message FROM url_failures")
            .fetch_all(&pool)
            .await
            .expect("read url_failures");
    for (url, error_type, error_message) in &rows {
        assert_eq!(
            error_type, "Process URL timeout",
            "url_failures row for {url} must use the ProcessUrlTimeout error type"
        );
        assert!(
            error_message.contains("drain timeout"),
            "url_failures row for {url} must mention drain timeout in its error message; got: {error_message}"
        );
    }

    // The set of attempted URLs in url_failures must match the input set
    // exactly — neither a subset (some lost) nor a superset (any duplicates).
    let mut got: Vec<String> = rows.iter().map(|(u, _, _)| u.clone()).collect();
    let mut want = urls.clone();
    got.sort();
    want.sort();
    assert_eq!(
        got, want,
        "every input URL must appear in url_failures exactly once"
    );
}
