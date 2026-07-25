//! CI-default offline orchestration tests (adversarial, no network fingerprints).
//!
//! These challenge rescan/orchestration accounting without relying on soft-skips
//! or ignored stress tests. Fingerprints load from a local JSON fixture.

use domain_status::{evaluate_exit_code, run_scan, Config, FailOn, LogFormat, LogLevel};
use sqlx::Row;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::{NamedTempFile, TempDir};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn write_urls(urls: &[&str]) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("temp urls");
    for url in urls {
        writeln!(file, "{url}").expect("write url");
    }
    file.flush().expect("flush");
    file
}

fn write_fingerprint_fixture(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("technologies.json");
    std::fs::write(
        &path,
        r#"{
  "Nginx": {
    "cats": [6],
    "website": "https://nginx.org",
    "headers": { "Server": "nginx(?:/([\\d.]+))?\\;version:\\1" }
  }
}"#,
    )
    .expect("write fingerprints");
    path
}

fn base_config(input: PathBuf, db: PathBuf, fingerprints: &Path) -> Config {
    Config {
        file: input,
        log_level: LogLevel::Error,
        log_level_filter_override: None,
        log_format: LogFormat::Plain,
        db_path: db,
        max_concurrency: 4,
        timeout_seconds: 5,
        user_agent: "domain_status_test/1.0".to_string(),
        rate_limit_rps: 0,
        fingerprints: Some(fingerprints.to_string_lossy().into_owned()),
        geoip: None,
        status_port: None,
        enable_whois: false,
        scan_external_scripts: false,
        fail_on: FailOn::Never,
        fail_on_pct_threshold: 10,
        log_file: None,
        progress_callback: None,
        dependency_overrides: None,
        allow_localhost_for_tests: true,
        drain_timeout_secs: 10,
    }
}

#[tokio::test]
async fn test_offline_run_scan_asserts_status_and_satellites() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Server", "nginx/1.24.0")
                .insert_header("X-Test", "satellite")
                .set_body_string("<html><title>Offline Fixture</title></html>"),
        )
        .mount(&mock)
        .await;

    let fp_dir = TempDir::new().expect("fp dir");
    let fingerprints = write_fingerprint_fixture(&fp_dir);
    let urls = write_urls(&[&format!("{}/", mock.uri())]);
    let db = NamedTempFile::new().expect("db");

    let report = run_scan(base_config(
        urls.path().to_path_buf(),
        db.path().to_path_buf(),
        &fingerprints,
    ))
    .await
    .expect("offline run_scan must succeed without network fingerprints");

    assert_eq!(report.total_urls, 1);
    assert_eq!(report.successful, 1);
    assert_eq!(report.failed, 0);
    assert_eq!(
        report.successful + report.failed + report.skipped,
        report.total_urls
    );

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", report.db_path.display()))
        .await
        .expect("connect db");

    let status_row =
        sqlx::query("SELECT http_status, title FROM url_status WHERE run_id = ? LIMIT 1")
            .bind(&report.run_id)
            .fetch_one(&pool)
            .await
            .expect("url_status row");
    assert_eq!(status_row.get::<i64, _>("http_status"), 200);
    assert_eq!(status_row.get::<String, _>("title"), "Offline Fixture");

    let tech_names: Vec<String> = sqlx::query_scalar(
        "SELECT t.technology_name FROM url_technologies t \
         JOIN url_status u ON u.id = t.url_status_id WHERE u.run_id = ?",
    )
    .bind(&report.run_id)
    .fetch_all(&pool)
    .await
    .expect("technologies");
    assert!(
        tech_names.iter().any(|n| n == "Nginx"),
        "expected Nginx from Server header; got {tech_names:?}"
    );

    let header_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM url_http_headers h \
         JOIN url_status u ON u.id = h.url_status_id WHERE u.run_id = ?",
    )
    .bind(&report.run_id)
    .fetch_one(&pool)
    .await
    .expect("http headers count");
    assert!(
        header_count > 0,
        "expected http header satellites for successful scan"
    );
}

#[tokio::test]
async fn test_partial_failure_accounting_and_exit_codes() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ok"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html><title>OK</title></html>"))
        .mount(&mock)
        .await;

    let fp_dir = TempDir::new().expect("fp dir");
    let fingerprints = write_fingerprint_fixture(&fp_dir);
    let ok = format!("{}/ok", mock.uri());
    // Reserved TLD `.invalid` never resolves — distinct final_domain from the mock IP,
    // so status/failure rows cannot UPSERT-collide.
    let dead = "http://no-such-host.invalid/".to_string();
    let urls = write_urls(&[&ok, &dead]);
    let db = NamedTempFile::new().expect("db");

    let report = run_scan(base_config(
        urls.path().to_path_buf(),
        db.path().to_path_buf(),
        &fingerprints,
    ))
    .await
    .expect("scan should complete");

    assert_eq!(
        report.successful + report.failed + report.skipped,
        report.total_urls,
        "counters must partition total_urls"
    );
    assert_eq!(report.successful, 1, "mock /ok should succeed");
    assert_eq!(report.failed, 1, "unresolvable host must fail");

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", report.db_path.display()))
        .await
        .expect("connect");
    let status_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM url_status WHERE run_id = ?")
        .bind(&report.run_id)
        .fetch_one(&pool)
        .await
        .expect("status count");
    let failure_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM url_failures WHERE run_id = ?")
            .bind(&report.run_id)
            .fetch_one(&pool)
            .await
            .expect("failure count");

    assert_eq!(
        usize::try_from(status_count).expect("non-neg"),
        report.successful,
        "url_status rows must match successful counter"
    );
    assert_eq!(
        usize::try_from(failure_count).expect("non-neg"),
        report.failed,
        "url_failures rows must match failed counter"
    );

    assert_eq!(evaluate_exit_code(&FailOn::Never, 10, &report), 0);
    assert_eq!(evaluate_exit_code(&FailOn::AnyFailure, 10, &report), 2);
    // 1 failure out of 2 → 50% > 10%
    assert_eq!(evaluate_exit_code(&FailOn::PctGreaterThan, 10, &report), 2);
    assert_eq!(evaluate_exit_code(&FailOn::PctGreaterThan, 90, &report), 0);
}

#[tokio::test]
async fn test_fast_concurrency_smoke_max_inflight() {
    let max_concurrency = 2;
    let total_urls = 6;
    let delay_ms = 80u64;

    let concurrent = Arc::new(AtomicUsize::new(0));
    let max_observed = Arc::new(AtomicUsize::new(0));
    let mock = MockServer::start().await;

    let concurrent_c = Arc::clone(&concurrent);
    let max_c = Arc::clone(&max_observed);
    Mock::given(method("GET"))
        .respond_with(move |_req: &wiremock::Request| {
            let current = concurrent_c.fetch_add(1, Ordering::SeqCst) + 1;
            let mut max = max_c.load(Ordering::SeqCst);
            while current > max {
                match max_c.compare_exchange_weak(max, current, Ordering::SeqCst, Ordering::SeqCst)
                {
                    Ok(_) => break,
                    Err(x) => max = x,
                }
            }
            std::thread::sleep(Duration::from_millis(delay_ms));
            concurrent_c.fetch_sub(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_string("OK")
        })
        .mount(&mock)
        .await;

    let fp_dir = TempDir::new().expect("fp dir");
    let fingerprints = write_fingerprint_fixture(&fp_dir);
    let url_list: Vec<String> = (0..total_urls)
        .map(|i| format!("{}/n/{i}", mock.uri()))
        .collect();
    let url_refs: Vec<&str> = url_list.iter().map(String::as_str).collect();
    let urls = write_urls(&url_refs);
    let db = NamedTempFile::new().expect("db");

    let mut config = base_config(
        urls.path().to_path_buf(),
        db.path().to_path_buf(),
        &fingerprints,
    );
    config.max_concurrency = max_concurrency;

    let report = run_scan(config).await.expect("concurrency smoke scan");
    assert_eq!(report.total_urls, total_urls);
    assert_eq!(report.successful, total_urls);

    let observed = max_observed.load(Ordering::SeqCst);
    assert!(
        observed <= max_concurrency,
        "observed concurrency {observed} exceeded limit {max_concurrency}"
    );
    assert!(observed >= 1, "expected at least one in-flight observation");
}
