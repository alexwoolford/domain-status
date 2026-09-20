//! CI-default offline orchestration tests (adversarial, no network fingerprints).
//!
//! These challenge rescan/orchestration accounting without relying on soft-skips
//! or ignored stress tests. Fingerprints load from a local JSON fixture.

use domain_status::{
    evaluate_exit_code, run_scan, seed_whois_cache, Config, FailOn, LogFormat, LogLevel,
    WhoisResult,
};
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

/// `init_ruleset` caches the parsed ruleset in a process-wide static keyed only on
/// "first call wins" (see `src/fingerprint/ruleset/mod.rs`), ignoring the source path on
/// every later call within the same test binary. All offline tests in this file must
/// therefore share one canonical fixture — otherwise whichever test's `run_scan` reaches
/// `init_ruleset` first silently decides which technologies every other test observes.
///
/// Nginx implies `TestOS` (never pattern-matched directly) so the offline detect path's
/// `is_implied` flagging can be exercised: Nginx stays `is_implied=0` (observed via the
/// `Server` header, with a captured version), `TestOS` arrives only via `implies` and is
/// marked `is_implied=1`.
fn write_fingerprint_fixture(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("technologies.json");
    std::fs::write(
        &path,
        r#"{
  "Nginx": {
    "cats": [6],
    "website": "https://nginx.org",
    "headers": { "Server": "nginx(?:/([\\d.]+))?\\;version:\\1" },
    "implies": ["TestOS"]
  },
  "TestOS": {
    "cats": [28],
    "website": "https://example.com/testos"
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
        cache_dir: None,
        scan_external_scripts: false,
        fail_on: FailOn::Never,
        fail_on_pct_threshold: 10,
        log_file: None,
        progress_callback: None,
        dependency_overrides: None,
        allow_localhost_for_tests: true,
        drain_timeout_secs: 10,
        allow_degraded_fingerprints: false,
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

/// Adversarial: when the drain timeout fires mid-flight, the abandoned task must be
/// recorded as a `url_failures` row (never silently dropped), and the same domain must
/// never end up in both `url_status` and `url_failures` for the same run (no UPSERT
/// collision between a late-arriving success and a drain-timeout failure).
#[tokio::test]
async fn test_drain_timeout_records_failure_with_status_failure_exclusivity() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&mock)
        .await;

    let fp_dir = TempDir::new().expect("fp dir");
    let fingerprints = write_fingerprint_fixture(&fp_dir);
    let urls = write_urls(&[&format!("{}/", mock.uri())]);
    let db = NamedTempFile::new().expect("db");

    let mut config = base_config(
        urls.path().to_path_buf(),
        db.path().to_path_buf(),
        &fingerprints,
    );
    // Shorter than the mock's 5s response delay, so the drain deadline fires while
    // the single in-flight task is still awaiting the response.
    config.drain_timeout_secs = 1;

    let report = run_scan(config)
        .await
        .expect("run_scan must complete even when drain timeout aborts in-flight tasks");

    assert_eq!(report.total_urls, 1);
    assert_eq!(
        report.successful + report.failed + report.skipped,
        report.total_urls,
        "counters must partition total_urls even when drain fires"
    );
    assert!(
        report.failed >= 1,
        "the 5s-delayed request must be aborted and recorded as a failure by the 1s drain timeout"
    );

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", report.db_path.display()))
        .await
        .expect("connect db");

    let failure_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM url_failures WHERE run_id = ?")
            .bind(&report.run_id)
            .fetch_one(&pool)
            .await
            .expect("failure count");
    assert!(
        failure_count >= 1,
        "drain timeout must persist a url_failures row for the abandoned task"
    );

    // Anti-join: no domain may appear in both url_status and url_failures for this run.
    let overlap_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM url_status s \
         WHERE s.run_id = ? \
         AND EXISTS (\
             SELECT 1 FROM url_failures f \
             WHERE f.run_id = s.run_id AND f.initial_domain = s.initial_domain\
         )",
    )
    .bind(&report.run_id)
    .fetch_one(&pool)
    .await
    .expect("overlap query");
    assert_eq!(
        overlap_count, 0,
        "no domain may be recorded in both url_status and url_failures for the same run"
    );
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
    assert_eq!(
        report.successful, 1,
        "same IP literal shares one url_status row per run"
    );
    assert_eq!(report.skipped, total_urls - 1);
    assert_eq!(
        report.successful + report.failed + report.skipped,
        report.total_urls
    );

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", report.db_path.display()))
        .await
        .expect("connect db");
    let status_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM url_status WHERE run_id = ?")
        .bind(&report.run_id)
        .fetch_one(&pool)
        .await
        .expect("status count");
    assert_eq!(
        usize::try_from(status_count).expect("non-neg"),
        report.successful
    );

    let observed = max_observed.load(Ordering::SeqCst);
    assert!(
        observed <= max_concurrency,
        "observed concurrency {observed} exceeded limit {max_concurrency}"
    );
    assert!(observed >= 1, "expected at least one in-flight observation");
}

/// Adversarial: technology version capture and implies-driven `is_implied` flagging must
/// both round-trip through the offline detect path into `url_technologies` columns.
#[tokio::test]
async fn test_technology_version_and_is_implied_persisted() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Server", "nginx/1.24.0")
                .set_body_string("<html><title>Implies Fixture</title></html>"),
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
    .expect("offline run_scan with implies fixture must succeed");

    assert_eq!(report.successful, 1);

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", report.db_path.display()))
        .await
        .expect("connect db");

    let nginx_row = sqlx::query(
        "SELECT technology_version, is_implied FROM url_technologies t \
         JOIN url_status u ON u.id = t.url_status_id \
         WHERE u.run_id = ? AND t.technology_name = 'Nginx'",
    )
    .bind(&report.run_id)
    .fetch_one(&pool)
    .await
    .expect("Nginx technology row");
    assert_eq!(
        nginx_row.get::<Option<String>, _>("technology_version"),
        Some("1.24.0".to_string()),
        "observed Nginx must capture the version from the Server header"
    );
    assert_eq!(
        nginx_row.get::<i64, _>("is_implied"),
        0,
        "directly observed Nginx must not be marked implied"
    );

    let testos_row = sqlx::query(
        "SELECT is_implied FROM url_technologies t \
         JOIN url_status u ON u.id = t.url_status_id \
         WHERE u.run_id = ? AND t.technology_name = 'TestOS'",
    )
    .bind(&report.run_id)
    .fetch_one(&pool)
    .await
    .expect("TestOS technology row (via implies)");
    assert_eq!(
        testos_row.get::<i64, _>("is_implied"),
        1,
        "TestOS only arrives via Nginx's implies list; must be marked implied"
    );
}

/// Adversarial: a private/loopback IP literal must be counted as `skipped` (SSRF policy),
/// never as `failed` — and a skip must not trip `FailOn::AnyFailure`.
#[tokio::test]
async fn test_private_ip_url_is_skipped_not_failed_and_does_not_trip_fail_on_any() {
    let fp_dir = TempDir::new().expect("fp dir");
    let fingerprints = write_fingerprint_fixture(&fp_dir);
    // IP literal bypasses DNS/SafeResolver, so SSRF protection must catch it via
    // validate_url_safe() on the initial URL itself (see src/run/mod.rs).
    let urls = write_urls(&["http://127.0.0.1/"]);
    let db = NamedTempFile::new().expect("db");

    let mut config = base_config(
        urls.path().to_path_buf(),
        db.path().to_path_buf(),
        &fingerprints,
    );
    config.allow_localhost_for_tests = false;

    let report = run_scan(config)
        .await
        .expect("scan must complete even when every URL is SSRF-unsafe");

    assert_eq!(report.total_urls, 1);
    assert_eq!(report.successful, 0);
    assert_eq!(
        report.failed, 0,
        "SSRF-unsafe URLs must be skipped, not failed"
    );
    assert_eq!(report.skipped, 1);
    assert_eq!(
        report.successful + report.failed + report.skipped,
        report.total_urls
    );

    assert_eq!(
        evaluate_exit_code(&FailOn::AnyFailure, 10, &report),
        0,
        "a skip must not be treated as a failure by FailOn::AnyFailure"
    );
}

/// Adversarial: an unusable `--geoip` path must not fail the whole scan (soft-fail).
/// `init_geoip` errors are caught and logged in `src/run/init.rs`; the scan proceeds
/// with `GeoIP` lookups disabled, so `url_geoip` stays empty for every URL in the run.
#[tokio::test]
async fn test_bogus_geoip_path_soft_fails_scan_still_succeeds() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html><title>Geo</title></html>"))
        .mount(&mock)
        .await;

    let fp_dir = TempDir::new().expect("fp dir");
    let fingerprints = write_fingerprint_fixture(&fp_dir);
    let urls = write_urls(&[&format!("{}/", mock.uri())]);
    let db = NamedTempFile::new().expect("db");

    let mut config = base_config(
        urls.path().to_path_buf(),
        db.path().to_path_buf(),
        &fingerprints,
    );
    config.geoip = Some("/nonexistent/path/GeoLite2.mmdb".to_string());

    let report = run_scan(config)
        .await
        .expect("a bogus --geoip path must not fail the scan (soft-fail)");

    assert_eq!(report.successful, 1);

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", report.db_path.display()))
        .await
        .expect("connect db");
    let geoip_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM url_geoip g \
         JOIN url_status u ON u.id = g.url_status_id WHERE u.run_id = ?",
    )
    .bind(&report.run_id)
    .fetch_one(&pool)
    .await
    .expect("geoip count");
    assert_eq!(
        geoip_count, 0,
        "GeoIP init failure must disable lookups, not error out or fabricate data"
    );
}

/// Duplicate `(run_id, initial_domain)` within one run must not inflate `successful_urls`
/// above `url_status` row count — accounting follows the UPSERT, not dispatch heuristics.
#[tokio::test]
async fn test_duplicate_registrable_domain_accounting() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Server", "nginx/1.24.0")
                .set_body_string("<html><title>Dup</title></html>"),
        )
        .mount(&mock)
        .await;

    let fp_dir = TempDir::new().expect("fp dir");
    let fingerprints = write_fingerprint_fixture(&fp_dir);
    let url = format!("{}/", mock.uri());
    let urls = write_urls(&[&url, &url]);
    let db = NamedTempFile::new().expect("db");

    let report = run_scan(base_config(
        urls.path().to_path_buf(),
        db.path().to_path_buf(),
        &fingerprints,
    ))
    .await
    .expect("scan should complete");

    assert_eq!(report.total_urls, 2);
    assert_eq!(report.successful, 1);
    assert_eq!(report.skipped, 1);
    assert_eq!(report.failed, 0);
    assert_eq!(
        report.successful + report.failed + report.skipped,
        report.total_urls
    );

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", report.db_path.display()))
        .await
        .expect("connect");
    let status_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM url_status WHERE run_id = ?")
        .bind(&report.run_id)
        .fetch_one(&pool)
        .await
        .expect("status count");
    assert_eq!(
        usize::try_from(status_count).expect("non-neg"),
        report.successful,
        "url_status rows must match successful counter"
    );
}

/// Mid-chain redirect to RFC1918 must stop the chain (not become an outbound fetch).
/// Unlike an initial-URL SSRF skip, the last safe hop is still a successful observation.
#[tokio::test]
async fn test_mid_chain_rfc1918_redirect_is_not_followed() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", "http://10.0.0.1/")
                .set_body_string("redirect"),
        )
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock)
        .await;

    let fp_dir = TempDir::new().expect("fp dir");
    let fingerprints = write_fingerprint_fixture(&fp_dir);
    let start = format!("{}/start", mock.uri());
    let urls = write_urls(&[&start]);
    let db = NamedTempFile::new().expect("db");

    let report = run_scan(base_config(
        urls.path().to_path_buf(),
        db.path().to_path_buf(),
        &fingerprints,
    ))
    .await
    .expect("scan must complete when a redirect target is SSRF-unsafe");

    assert_eq!(report.total_urls, 1);
    assert_eq!(
        report.failed, 0,
        "blocked redirect must not count as failed"
    );
    assert_eq!(
        report.successful, 1,
        "last safe hop is a successful observation, not a skip"
    );
    assert_eq!(report.skipped, 0);

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", report.db_path.display()))
        .await
        .expect("connect db");
    let failure_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM url_failures WHERE run_id = ?")
            .bind(&report.run_id)
            .fetch_one(&pool)
            .await
            .expect("failure count");
    assert_eq!(failure_count, 0, "url_failures must stay empty");

    let row = sqlx::query("SELECT final_url, http_status FROM url_status WHERE run_id = ?")
        .bind(&report.run_id)
        .fetch_one(&pool)
        .await
        .expect("url_status row");
    let final_url: String = row.get("final_url");
    let http_status: i64 = row.get("http_status");
    assert_eq!(
        http_status, 302,
        "last fetched hop is the 302 that pointed at RFC1918, not a follow"
    );
    assert!(
        !final_url.contains("10.0.0.1"),
        "final_url must stay on the last safe hop, got {final_url}"
    );
    assert!(
        final_url.contains("/start"),
        "final_url should be the mock start hop, got {final_url}"
    );

    for req in mock.received_requests().await.unwrap_or_default() {
        let url = req.url.to_string();
        assert!(
            !url.contains("10.0.0.1"),
            "mock must not be asked to fetch the private target: {url}"
        );
    }
}

/// `--no-whois` / `enable_whois: false` must not write `url_whois` for a successful URL.
#[tokio::test]
async fn test_whois_disabled_leaves_url_whois_empty() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<html><title>NoWhois</title></html>"),
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
    .expect("scan with WHOIS disabled");

    assert_eq!(report.successful, 1);

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", report.db_path.display()))
        .await
        .expect("connect db");
    let whois_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM url_whois w \
         JOIN url_status u ON u.id = w.url_status_id WHERE u.run_id = ?",
    )
    .bind(&report.run_id)
    .fetch_one(&pool)
    .await
    .expect("whois count");
    assert_eq!(
        whois_count, 0,
        "enable_whois=false must not insert url_whois rows"
    );
}

/// Cache-seeded WHOIS must persist under `run_scan` when WHOIS is enabled (no live lookup).
#[tokio::test]
async fn test_whois_enabled_writes_seeded_cache_row() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<html><title>Whois</title></html>"),
        )
        .mount(&mock)
        .await;

    let parsed = mock.address().ip().to_string();

    let cache_root = TempDir::new().expect("cache root");
    let whois_dir = cache_root.path().join("whois");
    std::fs::create_dir_all(&whois_dir).expect("whois dir");
    seed_whois_cache(
        &whois_dir,
        &parsed,
        &WhoisResult {
            registrar: Some("Fixture Registrar".to_string()),
            registrant_country: Some("US".to_string()),
            registrant_org: Some("Fixture Org".to_string()),
            raw_text: Some("seeded whois cache".to_string()),
            ..WhoisResult::default()
        },
    )
    .await
    .expect("seed whois cache");

    let fp_dir = TempDir::new().expect("fp dir");
    let fingerprints = write_fingerprint_fixture(&fp_dir);
    let urls = write_urls(&[&format!("{}/", mock.uri())]);
    let db = NamedTempFile::new().expect("db");

    let mut config = base_config(
        urls.path().to_path_buf(),
        db.path().to_path_buf(),
        &fingerprints,
    );
    config.enable_whois = true;
    config.cache_dir = Some(cache_root.path().to_path_buf());

    let report = run_scan(config)
        .await
        .expect("scan with seeded WHOIS cache");

    assert_eq!(report.successful, 1);

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", report.db_path.display()))
        .await
        .expect("connect db");
    let registrar: Option<String> = sqlx::query_scalar(
        "SELECT w.registrar FROM url_whois w \
         JOIN url_status u ON u.id = w.url_status_id WHERE u.run_id = ?",
    )
    .bind(&report.run_id)
    .fetch_one(&pool)
    .await
    .expect("whois registrar");
    assert_eq!(
        registrar.as_deref(),
        Some("Fixture Registrar"),
        "seeded WHOIS cache must land in url_whois"
    );
}
