//! Integration tests for the `domain_status` application.
//!
//! These tests verify the library API using a mock HTTP server.
//! They do not make real network requests, ensuring tests are fast and reliable.
//!
//! With the library + binary structure, we can now test the full pipeline
//! by calling `run_scan()` directly with controlled inputs.
//!
//! ## Test Categories
//!
//! - **Unit tests**: Fast, no network access, run in all CI jobs
//! - **Integration tests with mock server**: Use `httptest` for HTTP mocking, run in all CI jobs
//! - **End-to-end tests** (marked `#[ignore]`): Require network access for DNS/fingerprints/TLS.
//!   These are run separately in CI via `cargo test -- --ignored` in the `e2e` job.
//!   To run locally: `cargo test -- --ignored`

#[cfg(test)]
mod tests {
    use httptest::{matchers::*, responders::*, Expectation, Server};

    /// Basic test to verify httptest setup works
    #[tokio::test]
    async fn test_mock_server_setup() {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/"))
                .respond_with(status_code(200).body("Hello, World!")),
        );

        let url = format!("http://{}/", server.addr());
        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .send()
            .await
            .expect("Request should succeed");

        assert_eq!(response.status(), 200);
        let body = response.text().await.expect("Should read body");
        assert_eq!(body, "Hello, World!");
    }

    /// Test redirect handling with mock server
    #[tokio::test]
    async fn test_redirect_with_mock_server() {
        let server = Server::run();
        let final_url = format!("http://{}/final", server.addr());

        server.expect(
            Expectation::matching(request::method_path("GET", "/redirect"))
                .respond_with(status_code(301).append_header("Location", final_url.as_str())),
        );
        server.expect(
            Expectation::matching(request::method_path("GET", "/final"))
                .respond_with(status_code(200).body("<html><title>Final</title></html>")),
        );

        let url = format!("http://{}/redirect", server.addr());
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("Failed to create client");

        let response = client
            .get(&url)
            .send()
            .await
            .expect("Request should succeed");
        assert_eq!(response.status(), 200);
        assert_eq!(response.url().as_str(), &final_url);
    }

    /// Test error handling (404) with mock server
    #[tokio::test]
    async fn test_404_error_with_mock_server() {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/notfound"))
                .respond_with(status_code(404).body("Not Found")),
        );

        let url = format!("http://{}/notfound", server.addr());
        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .send()
            .await
            .expect("Request should succeed");

        assert_eq!(response.status(), 404);
    }

    /// Full pipeline via library API with mock HTTP + offline fingerprint fixture.
    ///
    /// Must not soft-skip on ruleset fetch: fingerprints are loaded from a local JSON file
    /// (same contract style as `tests/orchestration_offline.rs`).
    #[tokio::test]
    async fn test_full_scan_with_mock_server() {
        use domain_status::{run_scan, Config};
        use tempfile::TempDir;

        let server = Server::run();
        let server_url = format!("http://{}/", server.addr());

        server.expect(
            Expectation::matching(request::method_path("GET", "/"))
                .times(..)
                .respond_with(
                    status_code(200)
                        .body(
                            "<html><head><title>Test Page</title></head><body>Hello</body></html>",
                        )
                        .append_header("Server", "nginx/1.18.0"),
                ),
        );
        server.expect(
            Expectation::matching(request::method_path("GET", "/favicon.ico"))
                .times(0..)
                .respond_with(status_code(404)),
        );

        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let input_file = temp_dir.path().join("urls.txt");
        std::fs::write(&input_file, format!("{}\n", server_url))
            .expect("Failed to write test file");

        let fingerprints = temp_dir.path().join("technologies.json");
        std::fs::write(
            &fingerprints,
            r#"{
  "Nginx": {
    "cats": [6],
    "website": "https://nginx.org",
    "headers": { "Server": "nginx(?:/([\\d.]+))?\\;version:\\1" }
  }
}"#,
        )
        .expect("write offline fingerprints");

        let config = Config {
            file: input_file,
            db_path: temp_dir.path().join("test.db"),
            max_concurrency: 1,
            rate_limit_rps: 0,
            enable_whois: false,
            cache_dir: None,
            scan_external_scripts: false,
            log_level: domain_status::LogLevel::Error,
            log_level_filter_override: None,
            log_format: domain_status::LogFormat::Plain,
            timeout_seconds: 5,
            user_agent: "domain_status-test/1.0".to_string(),
            fingerprints: Some(fingerprints.to_string_lossy().into_owned()),
            geoip: None,
            status_port: None,
            fail_on: domain_status::FailOn::Never,
            fail_on_pct_threshold: 10,
            log_file: None,
            progress_callback: None,
            dependency_overrides: None,
            allow_localhost_for_tests: true,
            drain_timeout_secs: 10,
        };

        let report = run_scan(config)
            .await
            .expect("offline fingerprints + mock HTTP must succeed without soft-skip");

        assert_eq!(report.total_urls, 1);
        assert!(report.db_path.exists());
        assert_eq!(
            report.successful + report.failed + report.skipped,
            report.total_urls
        );
        assert_eq!(
            report.successful, 1,
            "mock URL should be counted successful"
        );

        let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", report.db_path.display()))
            .await
            .expect("Failed to connect to test database");

        let run_count: (i32,) = sqlx::query_as("SELECT COUNT(*) FROM runs")
            .fetch_one(&pool)
            .await
            .expect("Failed to query database");

        assert_eq!(run_count.0, 1, "Database should contain 1 run record");
    }
}
