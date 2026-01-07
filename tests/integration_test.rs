//! Integration tests for the domain_status application.
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
    use tempfile::TempDir;

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

    /// Test that tempfile works for test database setup
    #[test]
    fn test_tempfile_setup() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test.db");
        assert!(!db_path.exists());
        // File would be created when database is initialized
        // This test just verifies tempfile works
    }

    /// Test full pipeline using library API with mock server
    ///
    /// This test verifies that the library API works end-to-end by:
    /// 1. Creating a mock HTTP server
    /// 2. Running a scan via the library API
    /// 3. Verifying the results are saved to the database
    ///
    /// Note: This test may make DNS lookups and fetch fingerprint rulesets,
    /// so it's more of an integration test than a unit test.
    #[tokio::test]
    #[ignore] // Ignore by default - requires network access for DNS/fingerprints
              // Run with `cargo test -- --ignored` or in CI e2e job
    async fn test_full_scan_with_mock_server() {
        use domain_status::{run_scan, Config};
        use tempfile::TempDir;

        let server = Server::run();
        let server_url = format!("http://{}/", server.addr());

        // Set up mock responses (allow multiple requests for DNS, fingerprints, etc.)
        server.expect(
            Expectation::matching(request::method_path("GET", "/"))
                .times(..) // Allow multiple requests
                .respond_with(
                    status_code(200)
                        .body(
                            "<html><head><title>Test Page</title></head><body>Hello</body></html>",
                        )
                        .append_header("Server", "nginx/1.18.0"),
                ),
        );

        // Create temporary input file
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let input_file = temp_dir.path().join("urls.txt");
        std::fs::write(&input_file, format!("{}\n", server_url))
            .expect("Failed to write test file");

        // Create config for library usage
        // Note: Uses default fingerprint fetching from GitHub (GITHUB_TOKEN env var increases rate limit)
        let config = Config {
            file: input_file,
            db_path: temp_dir.path().join("test.db"),
            max_concurrency: 1,
            rate_limit_rps: 0,   // Disable rate limiting for test
            enable_whois: false, // Disable WHOIS for faster tests
            log_level: domain_status::LogLevel::Error, // Reduce log noise in tests
            log_format: domain_status::LogFormat::Plain,
            timeout_seconds: 5,
            user_agent: "domain_status-test/1.0".to_string(),
            adaptive_error_threshold: 0.2,
            fingerprints: None, // Use default (fetches from GitHub - GITHUB_TOKEN increases rate limit)
            geoip: None,        // Disable GeoIP for test
            status_port: None,
            fail_on: domain_status::FailOn::Never,
            fail_on_pct_threshold: 10,
            log_file: None,
            progress_callback: None,
        };

        // Run the scan using the library
        // Skip test if ruleset initialization fails (e.g., network issues, rate limits)
        let report = match run_scan(config).await {
            Ok(report) => report,
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("Failed to initialize fingerprint ruleset")
                    || error_msg.contains("Failed to fetch ruleset")
                {
                    eprintln!(
                        "Skipping test: ruleset initialization failed (likely network issues or rate limits): {}",
                        error_msg
                    );
                    return;
                }
                // Re-raise other errors
                panic!("Scan should complete: {}", e);
            }
        };

        // Verify results
        assert_eq!(report.total_urls, 1);
        // Note: URL might fail due to DNS resolution issues with mock server
        // So we just verify the scan completed and database exists
        assert!(report.db_path.exists());
        assert!(report.successful + report.failed == 1);

        // Verify database was created and has the runs table
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
