//! Integration tests for the domain_status application.
//!
//! These tests verify HTTP client behavior using a mock HTTP server.
//! They do not make real network requests, ensuring tests are fast and reliable.
//!
//! **Note**: Full pipeline integration tests would require refactoring the crate
//! to expose a library interface (lib.rs + main.rs structure). The current tests
//! focus on HTTP client behavior which is the most critical integration point.

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
}
