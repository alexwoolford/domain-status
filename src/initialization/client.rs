//! HTTP client initialization.
//!
//! This module provides functions to initialize HTTP clients with proper
//! configuration for requests and redirect handling.

use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::security::safe_resolver::SafeResolver;
use hickory_resolver::TokioResolver;
use reqwest::ClientBuilder;

/// Initializes the HTTP client with default settings.
///
/// Creates a `reqwest::Client` configured with:
/// - User-Agent header from options
/// - Timeout from options
/// - Redirect following DISABLED (SSRF protection)
/// - TLS certificate and hostname verification at reqwest default (strict); never disabled
/// - Rustls TLS backend (no native TLS)
///
/// # Security Note
///
/// This client is for page fetch only. Certificate and hostname verification are left at
/// reqwest's default (strict). Do not add `danger_accept_invalid_certs()` or similar;
/// TLS capture for observation uses a separate path in `src/tls/` (see ADR 0003).
/// Redirects are disabled to prevent SSRF bypass via TOCTOU race conditions.
/// Redirect chains are manually resolved by `resolve_redirect_chain()` with SSRF
/// validation at each hop. If this client followed redirects automatically,
/// a malicious server could redirect to internal IPs after validation.
///
/// # Arguments
///
/// * `config` - Configuration containing user-agent and timeout settings
///
/// # Returns
///
/// A configured HTTP client ready for making requests.
///
/// # Errors
///
/// Returns a `reqwest::Error` if client creation fails.
///
/// # Examples
///
/// ```no_run
/// use domain_status::{initialization::{init_client, init_resolver}, Config};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let resolver = init_resolver()?;
/// let client = init_client(&Config::default(), resolver).await?;
/// let response = client.get("https://example.com").send().await?;
/// println!("{}", response.status());
/// # Ok(())
/// # }
/// ```
pub async fn init_client(
    config: &Config,
    resolver: Arc<TokioResolver>,
) -> Result<Arc<reqwest::Client>, reqwest::Error> {
    use crate::config::TCP_CONNECT_TIMEOUT_SECS;

    // SECURITY: SafeResolver validates that all DNS-resolved IPs are public before
    // reqwest opens a TCP socket, closing the DNS-rebinding TOCTOU gap. It uses the
    // same hickory resolver (and its timeouts) as the rest of the scan.
    let client = ClientBuilder::new()
        .dns_resolver(Arc::new(SafeResolver::new(resolver)))
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(config.timeout_seconds))
        .connect_timeout(Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS))
        .user_agent(config.user_agent.clone())
        .build()?;
    Ok(Arc::new(client))
}

/// Initializes a shared HTTP client for redirect resolution.
///
/// Creates a `reqwest::Client` for the redirect-resolution stage.
///
/// The primary fetch client and redirect client currently share the same low-level
/// configuration (including strict TLS verification; see `init_client`), but they are
/// exposed as separate constructors so call sites can express intent clearly.
///
/// Redirects remain disabled here as well; redirect traversal is performed manually
/// so the scanner can inspect and validate each hop.
///
/// # Arguments
///
/// * `config` - Configuration containing user-agent and timeout settings
///
/// # Returns
///
/// A configured HTTP client with redirects disabled.
///
/// # Errors
///
/// Returns a `reqwest::Error` if client creation fails.
///
/// # Examples
///
/// ```no_run
/// use domain_status::{initialization::{init_redirect_client, init_resolver}, Config};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let resolver = init_resolver()?;
/// let client = init_redirect_client(&Config::default(), resolver).await?;
/// let response = client.get("https://example.com").send().await?;
/// println!("{}", response.status());
/// # Ok(())
/// # }
/// ```
pub async fn init_redirect_client(
    config: &Config,
    resolver: Arc<TokioResolver>,
) -> Result<Arc<reqwest::Client>, reqwest::Error> {
    use crate::config::TCP_CONNECT_TIMEOUT_SECS;

    // SECURITY: SafeResolver validates resolved IPs are public, preventing
    // DNS-rebinding attacks during redirect resolution. Uses same resolver (and timeouts).
    let client = ClientBuilder::new()
        .dns_resolver(Arc::new(SafeResolver::new(resolver)))
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(config.timeout_seconds))
        .connect_timeout(Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS))
        .user_agent(config.user_agent.clone())
        .build()?;
    Ok(Arc::new(client))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::initialization::init_resolver;
    use std::path::PathBuf;

    use crate::config::FailOn;

    fn test_resolver() -> Arc<TokioResolver> {
        init_resolver().expect("test resolver")
    }

    fn create_test_config() -> Config {
        // Create Config manually with required fields
        Config {
            file: PathBuf::from("test.txt"),
            user_agent: "test-agent/1.0".to_string(),
            timeout_seconds: 10,
            db_path: PathBuf::from("./test.db"),
            max_concurrency: 30,
            fail_on: FailOn::Never,
            fail_on_pct_threshold: 10,
            rate_limit_rps: 15,
            log_level: crate::config::LogLevel::Info,
            log_level_filter_override: None,
            log_format: crate::config::LogFormat::Plain,
            status_port: None,
            fingerprints: None,
            geoip: None,
            enable_whois: false,
            log_file: None,
            progress_callback: None,
            dependency_overrides: None,
        }
    }

    #[tokio::test]
    async fn test_init_client_success() {
        let config = create_test_config();
        let resolver = test_resolver();
        let result = init_client(&config, resolver).await;
        assert!(result.is_ok());
        let client = result.unwrap();
        assert_eq!(Arc::strong_count(&client), 1);
    }

    #[tokio::test]
    async fn test_init_client_with_custom_timeout() {
        let mut config = create_test_config();
        config.timeout_seconds = 30;
        let result = init_client(&config, test_resolver()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_client_with_custom_user_agent() {
        let mut config = create_test_config();
        config.user_agent = "Custom-Agent/2.0".to_string();
        let result = init_client(&config, test_resolver()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_redirect_client_success() {
        let config = create_test_config();
        let result = init_redirect_client(&config, test_resolver()).await;
        assert!(result.is_ok());
        let client = result.unwrap();
        assert_eq!(Arc::strong_count(&client), 1);
    }

    #[tokio::test]
    async fn test_init_client_and_redirect_client_different_instances() {
        let config = create_test_config();
        let resolver = test_resolver();
        let client1 = init_client(&config, Arc::clone(&resolver)).await.unwrap();
        let client2 = init_redirect_client(&config, resolver).await.unwrap();
        // They should be different Arc instances
        assert!(!Arc::ptr_eq(&client1, &client2));
    }

    #[tokio::test]
    async fn test_init_client_empty_user_agent() {
        // Test that empty user agent string is handled gracefully
        let mut config = create_test_config();
        config.user_agent = String::new();
        let result = init_client(&config, test_resolver()).await;
        // Should succeed even with empty user agent (reqwest allows it)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_client_zero_timeout() {
        // Test that zero timeout is handled (edge case - should still create client)
        let mut config = create_test_config();
        config.timeout_seconds = 0;
        let result = init_client(&config, test_resolver()).await;
        // Should succeed (zero timeout means no timeout, not immediate failure)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_client_very_large_timeout() {
        // Test that very large timeout values don't cause overflow
        let mut config = create_test_config();
        config.timeout_seconds = u64::MAX / 1000; // Large but reasonable timeout
        let result = init_client(&config, test_resolver()).await;
        // Should succeed (Duration handles large values gracefully)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_redirect_client_empty_user_agent() {
        // Test that empty user agent works for redirect client too
        let mut config = create_test_config();
        config.user_agent = String::new();
        let result = init_redirect_client(&config, test_resolver()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_redirect_client_zero_timeout() {
        // Test that zero timeout works for redirect client
        let mut config = create_test_config();
        config.timeout_seconds = 0;
        let result = init_redirect_client(&config, test_resolver()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_client_does_not_follow_redirects() {
        // CRITICAL SECURITY TEST: Verify the main client does NOT follow redirects.
        // This prevents SSRF bypass via TOCTOU race conditions.
        // After resolve_redirect_chain() validates the redirect chain, if the main client
        // followed redirects, a malicious server could redirect to an internal IP.
        use httptest::{matchers::*, responders::*, Expectation, Server};

        let server = Server::run();
        let redirect_url = format!("http://{}/redirect", server.addr());
        let target_url = format!("http://{}/target", server.addr());

        // Set up server to return 302 redirect
        server.expect(
            Expectation::matching(request::method_path("GET", "/redirect"))
                .respond_with(status_code(302).insert_header("Location", target_url.clone())),
        );

        // The target should NOT be hit if redirects are disabled
        // (we don't add an expectation for /target)

        let config = create_test_config();
        let client = init_client(&config, test_resolver())
            .await
            .expect("Should create client");

        // Make request to the redirect URL
        let response = client
            .get(&redirect_url)
            .send()
            .await
            .expect("Should send request");

        // Verify we got the 302 status (not followed to target)
        assert_eq!(
            response.status().as_u16(),
            302,
            "Main client should NOT follow redirects - got status {} instead of 302",
            response.status().as_u16()
        );

        // Verify the URL is still the redirect URL (not the target)
        assert_eq!(
            response.url().path(),
            "/redirect",
            "Main client should NOT follow redirects"
        );
    }

    #[tokio::test]
    async fn test_both_clients_have_redirects_disabled() {
        // Verify that both init_client and init_redirect_client have redirects disabled
        // This is critical for SSRF protection
        use httptest::{matchers::*, responders::*, Expectation, Server};

        let server = Server::run();
        let redirect_url = format!("http://{}/redirect", server.addr());
        let target_url = format!("http://{}/target", server.addr());

        // Set up two expectations - one for each client
        server.expect(
            Expectation::matching(request::method_path("GET", "/redirect"))
                .times(2..) // Both clients will hit this
                .respond_with(status_code(302).insert_header("Location", target_url.clone())),
        );

        let config = create_test_config();
        let resolver = test_resolver();
        let main_client = init_client(&config, Arc::clone(&resolver))
            .await
            .expect("Should create main client");
        let redirect_client = init_redirect_client(&config, resolver)
            .await
            .expect("Should create redirect client");

        // Test main client
        let main_response = main_client
            .get(&redirect_url)
            .send()
            .await
            .expect("Main client should send request");
        assert_eq!(
            main_response.status().as_u16(),
            302,
            "Main client should not follow redirects"
        );

        // Test redirect client
        let redirect_response = redirect_client
            .get(&redirect_url)
            .send()
            .await
            .expect("Redirect client should send request");
        assert_eq!(
            redirect_response.status().as_u16(),
            302,
            "Redirect client should not follow redirects"
        );
    }

    /// CRITICAL SECURITY TEST: Page-fetch client must reject invalid TLS certificates.
    /// The client uses reqwest default (strict) verification; it must never accept
    /// self-signed or wrong-hostname certs. This guards against future changes that
    /// might enable `danger_accept_invalid_certs()` on the page-fetch client.
    /// Run with: cargo test -- --ignored (e2e job runs these).
    #[tokio::test]
    #[ignore] // Requires network; uses badssl.com
    async fn test_init_client_rejects_invalid_tls_certificate() {
        let config = create_test_config();
        let client = init_client(&config, test_resolver())
            .await
            .expect("Should create client");
        // self-signed.badssl.com serves a self-signed certificate; strict TLS must fail
        let result = client.get("https://self-signed.badssl.com/").send().await;
        assert!(
            result.is_err(),
            "Page-fetch client must reject invalid (self-signed) certificates; got Ok"
        );
    }
}
