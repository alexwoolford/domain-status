//! HTTP client initialization.
//!
//! This module provides functions to initialize HTTP clients with proper
//! configuration for requests and redirect handling.

use std::sync::Arc;
use std::time::Duration;

use crate::config::{Config, TCP_CONNECT_TIMEOUT_SECS};
use crate::security::safe_resolver::SafeResolver;
use crate::security::ssrf_safe_redirect_policy;
use anyhow::Context;
use hickory_resolver::TokioResolver;
use reqwest::ClientBuilder;

/// Redirect policy for SSRF-safe clients.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RedirectMode {
    /// Do not follow redirects (manual hop validation).
    None,
    /// Follow redirects with per-hop SSRF checks.
    SsrfSafe,
}

/// Options for building an SSRF-safe `reqwest` client.
#[derive(Debug, Clone)]
pub(crate) struct SsrfClientOptions {
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub user_agent: Option<String>,
    pub redirect: RedirectMode,
    pub pool_idle_timeout: Option<Duration>,
    pub pool_max_idle_per_host: Option<usize>,
    pub tcp_nodelay: bool,
}

impl SsrfClientOptions {
    /// Defaults suited to one-off asset downloads (`GeoIP`, ruleset, UA).
    #[must_use]
    pub(crate) fn download(timeout: Duration) -> Self {
        Self {
            timeout,
            connect_timeout: Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS),
            user_agent: None,
            redirect: RedirectMode::SsrfSafe,
            pool_idle_timeout: None,
            pool_max_idle_per_host: None,
            tcp_nodelay: false,
        }
    }

    /// Defaults for the shared scan clients (page fetch / redirect resolution).
    #[must_use]
    pub(crate) fn scan(config: &Config) -> Self {
        Self {
            timeout: Duration::from_secs(config.timeout_seconds),
            connect_timeout: Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS),
            user_agent: Some(config.user_agent.clone()),
            redirect: RedirectMode::None,
            pool_idle_timeout: Some(Duration::from_secs(30)),
            pool_max_idle_per_host: Some(10),
            tcp_nodelay: true,
        }
    }
}

/// Builds an SSRF-safe HTTP client using the given resolver and options.
pub(crate) fn build_ssrf_client(
    resolver: Arc<TokioResolver>,
    opts: SsrfClientOptions,
) -> Result<reqwest::Client, reqwest::Error> {
    let redirect = match opts.redirect {
        RedirectMode::None => reqwest::redirect::Policy::none(),
        RedirectMode::SsrfSafe => ssrf_safe_redirect_policy(),
    };

    let mut builder = ClientBuilder::new()
        .dns_resolver(Arc::new(SafeResolver::new(resolver)))
        .redirect(redirect)
        .timeout(opts.timeout)
        .connect_timeout(opts.connect_timeout);

    if let Some(ua) = opts.user_agent {
        builder = builder.user_agent(ua);
    }
    if let Some(idle) = opts.pool_idle_timeout {
        builder = builder.pool_idle_timeout(idle);
    }
    if let Some(max_idle) = opts.pool_max_idle_per_host {
        builder = builder.pool_max_idle_per_host(max_idle);
    }
    if opts.tcp_nodelay {
        builder = builder.tcp_nodelay(true);
    }

    builder.build()
}

/// Builds a download client with a fresh resolver (`GeoIP` / ruleset / UA fetches).
pub(crate) fn build_download_client(timeout: Duration) -> Result<reqwest::Client, anyhow::Error> {
    let resolver = crate::initialization::init_resolver()
        .context("Failed to initialize DNS resolver for download")?;
    build_ssrf_client(resolver, SsrfClientOptions::download(timeout))
        .context("Failed to build SSRF-safe download client")
}

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
/// # Errors
///
/// Returns a `reqwest::Error` if client creation fails.
pub async fn init_client(
    config: &Config,
    resolver: Arc<TokioResolver>,
) -> Result<Arc<reqwest::Client>, reqwest::Error> {
    // SECURITY: SafeResolver validates that all DNS-resolved IPs are public before
    // reqwest opens a TCP socket, closing the DNS-rebinding TOCTOU gap.
    let client = build_ssrf_client(resolver, SsrfClientOptions::scan(config))?;
    Ok(Arc::new(client))
}

/// Initializes a shared HTTP client for redirect resolution.
///
/// The primary fetch client and redirect client share the same low-level
/// configuration; separate constructors keep call-site intent clear.
/// Redirects remain disabled; redirect traversal is performed manually
/// so the scanner can inspect and validate each hop.
///
/// # Errors
///
/// Returns a `reqwest::Error` if client creation fails.
pub async fn init_redirect_client(
    config: &Config,
    resolver: Arc<TokioResolver>,
) -> Result<Arc<reqwest::Client>, reqwest::Error> {
    let client = build_ssrf_client(resolver, SsrfClientOptions::scan(config))?;
    Ok(Arc::new(client))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::config::FailOn;
    use crate::initialization::test_resolver;
    use std::path::PathBuf;

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
            cache_dir: None,
            scan_external_scripts: false,
            log_file: None,
            progress_callback: None,
            dependency_overrides: None,
            allow_localhost_for_tests: false,
            drain_timeout_secs: 10,
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
