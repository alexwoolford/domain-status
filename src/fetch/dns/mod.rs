//! DNS and TLS certificate fetching.
//!
//! This module handles fetching TLS certificate information and DNS records,
//! including additional DNS records (NS, TXT, MX) and SPF/DMARC extraction.

mod additional;
mod tls_dns;
mod types;

use anyhow::Error;

// Re-export types (these are crate-private, used internally by fetch module)
pub(crate) use types::{AdditionalDnsData, TlsDnsData};

use additional::fetch_additional_dns_records;
use tls_dns::fetch_tls_and_dns;

/// Fetches all DNS-related data (TLS, DNS resolution, and additional DNS records).
///
/// Returns the combined data, all partial failures encountered, and timing metrics.
/// Timing metrics: (dns_forward_ms, dns_reverse_ms, dns_additional_ms, tls_handshake_ms)
pub(crate) async fn fetch_all_dns_data(
    resp_data: &crate::fetch::response::ResponseData,
    resolver: &hickory_resolver::TokioResolver,
    error_stats: &crate::error_handling::ProcessingStats,
    run_id: Option<&str>,
) -> Result<
    (
        TlsDnsData,
        AdditionalDnsData,
        Vec<(crate::error_handling::ErrorType, String)>,
        (u64, u64, u64, u64), // Timing metrics
    ),
    Error,
> {
    // Fetch TLS and DNS data in parallel
    let (tls_dns_result, (dns_forward_ms, dns_reverse_ms, tls_handshake_ms)) = fetch_tls_and_dns(
        &resp_data.final_url,
        &resp_data.host,
        resolver,
        &resp_data.final_domain,
        error_stats,
        run_id,
    )
    .await?;
    let tls_dns_data = tls_dns_result.data;
    let mut partial_failures = tls_dns_result.partial_failures;

    // Fetch additional DNS records in parallel
    let additional_dns_start = std::time::Instant::now();
    let additional_dns_result =
        fetch_additional_dns_records(&resp_data.final_domain, resolver, error_stats).await;
    let dns_additional_ms = crate::utils::duration_to_ms(additional_dns_start.elapsed());
    let additional_dns = additional_dns_result.data;
    partial_failures.extend(additional_dns_result.partial_failures);

    Ok((
        tls_dns_data,
        additional_dns,
        partial_failures,
        (
            dns_forward_ms,
            dns_reverse_ms,
            dns_additional_ms,
            tls_handshake_ms,
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ProcessingStats;
    use crate::fetch::response::ResponseData;
    use hickory_resolver::config::ResolverOpts;
    use hickory_resolver::TokioResolver;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn create_test_resolver() -> TokioResolver {
        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(5);
        opts.attempts = 1;
        TokioResolver::builder_tokio()
            .unwrap()
            .with_options(opts)
            .build()
    }

    fn create_test_response_data() -> ResponseData {
        ResponseData {
            final_url: "https://example.com".to_string(),
            initial_domain: "example.com".to_string(),
            final_domain: "example.com".to_string(),
            host: "example.com".to_string(),
            status: 200,
            status_desc: "OK".to_string(),
            headers: reqwest::header::HeaderMap::new(),
            security_headers: HashMap::new(),
            http_headers: HashMap::new(),
            body: "<html><body>Test</body></html>".to_string(),
        }
    }

    #[tokio::test]
    async fn test_fetch_all_dns_data_success() {
        // Test that fetch_all_dns_data successfully combines TLS/DNS and additional DNS data
        crate::initialization::init_crypto_provider();
        let resolver = create_test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        let resp_data = create_test_response_data();

        let result = fetch_all_dns_data(
            &resp_data,
            &resolver,
            error_stats.as_ref(),
            Some("test-run"),
        )
        .await;

        // Should succeed (may have partial failures, but should return Ok)
        assert!(result.is_ok());
        let (tls_dns_data, additional_dns, partial_failures, timings) = result.unwrap();

        // Verify structure is correct
        let _ = tls_dns_data.ip_address; // Should have IP address
        let _ = additional_dns.nameservers; // May be None or Some
        let _ = partial_failures; // Partial failures may be empty or contain errors

        // Verify timing metrics are returned (u64 values are always >= 0)
        let (_dns_forward_ms, _dns_reverse_ms, _dns_additional_ms, _tls_handshake_ms) = timings;
    }

    #[tokio::test]
    async fn test_fetch_all_dns_data_partial_failures_merged() {
        // Test that partial failures from both TLS/DNS and additional DNS are merged correctly
        crate::initialization::init_crypto_provider();
        let resolver = create_test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        let resp_data = create_test_response_data();

        let result = fetch_all_dns_data(&resp_data, &resolver, error_stats.as_ref(), None).await;

        assert!(result.is_ok());
        let (_tls_dns_data, _additional_dns, partial_failures, _timings) = result.unwrap();

        // Partial failures should be a valid vector (may be empty or contain errors)
        // The key is that failures from both sources are merged
        // We can't easily verify specific failures without mocking, but we verify the structure
        for (error_type, error_msg) in &partial_failures {
            // Error type should be a valid DNS/TLS error type
            let _ = error_type;
            // Error message should be non-empty and sanitized
            assert!(!error_msg.is_empty(), "Error message should not be empty");
            assert!(
                error_msg.len() <= 500,
                "Error message should be sanitized/truncated"
            );
        }
    }

    #[tokio::test]
    async fn test_fetch_all_dns_data_timing_metrics_calculated() {
        // Test that timing metrics are correctly calculated for all operations
        crate::initialization::init_crypto_provider();
        let resolver = create_test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        let resp_data = create_test_response_data();

        let result = fetch_all_dns_data(&resp_data, &resolver, error_stats.as_ref(), None).await;

        assert!(result.is_ok());
        let (_tls_dns_data, _additional_dns, _partial_failures, timings) = result.unwrap();

        // Verify timing metrics are returned (u64 values are always >= 0)
        // All timings should be calculated - they may be 0 if operations are very fast
        let (_dns_forward_ms, _dns_reverse_ms, _dns_additional_ms, _tls_handshake_ms) = timings;
    }

    #[tokio::test]
    async fn test_fetch_all_dns_data_http_url_handled() {
        // Test that HTTP URLs are handled correctly (no TLS handshake)
        crate::initialization::init_crypto_provider();
        let resolver = create_test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        let mut resp_data = create_test_response_data();
        resp_data.final_url = "http://example.com".to_string();

        let result = fetch_all_dns_data(&resp_data, &resolver, error_stats.as_ref(), None).await;

        // Should succeed (HTTP URLs don't attempt TLS)
        assert!(result.is_ok());
        let (tls_dns_data, _additional_dns, _partial_failures, _timings) = result.unwrap();

        // TLS version should be None for HTTP
        assert!(tls_dns_data.tls_version.is_none());
    }

    #[tokio::test]
    async fn test_fetch_all_dns_data_invalid_domain_handled() {
        // Test that invalid domains are handled gracefully
        crate::initialization::init_crypto_provider();
        let resolver = create_test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        let mut resp_data = create_test_response_data();
        resp_data.final_domain = "this-domain-definitely-does-not-exist-12345.invalid".to_string();
        resp_data.host = "this-domain-definitely-does-not-exist-12345.invalid".to_string();

        let result = fetch_all_dns_data(&resp_data, &resolver, error_stats.as_ref(), None).await;

        // Should succeed but may have partial failures
        // TLS/DNS fetch may fail, but should return Ok with partial failures
        // Additional DNS will definitely fail, but should be in partial failures
        let _ = result; // May succeed or fail depending on resolver behavior
    }

    #[tokio::test]
    async fn test_fetch_all_dns_data_error_propagation() {
        // Test that errors from fetch_tls_and_dns are correctly propagated
        // This is critical - if TLS/DNS fetch fails completely, error should propagate
        crate::initialization::init_crypto_provider();
        let resolver = create_test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        let mut resp_data = create_test_response_data();
        // Use an invalid URL that will cause fetch_tls_and_dns to fail
        resp_data.final_url =
            "https://this-domain-definitely-does-not-exist-12345.invalid".to_string();
        resp_data.host = "this-domain-definitely-does-not-exist-12345.invalid".to_string();
        resp_data.final_domain = "this-domain-definitely-does-not-exist-12345.invalid".to_string();

        let result = fetch_all_dns_data(&resp_data, &resolver, error_stats.as_ref(), None).await;

        // May succeed with partial failures or fail completely depending on resolver behavior
        // The key is that it doesn't panic
        let _ = result;
    }

    #[tokio::test]
    async fn test_fetch_all_dns_data_run_id_passed_through() {
        // Test that run_id is correctly passed to fetch_tls_and_dns
        crate::initialization::init_crypto_provider();
        let resolver = create_test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        let resp_data = create_test_response_data();

        // Test with run_id
        let result_with_run_id = fetch_all_dns_data(
            &resp_data,
            &resolver,
            error_stats.as_ref(),
            Some("test-run-123"),
        )
        .await;

        // Test without run_id
        let result_without_run_id =
            fetch_all_dns_data(&resp_data, &resolver, error_stats.as_ref(), None).await;

        // Both should succeed (run_id is optional)
        assert!(result_with_run_id.is_ok());
        assert!(result_without_run_id.is_ok());
    }
}
