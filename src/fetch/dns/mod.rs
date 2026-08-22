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
/// Timing metrics in microseconds: (`dns_forward_us`, `dns_reverse_us`, `dns_additional_us`, `tls_handshake_us`)
pub(crate) async fn fetch_all_dns_data(
    resp_data: &crate::fetch::response::ResponseData,
    resolver: &hickory_resolver::TokioResolver,
    error_stats: &crate::error_handling::ProcessingStats,
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
    let (tls_dns_result, (dns_forward_us, dns_reverse_us, tls_handshake_us)) = fetch_tls_and_dns(
        &resp_data.final_url,
        &resp_data.host,
        resolver,
        &resp_data.final_domain,
        error_stats,
    )
    .await?;
    let tls_dns_data = tls_dns_result.data;
    let mut partial_failures = tls_dns_result.partial_failures;

    // Fetch additional DNS records in parallel
    let additional_dns_start = std::time::Instant::now();
    let additional_dns_result =
        fetch_additional_dns_records(&resp_data.final_domain, resolver, error_stats).await;
    let dns_additional_us = crate::utils::duration_to_us(additional_dns_start.elapsed());
    let additional_dns = additional_dns_result.data;
    partial_failures.extend(additional_dns_result.partial_failures);

    Ok((
        tls_dns_data,
        additional_dns,
        partial_failures,
        (
            dns_forward_us,
            dns_reverse_us,
            dns_additional_us,
            tls_handshake_us,
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
            .expect("resolver builds with default config")
    }

    fn create_test_response_data() -> ResponseData {
        ResponseData {
            initial_url: "https://example.com".to_string(),
            final_url: "https://example.com".to_string(),
            initial_domain: "example.com".to_string(),
            final_domain: "example.com".to_string(),
            host: "example.com".to_string(),
            status: 200,
            status_desc: "OK".to_string(),
            headers: reqwest::header::HeaderMap::new(),
            security_headers: HashMap::new(),
            http_headers: HashMap::new(),
            body: std::sync::Arc::<str>::from("<html><body>Test</body></html>"),
            body_sha256: None,
            body_truncated: false,
            content_length: None,
            http_version: None,
            content_type: None,
        }
    }

    #[tokio::test]
    async fn test_fetch_all_dns_data_partial_failures_merged() {
        // Test that partial failures from both TLS/DNS and additional DNS are merged correctly
        crate::initialization::init_crypto_provider();
        let resolver = create_test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        let resp_data = create_test_response_data();

        let result = fetch_all_dns_data(&resp_data, &resolver, error_stats.as_ref()).await;

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
    async fn test_fetch_all_dns_data_http_url_handled() {
        // Test that HTTP URLs are handled correctly (no TLS handshake)
        crate::initialization::init_crypto_provider();
        let resolver = create_test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        let mut resp_data = create_test_response_data();
        resp_data.final_url = "http://example.com".to_string();

        let result = fetch_all_dns_data(&resp_data, &resolver, error_stats.as_ref()).await;

        // Should succeed (HTTP URLs don't attempt TLS)
        assert!(result.is_ok());
        let (tls_dns_data, _additional_dns, _partial_failures, _timings) = result.unwrap();

        // TLS version should be None for HTTP
        assert!(tls_dns_data.tls_version.is_none());
    }
}
