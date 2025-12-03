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
    resolver: &hickory_resolver::TokioAsyncResolver,
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
