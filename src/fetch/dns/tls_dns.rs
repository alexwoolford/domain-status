//! TLS certificate and DNS resolution fetching.
//!
//! This module handles fetching TLS certificate information and DNS resolution
//! in parallel for a given hostname.

use anyhow::Error;
use log::debug;
use std::time::Instant;

use crate::dns::{resolve_host_to_ip, reverse_dns_lookup};
use crate::tls::get_ssl_certificate_info;
use crate::utils::duration_to_us;

use super::types::{TlsDnsData, TlsDnsResult};

/// Fetches TLS certificate information and DNS resolution in parallel.
///
/// # Arguments
///
/// * `final_url` - The final URL (to check if HTTPS)
/// * `host` - The hostname to resolve
/// * `resolver` - DNS resolver
/// * `final_domain` - The final domain (for logging)
/// * `error_stats` - Processing statistics tracker
///
/// # Returns
///
/// Returns TLS/DNS data and any partial failures (errors that didn't prevent processing).
/// DNS/TLS failures are recorded as partial failures, not as errors that stop processing.
#[allow(clippy::too_many_lines)] // Orchestrates parallel TLS + DNS fetches and merges results; splitting would obscure the join logic
pub(crate) async fn fetch_tls_and_dns(
    final_url: &str,
    host: &str,
    resolver: &hickory_resolver::TokioResolver,
    final_domain: &str,
    error_stats: &crate::error_handling::ProcessingStats,
) -> Result<(TlsDnsResult, (u64, u64, u64)), Error> {
    // Run TLS and DNS operations in parallel (they're independent).
    // Each branch measures its own timing so metrics are accurate.
    let ((tls_result, tls_handshake_us), dns_result) = tokio::join!(
        // TLS certificate extraction (only for HTTPS)
        async {
            let tls_start = Instant::now();
            let result = if final_url.starts_with("https://") {
                get_ssl_certificate_info(host.to_string(), resolver).await
            } else {
                use crate::models::CertificateInfo;
                Ok(CertificateInfo {
                    tls_version: None,
                    subject: None,
                    issuer: None,
                    valid_from: None,
                    valid_to: None,
                    oids: None,
                    cipher_suite: None,
                    key_algorithm: None,
                    subject_alternative_names: None,
                    fingerprint_sha256: None,
                    serial_number: None,
                    is_self_signed: None,
                    is_wildcard: None,
                })
            };
            (result, duration_to_us(tls_start.elapsed()))
        },
        // DNS resolution (IP address and reverse DNS)
        async {
            let forward_start = Instant::now();
            let ip_result = resolve_host_to_ip(host, resolver).await;
            let forward_us = duration_to_us(forward_start.elapsed());

            let reverse_start = Instant::now();
            let result = match ip_result {
                Ok(ip) => {
                    let reverse_result = reverse_dns_lookup(&ip, resolver).await;
                    let reverse_us = duration_to_us(reverse_start.elapsed());
                    match reverse_result {
                        Ok(reverse_dns) => Ok((ip, reverse_dns, forward_us, reverse_us)),
                        Err(e) => Err((e, forward_us, reverse_us)),
                    }
                }
                Err(e) => Err((e, forward_us, 0)),
            };
            result
        }
    );
    let (dns_result, dns_forward_us, dns_reverse_us) = match dns_result {
        Ok((ip, reverse_dns, forward_us, reverse_us)) => {
            (Ok((ip, reverse_dns)), forward_us, reverse_us)
        }
        Err((e, forward_us, reverse_us)) => (Err(e), forward_us, reverse_us),
    };

    // Extract TLS info and record partial failures
    let mut partial_failures = Vec::new();
    let (
        tls_version,
        subject,
        issuer,
        valid_from,
        valid_to,
        oids,
        cipher_suite,
        key_algorithm,
        subject_alternative_names,
        cert_fingerprint_sha256,
        cert_serial_number,
        cert_is_self_signed,
        cert_is_wildcard,
    ) = match tls_result {
        Ok(cert_info) => (
            cert_info.tls_version,
            cert_info.subject,
            cert_info.issuer,
            cert_info.valid_from,
            cert_info.valid_to,
            cert_info.oids,
            cert_info.cipher_suite,
            cert_info.key_algorithm,
            cert_info.subject_alternative_names,
            cert_info.fingerprint_sha256,
            cert_info.serial_number,
            cert_info.is_self_signed,
            cert_info.is_wildcard,
        ),
        Err(e) => {
            log::error!("Failed to get SSL certificate info for {final_domain}: {e}");
            error_stats.increment_error(crate::error_handling::ErrorType::TlsCertificateError);
            let error_msg = format!("Failed to get SSL certificate info for {final_domain}: {e}");
            let truncated_msg =
                crate::utils::sanitize::sanitize_and_truncate_error_message(&error_msg);
            partial_failures.push((
                crate::error_handling::ErrorType::TlsCertificateError,
                truncated_msg,
            ));
            (
                None, None, None, None, None, None, None, None, None, None, None, None, None,
            )
        }
    };

    debug!(
        "Extracted SSL info for {final_domain}: {tls_version:?}, {subject:?}, {issuer:?}, {valid_from:?}, {valid_to:?}"
    );

    // Extract DNS info and record partial failures
    // If DNS resolution fails, continue with None values rather than failing the entire request
    // This makes the system more resilient to DNS issues
    let (ip_address, reverse_dns_name) = match dns_result {
        Ok((ip, reverse_dns)) => (Some(ip), reverse_dns),
        Err(e) => {
            log::warn!(
                "Failed to resolve DNS for {final_domain}: {e} - continuing without IP address"
            );
            error_stats.increment_error(crate::error_handling::ErrorType::DnsForwardLookupError);
            // Record as partial failure using ErrorType enum
            // Sanitize and truncate error message to prevent database bloat
            let error_msg = format!("Failed to resolve DNS for {final_domain}: {e}");
            let truncated_msg =
                crate::utils::sanitize::sanitize_and_truncate_error_message(&error_msg);
            partial_failures.push((
                crate::error_handling::ErrorType::DnsForwardLookupError,
                truncated_msg,
            ));
            (None, None)
        }
    };

    debug!("Resolved IP address: {ip_address:?}");
    debug!("Resolved reverse DNS name: {reverse_dns_name:?}");

    Ok((
        TlsDnsResult {
            data: TlsDnsData {
                tls_version,
                subject,
                issuer,
                valid_from,
                valid_to,
                oids,
                cipher_suite,
                key_algorithm,
                subject_alternative_names,
                ip_address,
                reverse_dns_name,
                cert_fingerprint_sha256,
                cert_serial_number,
                cert_is_self_signed,
                cert_is_wildcard,
            },
            partial_failures,
        },
        (dns_forward_us, dns_reverse_us, tls_handshake_us),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ProcessingStats;
    use crate::initialization::test_resolver;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_fetch_tls_and_dns_http_url() {
        crate::initialization::init_crypto_provider();
        let resolver = test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        let result = fetch_tls_and_dns(
            "http://example.com",
            "example.com",
            &resolver,
            "example.com",
            error_stats.as_ref(),
        )
        .await;

        // HTTP URLs should not attempt TLS
        assert!(result.is_ok());
        let (tls_dns_result, _timings) = result.unwrap();
        // TLS should be None for HTTP
        assert!(tls_dns_result.data.tls_version.is_none());
    }
}
