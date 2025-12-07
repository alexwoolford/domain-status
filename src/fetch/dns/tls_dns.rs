//! TLS certificate and DNS resolution fetching.
//!
//! This module handles fetching TLS certificate information and DNS resolution
//! in parallel for a given hostname.

use anyhow::Error;
use log::debug;
use std::time::Instant;

use crate::dns::{resolve_host_to_ip, reverse_dns_lookup};
use crate::tls::get_ssl_certificate_info;
use crate::utils::duration_to_ms;

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
/// * `_run_id` - Run identifier for partial failure tracking
///
/// # Returns
///
/// Returns TLS/DNS data and any partial failures (errors that didn't prevent processing).
/// DNS/TLS failures are recorded as partial failures, not as errors that stop processing.
pub(crate) async fn fetch_tls_and_dns(
    final_url: &str,
    host: &str,
    resolver: &hickory_resolver::TokioResolver,
    final_domain: &str,
    error_stats: &crate::error_handling::ProcessingStats,
    _run_id: Option<&str>, // Reserved for future use (partial failure tracking)
) -> Result<(TlsDnsResult, (u64, u64, u64)), Error> {
    // Run TLS and DNS operations in parallel (they're independent)
    let tls_start = Instant::now();

    let (tls_result, dns_result) = tokio::join!(
        // TLS certificate extraction (only for HTTPS)
        async {
            if final_url.starts_with("https://") {
                get_ssl_certificate_info(host.to_string()).await
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
                })
            }
        },
        // DNS resolution (IP address and reverse DNS)
        async {
            let forward_start = Instant::now();
            let ip_result = resolve_host_to_ip(host, resolver).await;
            let forward_ms = duration_to_ms(forward_start.elapsed());

            let reverse_start = Instant::now();
            let result = match ip_result {
                Ok(ip) => {
                    let reverse_result = reverse_dns_lookup(&ip, resolver).await;
                    let reverse_ms = duration_to_ms(reverse_start.elapsed());
                    match reverse_result {
                        Ok(reverse_dns) => Ok((ip, reverse_dns, forward_ms, reverse_ms)),
                        Err(e) => Err((e, forward_ms, reverse_ms)),
                    }
                }
                Err(e) => Err((e, forward_ms, 0)),
            };
            result
        }
    );

    let tls_handshake_ms = duration_to_ms(tls_start.elapsed());
    let (dns_result, dns_forward_ms, dns_reverse_ms) = match dns_result {
        Ok((ip, reverse_dns, forward_ms, reverse_ms)) => {
            (Ok((ip, reverse_dns)), forward_ms, reverse_ms)
        }
        Err((e, forward_ms, reverse_ms)) => (Err(e), forward_ms, reverse_ms),
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
        ),
        Err(e) => {
            log::error!("Failed to get SSL certificate info for {final_domain}: {e}");
            error_stats.increment_error(crate::error_handling::ErrorType::TlsCertificateError);
            // Record as partial failure using ErrorType enum
            // Sanitize and truncate error message to prevent database bloat
            let error_msg = format!("Failed to get SSL certificate info for {final_domain}: {e}");
            let truncated_msg =
                crate::utils::sanitize::sanitize_and_truncate_error_message(&error_msg);
            partial_failures.push((
                crate::error_handling::ErrorType::TlsCertificateError,
                truncated_msg,
            ));
            (None, None, None, None, None, None, None, None, None)
        }
    };

    debug!(
        "Extracted SSL info for {final_domain}: {tls_version:?}, {subject:?}, {issuer:?}, {valid_from:?}, {valid_to:?}"
    );

    // Extract DNS info and record partial failures
    // If DNS resolution fails, continue with None values rather than failing the entire request
    // This makes the system more resilient to DNS issues
    let (ip_address, reverse_dns_name) = match dns_result {
        Ok((ip, reverse_dns)) => (ip, reverse_dns),
        Err(e) => {
            log::warn!(
                "Failed to resolve DNS for {final_domain}: {e} - continuing without IP address"
            );
            error_stats.increment_error(crate::error_handling::ErrorType::DnsNsLookupError);
            // Record as partial failure using ErrorType enum
            // Sanitize and truncate error message to prevent database bloat
            let error_msg = format!("Failed to resolve DNS for {final_domain}: {e}");
            let truncated_msg =
                crate::utils::sanitize::sanitize_and_truncate_error_message(&error_msg);
            partial_failures.push((
                crate::error_handling::ErrorType::DnsNsLookupError,
                truncated_msg,
            ));
            (String::new(), None) // Use empty string for IP, None for reverse DNS
        }
    };

    debug!("Resolved IP address: {ip_address}");
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
            },
            partial_failures,
        },
        (dns_forward_ms, dns_reverse_ms, tls_handshake_ms),
    ))
}
