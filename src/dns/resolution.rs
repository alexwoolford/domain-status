//! IP address resolution and reverse DNS lookup.
//!
//! This module provides functions to resolve hostnames to IP addresses
//! and perform reverse DNS lookups (PTR records).

use anyhow::{Error, Result};
use hickory_resolver::TokioResolver;

/// Resolves a hostname to an IP address using DNS.
///
/// Prefers a public IP when the response contains both public and private
/// addresses, so the returned value matches what [`SafeResolver`](crate::security::safe_resolver::SafeResolver) would use
/// for the actual connection (consistent analytics and no misleading private-IP
/// entries when DNS returns multiple addresses).
///
/// # Arguments
///
/// * `host` - The hostname to resolve
/// * `resolver` - The DNS resolver instance
///
/// # Returns
///
/// A public IP if present, otherwise the first IP in the response, or an error
/// if resolution fails or no addresses are found.
///
/// # Errors
///
/// Returns an error if DNS resolution fails or no IP addresses are found.
pub async fn resolve_host_to_ip(host: &str, resolver: &TokioResolver) -> Result<String, Error> {
    // In 0.24, this worked fine without FQDN workarounds
    let response = resolver.lookup_ip(host).await.map_err(Error::new)?;
    let ip = response
        .iter()
        .find(|ip| crate::security::safe_resolver::is_public_ip(*ip))
        .or_else(|| response.iter().next())
        .ok_or_else(|| Error::msg("No IP addresses found"))?
        .to_string();
    Ok(ip)
}

/// Performs a reverse DNS lookup (PTR record) for an IP address.
///
/// # Arguments
///
/// * `ip` - The IP address to look up
/// * `resolver` - The DNS resolver instance
///
/// # Returns
///
/// The reverse DNS name, or `None` if the lookup fails.
pub async fn reverse_dns_lookup(
    ip: &str,
    resolver: &TokioResolver,
) -> Result<Option<String>, Error> {
    use hickory_resolver::proto::rr::Name;
    let addr: std::net::IpAddr = ip.parse()?;
    match resolver.reverse_lookup(Name::from(addr)).await {
        Ok(response) => {
            use hickory_resolver::proto::rr::RData;
            let name = response.answers().iter().find_map(|record| {
                if let RData::PTR(ptr) = &record.data {
                    Some(ptr.to_utf8())
                } else {
                    None
                }
            });
            Ok(name)
        }
        Err(e) => {
            log::warn!("Failed to perform reverse DNS lookup for {ip}: {e}");
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::initialization::test_resolver;

    #[tokio::test]
    #[ignore = "live DNS; run with --ignored"]
    async fn test_resolve_host_to_ip_success() {
        let resolver = test_resolver();
        let ip = resolve_host_to_ip("example.com", &resolver)
            .await
            .expect("example.com should resolve when network DNS is available");
        assert!(!ip.is_empty(), "IP address should not be empty");
        assert!(
            ip.contains('.') || ip.contains(':'),
            "IP address should be IPv4 or IPv6, got {ip}"
        );
    }

    #[tokio::test]
    async fn test_resolve_host_to_ip_invalid_domain() {
        let resolver = test_resolver();
        // Use a domain that definitely doesn't exist
        let result =
            resolve_host_to_ip("this-domain-definitely-does-not-exist-12345.com", &resolver).await;
        // Should fail with an error
        assert!(
            result.is_err(),
            "DNS resolution should fail for non-existent domain"
        );
    }

    #[tokio::test]
    #[ignore = "live reverse DNS; run with --ignored"]
    async fn test_reverse_dns_lookup_success() {
        let resolver = test_resolver();
        let result = reverse_dns_lookup("8.8.8.8", &resolver)
            .await
            .expect("PTR lookup should complete when network DNS is available");
        if let Some(hostname) = result {
            assert!(
                !hostname.is_empty(),
                "PTR hostname should not be empty when present"
            );
        }
    }

    #[tokio::test]
    async fn test_reverse_dns_lookup_invalid_ip() {
        let resolver = test_resolver();
        // Invalid IP address format
        let result = reverse_dns_lookup("not.an.ip.address", &resolver).await;
        assert!(
            result.is_err(),
            "Reverse DNS lookup should error on invalid IP"
        );
    }

    #[tokio::test]
    async fn test_reverse_dns_lookup_no_ptr_record() {
        let resolver = test_resolver();
        // Use a private IP that likely doesn't have a PTR record
        // Note: This may still succeed if the IP has a PTR, so we just verify it doesn't error
        let result = reverse_dns_lookup("192.0.2.1", &resolver).await;
        assert!(
            result.is_ok(),
            "Reverse DNS lookup should not error even if no PTR record"
        );
        // Result will be None if no PTR record exists
    }

    #[tokio::test]
    async fn test_resolve_host_to_ip_empty_host() {
        let resolver = test_resolver();
        // Empty hostname should fail
        let result = resolve_host_to_ip("", &resolver).await;
        assert!(
            result.is_err(),
            "DNS resolution should fail for empty hostname"
        );
    }
}
