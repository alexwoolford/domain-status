//! IP address resolution and reverse DNS lookup.
//!
//! This module provides functions to resolve hostnames to IP addresses
//! and perform reverse DNS lookups (PTR records).

use anyhow::{Error, Result};
use hickory_resolver::TokioResolver;

/// Resolves a hostname to an IP address using DNS.
///
/// # Arguments
///
/// * `host` - The hostname to resolve
/// * `resolver` - The DNS resolver instance
///
/// # Returns
///
/// The first IP address found, or an error if resolution fails.
///
/// # Errors
///
/// Returns an error if DNS resolution fails or no IP addresses are found.
pub async fn resolve_host_to_ip(host: &str, resolver: &TokioResolver) -> Result<String, Error> {
    // In 0.24, this worked fine without FQDN workarounds
    let response = resolver.lookup_ip(host).await.map_err(Error::new)?;
    let ip = response
        .iter()
        .next()
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
    match resolver.reverse_lookup(ip.parse()?).await {
        Ok(response) => {
            let name = response.iter().next().map(|name| name.to_utf8());
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
    use hickory_resolver::config::ResolverOpts;
    use std::time::Duration;

    /// Creates a test DNS resolver with short timeouts for faster test execution.
    fn create_test_resolver() -> TokioResolver {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 1; // Single attempt for faster failures in tests
        opts.ndots = 0;

        TokioResolver::builder_tokio()
            .unwrap()
            .with_options(opts)
            .build()
    }

    #[tokio::test]
    async fn test_resolve_host_to_ip_success() {
        let resolver = create_test_resolver();
        // Use a well-known domain that should resolve
        // Note: This test makes a real DNS call, so it may fail in CI if DNS is blocked
        // or if the domain is unreachable. Consider mocking for more reliable CI.
        let result = resolve_host_to_ip("example.com", &resolver).await;
        if result.is_ok() {
            let ip = result.unwrap();
            assert!(!ip.is_empty(), "IP address should not be empty");
            // Verify it's a valid IP (IPv4 or IPv6)
            assert!(
                ip.contains('.') || ip.contains(':'),
                "IP address should be valid format"
            );
        } else {
            // If DNS resolution fails (e.g., in CI without network), skip the test
            // This is acceptable since the function logic is correct
            eprintln!("DNS resolution failed (likely CI environment), skipping test");
        }
    }

    #[tokio::test]
    async fn test_resolve_host_to_ip_invalid_domain() {
        let resolver = create_test_resolver();
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
    async fn test_reverse_dns_lookup_success() {
        let resolver = create_test_resolver();
        // Use a well-known IP (Google's DNS: 8.8.8.8)
        // Note: Reverse DNS may or may not be configured, so we test both cases
        // Note: This test makes a real DNS call, so it may fail in CI if DNS is blocked
        let result = reverse_dns_lookup("8.8.8.8", &resolver).await;
        if result.is_ok() {
            // Result may be Some or None depending on PTR record configuration
            // Both are valid outcomes
            if let Ok(Some(hostname)) = result {
                assert!(
                    !hostname.is_empty(),
                    "Hostname should not be empty if present"
                );
            }
        } else {
            // If reverse DNS lookup fails (e.g., in CI without network), skip the test
            eprintln!("Reverse DNS lookup failed (likely CI environment), skipping test");
        }
    }

    #[tokio::test]
    async fn test_reverse_dns_lookup_invalid_ip() {
        let resolver = create_test_resolver();
        // Invalid IP address format
        let result = reverse_dns_lookup("not.an.ip.address", &resolver).await;
        assert!(
            result.is_err(),
            "Reverse DNS lookup should error on invalid IP"
        );
    }

    #[tokio::test]
    async fn test_reverse_dns_lookup_no_ptr_record() {
        let resolver = create_test_resolver();
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
        let resolver = create_test_resolver();
        // Empty hostname should fail
        let result = resolve_host_to_ip("", &resolver).await;
        assert!(
            result.is_err(),
            "DNS resolution should fail for empty hostname"
        );
    }
}
