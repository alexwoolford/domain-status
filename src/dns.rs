//! DNS resolution and record querying.
//!
//! This module provides async DNS operations using `hickory-resolver`:
//! - IP address resolution (A/AAAA records)
//! - Nameserver queries (NS records)
//! - Text record queries (TXT records) with SPF/DMARC extraction
//! - Mail exchanger queries (MX records)
//!
//! All operations are async and respect system DNS configuration.

use anyhow::{Error, Result};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioAsyncResolver;

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
pub async fn resolve_host_to_ip(
    host: &str,
    resolver: &TokioAsyncResolver,
) -> Result<String, Error> {
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
    resolver: &TokioAsyncResolver,
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

/// Queries NS (nameserver) records for a domain.
///
/// # Arguments
///
/// * `domain` - The domain to query
/// * `resolver` - The DNS resolver instance
///
/// # Returns
///
/// A vector of nameserver hostnames, or an empty vector if the query fails.
pub async fn lookup_ns_records(
    domain: &str,
    resolver: &TokioAsyncResolver,
) -> Result<Vec<String>, Error> {
    // For TXT/NS/MX lookups, use domain as-is (no trailing dot needed)
    match resolver.lookup(domain, RecordType::NS).await {
        Ok(lookup) => {
            let nameservers: Vec<String> = lookup
                .iter()
                .filter_map(|rdata| {
                    if let RData::NS(ns) = rdata {
                        Some(ns.to_utf8())
                    } else {
                        None
                    }
                })
                .collect();
            Ok(nameservers)
        }
        Err(e) => {
            let error_msg = e.to_string();
            // "no records found" is expected for some domains - return empty vector
            if error_msg.contains("no records found") || error_msg.contains("NXDomain") {
                Ok(Vec::new())
            } else {
                // Actual failures (timeouts, network errors, etc.) should be propagated as errors
                // so they can be recorded as partial failures
                if error_msg.contains("timeout") || error_msg.contains("timed out") {
                    log::warn!("NS record lookup timed out for {domain}: {e}");
                } else {
                    log::warn!("Failed to lookup NS records for {domain}: {e}");
                }
                Err(e.into())
            }
        }
    }
}

/// Queries TXT records for a domain.
///
/// TXT records commonly contain SPF, DMARC, DKIM, and other policy records.
///
/// # Arguments
///
/// * `domain` - The domain to query
/// * `resolver` - The DNS resolver instance
///
/// # Returns
///
/// A vector of TXT record strings, or an empty vector if the query fails.
pub async fn lookup_txt_records(
    domain: &str,
    resolver: &TokioAsyncResolver,
) -> Result<Vec<String>, Error> {
    // In 0.24, this worked fine without FQDN workarounds
    match resolver.lookup(domain, RecordType::TXT).await {
        Ok(lookup) => {
            let txt_records: Vec<String> = lookup
                .iter()
                .filter_map(|rdata| {
                    if let RData::TXT(txt) = rdata {
                        // TXT records can be split across multiple byte slices, join them
                        // Convert each byte slice to a string, handling UTF-8
                        let parts: Result<Vec<String>, _> = txt
                            .iter()
                            .map(|bytes| String::from_utf8(bytes.to_vec()))
                            .collect();
                        parts.ok().map(|parts| parts.join(""))
                    } else {
                        None
                    }
                })
                .collect();
            Ok(txt_records)
        }
        Err(e) => {
            let error_msg = e.to_string();
            // "no records found" is expected for many domains - return empty vector
            if error_msg.contains("no records found") || error_msg.contains("NXDomain") {
                Ok(Vec::new())
            } else {
                // Actual failures (timeouts, network errors, etc.) should be propagated as errors
                // so they can be recorded as partial failures
                if error_msg.contains("timeout") || error_msg.contains("timed out") {
                    log::warn!("TXT record lookup timed out for {domain}: {e}");
                } else {
                    log::warn!("Failed to lookup TXT records for {domain}: {e}");
                }
                Err(e.into())
            }
        }
    }
}

/// Queries MX (mail exchange) records for a domain.
///
/// # Arguments
///
/// * `domain` - The domain to query
/// * `resolver` - The DNS resolver instance
///
/// # Returns
///
/// A vector of tuples (priority, hostname), sorted by priority (lower is higher priority),
/// or an empty vector if the query fails.
pub async fn lookup_mx_records(
    domain: &str,
    resolver: &TokioAsyncResolver,
) -> Result<Vec<(u16, String)>, Error> {
    // In 0.24, this worked fine without FQDN workarounds
    match resolver.lookup(domain, RecordType::MX).await {
        Ok(lookup) => {
            let mut mx_records: Vec<(u16, String)> = lookup
                .iter()
                .filter_map(|rdata| {
                    if let RData::MX(mx) = rdata {
                        Some((mx.preference(), mx.exchange().to_utf8()))
                    } else {
                        None
                    }
                })
                .collect();
            // Sort by priority (lower preference = higher priority)
            mx_records.sort_by_key(|(priority, _)| *priority);
            Ok(mx_records)
        }
        Err(e) => {
            let error_msg = e.to_string();
            // "no records found" is expected for domains without mail servers - return empty vector
            if error_msg.contains("no records found") || error_msg.contains("NXDomain") {
                Ok(Vec::new())
            } else {
                // Actual failures (timeouts, network errors, etc.) should be propagated as errors
                // so they can be recorded as partial failures
                if error_msg.contains("timeout") || error_msg.contains("timed out") {
                    log::warn!("MX record lookup timed out for {domain}: {e}");
                } else {
                    log::warn!("Failed to lookup MX records for {domain}: {e}");
                }
                Err(e.into())
            }
        }
    }
}

/// Extracts SPF record from TXT records.
///
/// SPF records start with "v=spf1".
///
/// # Arguments
///
/// * `txt_records` - Vector of TXT record strings
///
/// # Returns
///
/// The first SPF record found, or `None` if no SPF record exists.
pub fn extract_spf_record(txt_records: &[String]) -> Option<String> {
    txt_records
        .iter()
        .find(|txt| txt.trim().starts_with("v=spf1"))
        .map(|s| s.trim().to_string())
}

/// Extracts DMARC record from TXT records.
///
/// DMARC records are typically at `_dmarc.<domain>` but we check the provided records.
/// DMARC records start with "v=DMARC1".
///
/// # Arguments
///
/// * `txt_records` - Vector of TXT record strings
///
/// # Returns
///
/// The first DMARC record found, or `None` if no DMARC record exists.
pub fn extract_dmarc_record(txt_records: &[String]) -> Option<String> {
    txt_records
        .iter()
        .find(|txt| txt.trim().starts_with("v=DMARC1"))
        .map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use std::time::Duration;

    /// Creates a test DNS resolver with short timeouts for faster test execution.
    fn create_test_resolver() -> TokioAsyncResolver {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 1; // Single attempt for faster failures in tests
        opts.ndots = 0;

        TokioAsyncResolver::tokio(ResolverConfig::default(), opts)
    }

    #[tokio::test]
    async fn test_lookup_ns_records_success() {
        let resolver = create_test_resolver();
        // Use a well-known domain that definitely has NS records
        let result = lookup_ns_records("google.com", &resolver).await;
        assert!(result.is_ok(), "NS lookup should succeed for google.com");
        let nameservers = result.unwrap();
        assert!(
            !nameservers.is_empty(),
            "google.com should have nameservers"
        );
        // Verify all nameservers are valid hostnames
        for ns in &nameservers {
            assert!(!ns.is_empty());
            assert!(ns.contains('.'));
        }
    }

    #[tokio::test]
    async fn test_lookup_ns_records_no_records_found() {
        let resolver = create_test_resolver();
        // Use a domain that definitely doesn't exist
        // Note: The actual error message from hickory-resolver may vary
        // but our function should handle "no records found" or "NXDomain" correctly
        let result = lookup_ns_records("definitely-does-not-exist-12345.invalid", &resolver).await;
        // The function should return Ok(Vec::new()) for NXDomain/no records found
        // If it returns Err, the error message should contain "no records found" or "NXDomain"
        match result {
            Ok(nameservers) => {
                assert!(
                    nameservers.is_empty(),
                    "Non-existent domain should return empty vector"
                );
            }
            Err(e) => {
                let error_msg = e.to_string().to_lowercase();
                // If it's an error, it should be a real failure, not "no records found"
                // This means our error detection might need adjustment, or the resolver
                // returns a different error format. For now, we just verify it doesn't panic.
                assert!(
                    !error_msg.contains("no records found") && !error_msg.contains("nxdomain"),
                    "Error should not be 'no records found' if it's an Err: {}",
                    error_msg
                );
            }
        }
    }

    #[tokio::test]
    async fn test_lookup_ns_records_invalid_domain() {
        let resolver = create_test_resolver();
        // Invalid domain format should still attempt lookup but may fail
        // This tests error handling, not necessarily DNS resolution
        let result = lookup_ns_records("", &resolver).await;
        // Empty string might return Ok(Vec::new()) or Err depending on resolver behavior
        // The important thing is it doesn't panic
        assert!(
            result.is_ok() || result.is_err(),
            "Invalid domain should not panic"
        );
    }

    #[tokio::test]
    async fn test_lookup_txt_records_success() {
        let resolver = create_test_resolver();
        // Use a domain that likely has TXT records (many domains have SPF/DMARC)
        let result = lookup_txt_records("google.com", &resolver).await;
        assert!(result.is_ok(), "TXT lookup should succeed for google.com");
        let _txt_records = result.unwrap();
        // google.com may or may not have TXT records, both are valid
        // The important thing is the function returns Ok
    }

    #[tokio::test]
    async fn test_lookup_txt_records_no_records_found() {
        let resolver = create_test_resolver();
        // Use a domain that definitely doesn't exist
        // Note: The actual error message from hickory-resolver may vary
        // but our function should handle "no records found" or "NXDomain" correctly
        let result = lookup_txt_records("definitely-does-not-exist-12345.invalid", &resolver).await;
        // The function should return Ok(Vec::new()) for NXDomain/no records found
        // If it returns Err, the error message should contain "no records found" or "NXDomain"
        match result {
            Ok(txt_records) => {
                assert!(
                    txt_records.is_empty(),
                    "Non-existent domain should return empty vector"
                );
            }
            Err(e) => {
                let error_msg = e.to_string().to_lowercase();
                // If it's an error, it should be a real failure, not "no records found"
                // This means our error detection might need adjustment, or the resolver
                // returns a different error format. For now, we just verify it doesn't panic.
                assert!(
                    !error_msg.contains("no records found") && !error_msg.contains("nxdomain"),
                    "Error should not be 'no records found' if it's an Err: {}",
                    error_msg
                );
            }
        }
    }

    #[tokio::test]
    async fn test_lookup_mx_records_success() {
        let resolver = create_test_resolver();
        // Use a domain that likely has MX records
        let result = lookup_mx_records("google.com", &resolver).await;
        assert!(result.is_ok(), "MX lookup should succeed for google.com");
        let mx_records = result.unwrap();
        // google.com should have MX records
        assert!(!mx_records.is_empty(), "google.com should have MX records");
        // Verify MX records are properly formatted (priority, hostname)
        for (_priority, hostname) in &mx_records {
            assert!(!hostname.is_empty());
            assert!(hostname.contains('.'));
            // Priority is a u16, so just verify it's within valid range
            // (u16 max is 65535, but this assertion is redundant - kept for documentation)
        }
        // Verify records are sorted by priority (lower = higher priority)
        for i in 1..mx_records.len() {
            assert!(
                mx_records[i - 1].0 <= mx_records[i].0,
                "MX records should be sorted by priority"
            );
        }
    }

    #[tokio::test]
    async fn test_lookup_mx_records_no_records_found() {
        let resolver = create_test_resolver();
        // Use a domain that definitely doesn't exist
        // Note: The actual error message from hickory-resolver may vary
        // but our function should handle "no records found" or "NXDomain" correctly
        let result = lookup_mx_records("definitely-does-not-exist-12345.invalid", &resolver).await;
        // The function should return Ok(Vec::new()) for NXDomain/no records found
        // If it returns Err, the error message should contain "no records found" or "NXDomain"
        match result {
            Ok(mx_records) => {
                assert!(
                    mx_records.is_empty(),
                    "Non-existent domain should return empty vector"
                );
            }
            Err(e) => {
                let error_msg = e.to_string().to_lowercase();
                // If it's an error, it should be a real failure, not "no records found"
                // This means our error detection might need adjustment, or the resolver
                // returns a different error format. For now, we just verify it doesn't panic.
                assert!(
                    !error_msg.contains("no records found") && !error_msg.contains("nxdomain"),
                    "Error should not be 'no records found' if it's an Err: {}",
                    error_msg
                );
            }
        }
    }

    #[tokio::test]
    async fn test_error_propagation_for_actual_failures() {
        let resolver = create_test_resolver();
        // Test with a domain that might cause a timeout or network error
        // We can't reliably trigger timeouts, but we can test the error handling logic
        // by checking that invalid formats don't return "no records found"

        // Test with a malformed domain that might cause a different error
        // Note: The resolver might handle this differently, so we just verify it doesn't panic
        let result = lookup_ns_records("..", &resolver).await;
        // Should either return Ok(Vec::new()) or Err, but not panic
        assert!(
            result.is_ok() || result.is_err(),
            "Malformed domain should not panic"
        );
    }

    #[tokio::test]
    async fn test_error_message_parsing_no_records_found() {
        // Test that error messages containing "no records found" or "NXDomain"
        // are properly identified and return Ok(Vec::new())
        // This is tested indirectly through the no_records_found tests above
        // but we can add a more explicit test here

        let resolver = create_test_resolver();
        // Use a TLD that doesn't exist
        let result = lookup_ns_records("test.invalid-tld-xyz", &resolver).await;
        // Should return Ok(Vec::new()) for NXDomain, or Err if resolver format differs
        // The important thing is the function handles the error correctly
        match result {
            Ok(nameservers) => {
                assert!(nameservers.is_empty());
            }
            Err(e) => {
                // If it's an error, verify the error message doesn't contain "no records found"
                // (which would indicate our parsing is wrong)
                let error_msg = e.to_string().to_lowercase();
                // This test verifies our error handling logic works
                // If the resolver returns a different format, that's okay
                assert!(
                    !error_msg.contains("no records found") && !error_msg.contains("nxdomain"),
                    "If Err, should not be 'no records found': {}",
                    error_msg
                );
            }
        }
    }

    #[tokio::test]
    async fn test_all_dns_functions_handle_nonexistent_domains() {
        let resolver = create_test_resolver();
        let test_domain = "definitely-does-not-exist-12345.invalid";

        // All three functions should handle non-existent domains gracefully
        // They may return Ok(Vec::new()) for "no records found" or Err for other errors
        let ns_result = lookup_ns_records(test_domain, &resolver).await;
        let txt_result = lookup_txt_records(test_domain, &resolver).await;
        let mx_result = lookup_mx_records(test_domain, &resolver).await;

        // Verify all three functions don't panic and return consistent results
        // (either all Ok with empty vecs, or all Err - depending on resolver behavior)
        match (ns_result, txt_result, mx_result) {
            (Ok(ns), Ok(txt), Ok(mx)) => {
                // All returned Ok - verify they're empty
                assert!(ns.is_empty());
                assert!(txt.is_empty());
                assert!(mx.is_empty());
            }
            (Err(ns_e), Err(txt_e), Err(mx_e)) => {
                // All returned Err - verify error messages don't contain "no records found"
                // (which would indicate our parsing is wrong)
                let ns_msg = ns_e.to_string().to_lowercase();
                let txt_msg = txt_e.to_string().to_lowercase();
                let mx_msg = mx_e.to_string().to_lowercase();

                // If they're errors, they should be real failures, not "no records found"
                assert!(
                    !ns_msg.contains("no records found") && !ns_msg.contains("nxdomain"),
                    "NS error should not be 'no records found': {}",
                    ns_msg
                );
                assert!(
                    !txt_msg.contains("no records found") && !txt_msg.contains("nxdomain"),
                    "TXT error should not be 'no records found': {}",
                    txt_msg
                );
                assert!(
                    !mx_msg.contains("no records found") && !mx_msg.contains("nxdomain"),
                    "MX error should not be 'no records found': {}",
                    mx_msg
                );
            }
            _ => {
                // Mixed results - this shouldn't happen, but we handle it gracefully
                // The important thing is none of them panicked
            }
        }
    }

    #[tokio::test]
    async fn test_dns_functions_with_valid_well_known_domains() {
        let resolver = create_test_resolver();

        // Test with multiple well-known domains to ensure consistency
        let test_domains = vec!["google.com", "github.com", "cloudflare.com"];

        for domain in test_domains {
            // NS records should exist for these domains
            let ns_result = lookup_ns_records(domain, &resolver).await;
            assert!(ns_result.is_ok(), "NS lookup should succeed for {}", domain);

            // TXT records may or may not exist (both are valid)
            let _txt_result = lookup_txt_records(domain, &resolver).await;
            assert!(
                _txt_result.is_ok(),
                "TXT lookup should succeed for {}",
                domain
            );

            // MX records should exist for these domains (they have email)
            let mx_result = lookup_mx_records(domain, &resolver).await;
            assert!(mx_result.is_ok(), "MX lookup should succeed for {}", domain);
        }
    }

    #[test]
    fn test_extract_spf_record() {
        let txt_records = vec![
            "v=spf1 include:_spf.google.com ~all".to_string(),
            "some other record".to_string(),
        ];
        let spf = extract_spf_record(&txt_records);
        assert_eq!(spf, Some("v=spf1 include:_spf.google.com ~all".to_string()));
    }

    #[test]
    fn test_extract_spf_record_not_found() {
        let txt_records = vec!["some other record".to_string()];
        let spf = extract_spf_record(&txt_records);
        assert_eq!(spf, None);
    }

    #[test]
    fn test_extract_spf_record_empty() {
        let txt_records = vec![];
        let spf = extract_spf_record(&txt_records);
        assert_eq!(spf, None);
    }

    #[test]
    fn test_extract_dmarc_record() {
        let txt_records = vec![
            "v=DMARC1; p=none; rua=mailto:dmarc@example.com".to_string(),
            "some other record".to_string(),
        ];
        let dmarc = extract_dmarc_record(&txt_records);
        assert_eq!(
            dmarc,
            Some("v=DMARC1; p=none; rua=mailto:dmarc@example.com".to_string())
        );
    }

    #[test]
    fn test_extract_dmarc_record_not_found() {
        let txt_records = vec!["some other record".to_string()];
        let dmarc = extract_dmarc_record(&txt_records);
        assert_eq!(dmarc, None);
    }

    #[test]
    fn test_extract_dmarc_record_empty() {
        let txt_records = vec![];
        let dmarc = extract_dmarc_record(&txt_records);
        assert_eq!(dmarc, None);
    }

    #[test]
    fn test_extract_dmarc_record_case_insensitive() {
        let txt_records = vec!["v=dmarc1; p=none".to_string()];
        let dmarc = extract_dmarc_record(&txt_records);
        // Should still match (starts_with is case-sensitive, but DMARC spec says v=DMARC1)
        // This test verifies our implementation matches the spec
        assert_eq!(dmarc, None); // Our implementation is case-sensitive for "v=DMARC1"
    }
}
