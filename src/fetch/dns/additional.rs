//! Additional DNS records fetching.
//!
//! This module handles fetching additional DNS records (NS, TXT, MX) and
//! extracting SPF/DMARC records from TXT records.

use log::debug;

use crate::dns::{
    extract_dmarc_record, extract_spf_record, lookup_aaaa_records, lookup_caa_records,
    lookup_cname_records, lookup_mx_records, lookup_ns_records, lookup_txt_records,
};
use crate::fetch::utils::serialize_json_with_default;

use super::types::{AdditionalDnsData, AdditionalDnsResult};

/// Fetches additional DNS records (NS, TXT, MX) in parallel.
///
/// # Arguments
///
/// * `final_domain` - The final domain to query
/// * `resolver` - DNS resolver
/// * `error_stats` - Processing statistics tracker
///
/// # Returns
///
/// Returns DNS data and any partial failures (errors that didn't prevent processing).
#[allow(clippy::too_many_lines)] // Fetches NS/TXT/MX/CNAME/AAAA/CAA records in parallel; inherently sequential result assembly
#[allow(clippy::cognitive_complexity)] // Each DNS record type has distinct parsing logic
pub(crate) async fn fetch_additional_dns_records(
    final_domain: &str,
    resolver: &hickory_resolver::TokioResolver,
    error_stats: &crate::error_handling::ProcessingStats,
) -> AdditionalDnsResult {
    // Query additional DNS records (NS, TXT, MX, CNAME, AAAA, CAA) in parallel
    let (ns_result, txt_result, mx_result, cname_result, aaaa_result, caa_result) = tokio::join!(
        lookup_ns_records(final_domain, resolver),
        lookup_txt_records(final_domain, resolver),
        lookup_mx_records(final_domain, resolver),
        lookup_cname_records(final_domain, resolver),
        lookup_aaaa_records(final_domain, resolver),
        lookup_caa_records(final_domain, resolver)
    );

    let mut partial_failures = Vec::new();

    let nameservers = match ns_result {
        Ok(ns) if !ns.is_empty() => {
            debug!("Found {} nameservers for {}", ns.len(), final_domain);
            Some(serialize_json_with_default(&ns, "[]"))
        }
        Ok(_) => None,
        Err(e) => {
            log::warn!("Failed to lookup NS records for {final_domain}: {e}");
            error_stats.increment_error(crate::error_handling::ErrorType::DnsNsLookupError);
            // Sanitize and truncate error message to prevent database bloat
            let error_msg = format!("Failed to lookup NS records for {final_domain}: {e}");
            let truncated_msg =
                crate::utils::sanitize::sanitize_and_truncate_error_message(&error_msg);
            partial_failures.push((
                crate::error_handling::ErrorType::DnsNsLookupError,
                truncated_msg,
            ));
            None
        }
    };

    // Extract TXT records for both JSON storage and SPF/DMARC extraction
    let txt_for_extraction = match &txt_result {
        Ok(records) => records.clone(),
        Err(e) => {
            log::debug!("Failed to extract TXT records for pattern matching: {e}");
            Vec::new()
        }
    };

    let txt_records = match txt_result {
        Ok(txt) if !txt.is_empty() => {
            debug!("Found {} TXT records for {}", txt.len(), final_domain);
            Some(serialize_json_with_default(&txt, "[]"))
        }
        Ok(_) => None,
        Err(e) => {
            log::warn!("Failed to lookup TXT records for {final_domain}: {e}");
            error_stats.increment_error(crate::error_handling::ErrorType::DnsTxtLookupError);
            // Sanitize and truncate error message to prevent database bloat
            let error_msg = format!("Failed to lookup TXT records for {final_domain}: {e}");
            let truncated_msg =
                crate::utils::sanitize::sanitize_and_truncate_error_message(&error_msg);
            partial_failures.push((
                crate::error_handling::ErrorType::DnsTxtLookupError,
                truncated_msg,
            ));
            None
        }
    };

    // Extract SPF and DMARC from TXT records
    let spf_record = extract_spf_record(&txt_for_extraction);
    let mut dmarc_record = extract_dmarc_record(&txt_for_extraction);

    // Also check _dmarc subdomain for DMARC
    if dmarc_record.is_none() {
        if let Ok(dmarc_txt) = lookup_txt_records(&format!("_dmarc.{final_domain}"), resolver).await
        {
            dmarc_record = extract_dmarc_record(&dmarc_txt);
        }
    }

    let mx_records = match mx_result {
        Ok(mx) if !mx.is_empty() => {
            debug!("Found {} MX records for {}", mx.len(), final_domain);
            // Store as JSON array of objects: [{"priority": 10, "hostname": "mail.example.com"}, ...]
            let mx_json: Vec<serde_json::Value> = mx
                .into_iter()
                .map(|(priority, hostname)| {
                    serde_json::json!({
                        "priority": priority,
                        "hostname": hostname
                    })
                })
                .collect();
            Some(serialize_json_with_default(&mx_json, "[]"))
        }
        Ok(_) => None,
        Err(e) => {
            log::warn!("Failed to lookup MX records for {final_domain}: {e}");
            error_stats.increment_error(crate::error_handling::ErrorType::DnsMxLookupError);
            // Sanitize and truncate error message to prevent database bloat
            let error_msg = format!("Failed to lookup MX records for {final_domain}: {e}");
            let truncated_msg =
                crate::utils::sanitize::sanitize_and_truncate_error_message(&error_msg);
            partial_failures.push((
                crate::error_handling::ErrorType::DnsMxLookupError,
                truncated_msg,
            ));
            None
        }
    };

    // Process CNAME results
    let cname_chain = match cname_result {
        Ok(cnames) if !cnames.is_empty() => {
            debug!("Found {} CNAME records for {}", cnames.len(), final_domain);
            Some(serialize_json_with_default(&cnames, "[]"))
        }
        Ok(_) => None,
        Err(e) => {
            log::warn!("Failed to lookup CNAME records for {final_domain}: {e}");
            error_stats.increment_error(crate::error_handling::ErrorType::DnsCnameLookupError);
            let error_msg = format!("Failed to lookup CNAME records for {final_domain}: {e}");
            let truncated_msg =
                crate::utils::sanitize::sanitize_and_truncate_error_message(&error_msg);
            partial_failures.push((
                crate::error_handling::ErrorType::DnsCnameLookupError,
                truncated_msg,
            ));
            None
        }
    };

    // Process AAAA (IPv6) results
    let aaaa_records = match aaaa_result {
        Ok(addrs) if !addrs.is_empty() => {
            debug!("Found {} AAAA records for {}", addrs.len(), final_domain);
            Some(serialize_json_with_default(&addrs, "[]"))
        }
        Ok(_) => None,
        Err(e) => {
            log::warn!("Failed to lookup AAAA records for {final_domain}: {e}");
            error_stats.increment_error(crate::error_handling::ErrorType::DnsAaaaLookupError);
            let error_msg = format!("Failed to lookup AAAA records for {final_domain}: {e}");
            let truncated_msg =
                crate::utils::sanitize::sanitize_and_truncate_error_message(&error_msg);
            partial_failures.push((
                crate::error_handling::ErrorType::DnsAaaaLookupError,
                truncated_msg,
            ));
            None
        }
    };

    // Process CAA results
    let caa_records = match caa_result {
        Ok(caas) if !caas.is_empty() => {
            debug!("Found {} CAA records for {}", caas.len(), final_domain);
            let caa_json: Vec<serde_json::Value> = caas
                .into_iter()
                .map(|(flag, tag, value)| {
                    serde_json::json!({
                        "flag": flag,
                        "tag": tag,
                        "value": value
                    })
                })
                .collect();
            Some(serialize_json_with_default(&caa_json, "[]"))
        }
        Ok(_) => None,
        Err(e) => {
            log::warn!("Failed to lookup CAA records for {final_domain}: {e}");
            error_stats.increment_error(crate::error_handling::ErrorType::DnsCaaLookupError);
            let error_msg = format!("Failed to lookup CAA records for {final_domain}: {e}");
            let truncated_msg =
                crate::utils::sanitize::sanitize_and_truncate_error_message(&error_msg);
            partial_failures.push((
                crate::error_handling::ErrorType::DnsCaaLookupError,
                truncated_msg,
            ));
            None
        }
    };

    AdditionalDnsResult {
        data: AdditionalDnsData {
            nameservers,
            txt_records,
            mx_records,
            spf_record,
            dmarc_record,
            cname_chain,
            aaaa_records,
            caa_records,
        },
        partial_failures,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ProcessingStats;
    use crate::initialization::test_resolver;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_fetch_additional_dns_records_invalid_domain() {
        let resolver = test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        let result = fetch_additional_dns_records(
            "this-domain-definitely-does-not-exist-12345.invalid",
            &resolver,
            error_stats.as_ref(),
        )
        .await;

        // Should return empty data (DNS lookups will fail for invalid domain)
        assert!(result.data.nameservers.is_none());
        assert!(result.data.txt_records.is_none());
        assert!(result.data.mx_records.is_none());
        assert!(result.data.spf_record.is_none());
        assert!(result.data.dmarc_record.is_none());
        // May or may not have partial failures depending on DNS resolver behavior
        // (Some resolvers may return empty results without errors)
    }

    #[test]
    fn test_spf_extraction_edge_cases() {
        // Test SPF extraction with various edge cases
        // This tests the extract_spf_record function indirectly through fetch_additional_dns_records
        use crate::dns::extract_spf_record;

        // Valid SPF record
        let txt_with_spf = vec!["v=spf1 include:_spf.google.com ~all".to_string()];
        let spf = extract_spf_record(&txt_with_spf);
        assert!(spf.is_some(), "Should extract valid SPF record");
        assert!(
            spf.unwrap().starts_with("v=spf1"),
            "SPF should start with v=spf1"
        );

        // Multiple TXT records, SPF not first
        let txt_multiple = vec![
            "some other record".to_string(),
            "v=spf1 include:_spf.google.com ~all".to_string(),
        ];
        let spf = extract_spf_record(&txt_multiple);
        assert!(spf.is_some(), "Should extract SPF even if not first");

        // SPF with redirect modifier
        let txt_redirect = vec!["v=spf1 redirect=_spf.example.com".to_string()];
        let spf = extract_spf_record(&txt_redirect);
        assert!(spf.is_some(), "Should extract SPF with redirect");

        // No SPF record
        let txt_no_spf = vec!["some other txt record".to_string()];
        let spf = extract_spf_record(&txt_no_spf);
        assert!(spf.is_none(), "Should return None when no SPF record");

        // Empty TXT records
        let txt_empty: Vec<String> = vec![];
        let spf = extract_spf_record(&txt_empty);
        assert!(spf.is_none(), "Should return None for empty TXT records");
    }

    #[test]
    fn test_dmarc_extraction_edge_cases() {
        // Test DMARC extraction with various edge cases
        use crate::dns::extract_dmarc_record;

        // Valid DMARC record
        let txt_with_dmarc = vec!["v=DMARC1; p=none; rua=mailto:dmarc@example.com".to_string()];
        let dmarc = extract_dmarc_record(&txt_with_dmarc);
        assert!(dmarc.is_some(), "Should extract valid DMARC record");
        assert!(
            dmarc.unwrap().starts_with("v=DMARC1"),
            "DMARC should start with v=DMARC1"
        );

        // DMARC with different policy
        let txt_policy = vec!["v=DMARC1; p=quarantine; pct=100".to_string()];
        let dmarc = extract_dmarc_record(&txt_policy);
        assert!(
            dmarc.is_some(),
            "Should extract DMARC with quarantine policy"
        );

        // DMARC with reject policy
        let txt_reject = vec!["v=DMARC1; p=reject".to_string()];
        let dmarc = extract_dmarc_record(&txt_reject);
        assert!(dmarc.is_some(), "Should extract DMARC with reject policy");

        // Multiple TXT records, DMARC not first
        let txt_multiple = vec![
            "some other record".to_string(),
            "v=DMARC1; p=none".to_string(),
        ];
        let dmarc = extract_dmarc_record(&txt_multiple);
        assert!(dmarc.is_some(), "Should extract DMARC even if not first");

        // No DMARC record
        let txt_no_dmarc = vec!["some other txt record".to_string()];
        let dmarc = extract_dmarc_record(&txt_no_dmarc);
        assert!(dmarc.is_none(), "Should return None when no DMARC record");

        // Empty TXT records
        let txt_empty: Vec<String> = vec![];
        let dmarc = extract_dmarc_record(&txt_empty);
        assert!(dmarc.is_none(), "Should return None for empty TXT records");
    }

    #[tokio::test]
    async fn test_fetch_additional_dns_records_spf_dmarc_extraction() {
        // Test that SPF and DMARC are correctly extracted from TXT records
        // This is critical - SPF/DMARC extraction must work correctly for security analysis
        let resolver = test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());

        // Use a domain that might have SPF/DMARC records
        let result =
            fetch_additional_dns_records("example.com", &resolver, error_stats.as_ref()).await;

        // Result should have valid structure
        // SPF and DMARC may or may not be present depending on actual DNS
        // The key is that extraction logic is exercised
        if let Some(spf) = &result.data.spf_record {
            assert!(
                spf.starts_with("v=spf1"),
                "SPF record should start with v=spf1"
            );
        }
        if let Some(dmarc) = &result.data.dmarc_record {
            assert!(
                dmarc.starts_with("v=DMARC1"),
                "DMARC record should start with v=DMARC1"
            );
        }
    }

    #[tokio::test]
    async fn test_fetch_additional_dns_records_mx_json_format() {
        // Test that MX records are correctly formatted as JSON
        // This is critical - MX records must be in correct format for database storage
        let resolver = test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());

        let result =
            fetch_additional_dns_records("example.com", &resolver, error_stats.as_ref()).await;

        // If MX records are present, they should be valid JSON
        if let Some(mx_json) = &result.data.mx_records {
            // Should be valid JSON array
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(mx_json);
            assert!(parsed.is_ok(), "MX records should be valid JSON");
            if let Ok(json) = parsed {
                assert!(json.is_array(), "MX records JSON should be an array");
            }
        }
    }

    #[tokio::test]
    async fn test_fetch_additional_dns_records_error_message_sanitization() {
        // Test that error messages are correctly sanitized and truncated
        // This is critical - error messages must not cause database bloat
        let resolver = test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());

        let result = fetch_additional_dns_records(
            "this-domain-definitely-does-not-exist-12345.invalid",
            &resolver,
            error_stats.as_ref(),
        )
        .await;

        // Verify partial failures have sanitized messages
        for (_error_type, error_msg) in &result.partial_failures {
            assert!(!error_msg.is_empty(), "Error message should not be empty");
            assert!(
                error_msg.len() <= 500,
                "Error message should be sanitized/truncated to prevent database bloat, got length: {}",
                error_msg.len()
            );
        }
    }
}
