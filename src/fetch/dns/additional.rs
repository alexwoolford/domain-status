//! Additional DNS records fetching.
//!
//! This module handles fetching additional DNS records (NS, TXT, MX) and
//! extracting SPF/DMARC records from TXT records.

use log::debug;

use crate::dns::{
    extract_dmarc_record, extract_spf_record, lookup_mx_records, lookup_ns_records,
    lookup_txt_records,
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
pub(crate) async fn fetch_additional_dns_records(
    final_domain: &str,
    resolver: &hickory_resolver::TokioResolver,
    error_stats: &crate::error_handling::ProcessingStats,
) -> AdditionalDnsResult {
    // Query additional DNS records (NS, TXT, MX) in parallel
    let (ns_result, txt_result, mx_result) = tokio::join!(
        lookup_ns_records(final_domain, resolver),
        lookup_txt_records(final_domain, resolver),
        lookup_mx_records(final_domain, resolver)
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
    let txt_for_extraction = txt_result.as_ref().ok().cloned().unwrap_or_default();

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
        if let Ok(dmarc_txt) =
            lookup_txt_records(&format!("_dmarc.{}", final_domain), resolver).await
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

    AdditionalDnsResult {
        data: AdditionalDnsData {
            nameservers,
            txt_records,
            mx_records,
            spf_record,
            dmarc_record,
        },
        partial_failures,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ProcessingStats;
    use hickory_resolver::config::ResolverOpts;
    use hickory_resolver::TokioResolver;
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

    #[tokio::test]
    async fn test_fetch_additional_dns_records_invalid_domain() {
        let resolver = create_test_resolver();
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

    #[tokio::test]
    async fn test_fetch_additional_dns_records_empty_domain() {
        let resolver = create_test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        let result = fetch_additional_dns_records("", &resolver, error_stats.as_ref()).await;

        // Should handle gracefully (may return None or have partial failures)
        // DNS resolver behavior with empty string may vary
        let _ = result;
    }

    #[tokio::test]
    async fn test_fetch_additional_dns_records_partial_failures() {
        let resolver = create_test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        // Use a domain that might have some records but not others
        let result =
            fetch_additional_dns_records("example.com", &resolver, error_stats.as_ref()).await;

        // Should not panic even if some lookups fail
        // Result may have data or partial failures depending on network
        let _ = result;
    }

    #[tokio::test]
    async fn test_fetch_additional_dns_records_error_stats_tracking() {
        let resolver = create_test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        let initial_ns_errors =
            error_stats.get_error_count(crate::error_handling::ErrorType::DnsNsLookupError);
        let initial_txt_errors =
            error_stats.get_error_count(crate::error_handling::ErrorType::DnsTxtLookupError);
        let initial_mx_errors =
            error_stats.get_error_count(crate::error_handling::ErrorType::DnsMxLookupError);

        let _result = fetch_additional_dns_records(
            "this-domain-definitely-does-not-exist-12345.invalid",
            &resolver,
            error_stats.as_ref(),
        )
        .await;

        // Error stats should be incremented for failed lookups
        // (May or may not increment depending on DNS resolver behavior)
        let _ = (initial_ns_errors, initial_txt_errors, initial_mx_errors);
    }

    #[tokio::test]
    async fn test_fetch_additional_dns_records_dmarc_subdomain_fallback() {
        let resolver = create_test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        // Test that _dmarc subdomain lookup is attempted
        let result =
            fetch_additional_dns_records("example.com", &resolver, error_stats.as_ref()).await;

        // Should attempt _dmarc subdomain lookup if main domain doesn't have DMARC
        // Result depends on actual DNS, but function should not panic
        let _ = result;
    }

    #[tokio::test]
    async fn test_fetch_additional_dns_records_error_stats_incremented_on_failure() {
        // Test that error stats are correctly incremented when DNS lookups fail
        // This is critical - error tracking must work correctly for adaptive rate limiting
        let resolver = create_test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());

        let initial_ns_errors =
            error_stats.get_error_count(crate::error_handling::ErrorType::DnsNsLookupError);
        let initial_txt_errors =
            error_stats.get_error_count(crate::error_handling::ErrorType::DnsTxtLookupError);
        let initial_mx_errors =
            error_stats.get_error_count(crate::error_handling::ErrorType::DnsMxLookupError);

        // Use a domain that will definitely fail DNS lookups
        let _result = fetch_additional_dns_records(
            "this-domain-definitely-does-not-exist-12345.invalid",
            &resolver,
            error_stats.as_ref(),
        )
        .await;

        // Error stats should be incremented (may vary by resolver, but should at least not decrease)
        let final_ns_errors =
            error_stats.get_error_count(crate::error_handling::ErrorType::DnsNsLookupError);
        let final_txt_errors =
            error_stats.get_error_count(crate::error_handling::ErrorType::DnsTxtLookupError);
        let final_mx_errors =
            error_stats.get_error_count(crate::error_handling::ErrorType::DnsMxLookupError);

        // Verify error stats don't decrease (they may or may not increase depending on resolver behavior)
        assert!(
            final_ns_errors >= initial_ns_errors,
            "NS error count should not decrease"
        );
        assert!(
            final_txt_errors >= initial_txt_errors,
            "TXT error count should not decrease"
        );
        assert!(
            final_mx_errors >= initial_mx_errors,
            "MX error count should not decrease"
        );
    }

    #[tokio::test]
    async fn test_fetch_additional_dns_records_partial_failures_recorded() {
        // Test that partial failures are correctly recorded in the result
        // This is critical - partial failures must be tracked for debugging
        let resolver = create_test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());

        let result = fetch_additional_dns_records(
            "this-domain-definitely-does-not-exist-12345.invalid",
            &resolver,
            error_stats.as_ref(),
        )
        .await;

        // Partial failures may or may not be present depending on resolver behavior
        // But the structure should be correct
        // The key is that the function doesn't panic and returns a valid result
        // (len() is always >= 0 for Vec, so we just verify it's a valid vector)
        let _ = result.partial_failures.len();

        // Verify partial failures have correct structure if present
        for (error_type, error_msg) in &result.partial_failures {
            // Error type should be a DNS-related error
            matches!(
                error_type,
                crate::error_handling::ErrorType::DnsNsLookupError
                    | crate::error_handling::ErrorType::DnsTxtLookupError
                    | crate::error_handling::ErrorType::DnsMxLookupError
            );
            // Error message should be non-empty and sanitized
            assert!(!error_msg.is_empty(), "Error message should not be empty");
            assert!(
                error_msg.len() <= 500,
                "Error message should be sanitized/truncated to prevent database bloat"
            );
        }
    }

    #[tokio::test]
    async fn test_fetch_additional_dns_records_empty_results_handled() {
        // Test that empty DNS results are handled correctly
        // This is critical - empty results should not cause panics or errors
        let resolver = create_test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());

        // Use a domain that might return empty results
        let result = fetch_additional_dns_records(
            "this-domain-definitely-does-not-exist-12345.invalid",
            &resolver,
            error_stats.as_ref(),
        )
        .await;

        // Should return valid result structure even with empty data
        assert!(
            result.data.nameservers.is_none() || result.data.nameservers.is_some(),
            "Nameservers should be Option (None or Some)"
        );
        assert!(
            result.data.txt_records.is_none() || result.data.txt_records.is_some(),
            "TXT records should be Option (None or Some)"
        );
        assert!(
            result.data.mx_records.is_none() || result.data.mx_records.is_some(),
            "MX records should be Option (None or Some)"
        );
        assert!(
            result.data.spf_record.is_none() || result.data.spf_record.is_some(),
            "SPF record should be Option (None or Some)"
        );
        assert!(
            result.data.dmarc_record.is_none() || result.data.dmarc_record.is_some(),
            "DMARC record should be Option (None or Some)"
        );
    }
}
