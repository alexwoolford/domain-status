//! Additional DNS records fetching.
//!
//! This module handles fetching additional DNS records (NS, TXT, MX) and
//! extracting SPF/DMARC records from TXT records.

use log::debug;

use crate::dns::{extract_dmarc_record, extract_spf_record, lookup_mx_records, lookup_ns_records, lookup_txt_records};
use crate::fetch::utils::serialize_json;

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
    resolver: &hickory_resolver::TokioAsyncResolver,
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
            Some(serialize_json(&ns))
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
            Some(serialize_json(&txt))
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
            Some(serialize_json(&mx_json))
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

