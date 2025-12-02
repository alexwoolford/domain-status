//! DNS record extraction utilities.
//!
//! This module provides functions to extract specific record types from
//! TXT record collections, such as SPF and DMARC records.

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

