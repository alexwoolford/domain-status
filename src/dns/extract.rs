//! DNS record extraction utilities.
//!
//! This module provides functions to extract specific record types from
//! TXT record collections, such as SPF and DMARC records.

/// Returns true if `txt` looks like an SPF policy (`v=spf1…`), case-insensitive.
pub fn is_spf_txt(txt: &str) -> bool {
    txt.trim()
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("v=spf1"))
}

/// Returns true if `txt` looks like a DMARC policy (`v=DMARC1…`), case-insensitive.
pub fn is_dmarc_txt(txt: &str) -> bool {
    txt.trim()
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("v=dmarc1"))
}

/// Extracts SPF record from TXT records.
///
/// SPF records start with "v=spf1" (case-insensitive).
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
        .find(|txt| is_spf_txt(txt))
        .map(|s| s.trim().to_string())
}

/// Extracts DMARC record from TXT records.
///
/// DMARC records are typically at `_dmarc.<domain>` but we check the provided records.
/// DMARC records start with "v=DMARC1" (case-insensitive).
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
        .find(|txt| is_dmarc_txt(txt))
        .map(|s| s.trim().to_string())
}
