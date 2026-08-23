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

/// Returns true if `txt` looks like an MTA-STS policy (`v=STSv1…`).
pub fn is_mta_sts_txt(txt: &str) -> bool {
    txt.trim()
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("v=stsv1"))
}

/// Returns true if `txt` looks like a TLS-RPT policy (`v=TLSRPTv1…`).
pub fn is_tls_rpt_txt(txt: &str) -> bool {
    txt.trim()
        .get(..10)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("v=tlsrptv1"))
}

/// Returns true if `txt` looks like a BIMI record (`v=BIMI1…`).
pub fn is_bimi_txt(txt: &str) -> bool {
    txt.trim()
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("v=bimi1"))
}

/// Extracts the first MTA-STS TXT record from `txt_records`.
pub fn extract_mta_sts_record(txt_records: &[String]) -> Option<String> {
    txt_records
        .iter()
        .find(|txt| is_mta_sts_txt(txt))
        .map(|s| s.trim().to_string())
}

/// Extracts the first TLS-RPT TXT record from `txt_records`.
pub fn extract_tls_rpt_record(txt_records: &[String]) -> Option<String> {
    txt_records
        .iter()
        .find(|txt| is_tls_rpt_txt(txt))
        .map(|s| s.trim().to_string())
}

/// Extracts the first BIMI TXT record from `txt_records`.
pub fn extract_bimi_record(txt_records: &[String]) -> Option<String> {
    txt_records
        .iter()
        .find(|txt| is_bimi_txt(txt))
        .map(|s| s.trim().to_string())
}

#[cfg(test)]
mod email_auth_tests {
    use super::*;

    #[test]
    fn extracts_mta_sts_tls_rpt_bimi() {
        assert!(is_mta_sts_txt("v=STSv1; id=20260101"));
        assert!(is_tls_rpt_txt("v=TLSRPTv1; rua=mailto:tlsrpt@example.com"));
        assert!(is_bimi_txt("v=BIMI1; l=https://example.com/logo.svg"));
        let txts = vec![
            "v=STSv1; id=abc".to_string(),
            "v=TLSRPTv1; rua=mailto:a@b.c".to_string(),
            "v=BIMI1; l=https://example.com/l.svg".to_string(),
        ];
        assert!(extract_mta_sts_record(&txts)
            .unwrap()
            .starts_with("v=STSv1"));
        assert!(extract_tls_rpt_record(&txts)
            .unwrap()
            .starts_with("v=TLSRPTv1"));
        assert!(extract_bimi_record(&txts).unwrap().starts_with("v=BIMI1"));
    }
}
