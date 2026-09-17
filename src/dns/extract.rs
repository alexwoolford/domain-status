//! DNS record extraction utilities.
//!
//! Classifies TXT strings (SPF, DMARC, MTA-STS, TLS-RPT, BIMI) and returns the
//! first matching record. Prefix matching is case-insensitive. Storage TXT
//! classification uses these same predicates.

/// True when the trimmed TXT starts with `tag` (ASCII case-insensitive).
#[must_use]
fn starts_with_tag(txt: &str, tag: &str) -> bool {
    txt.trim()
        .get(..tag.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(tag))
}

fn extract_first(txt_records: &[String], pred: impl Fn(&str) -> bool) -> Option<String> {
    txt_records
        .iter()
        .find(|txt| pred(txt))
        .map(|s| s.trim().to_string())
}

/// Returns true if `txt` looks like an SPF policy (`v=spf1…`), case-insensitive.
#[must_use]
pub fn is_spf_txt(txt: &str) -> bool {
    starts_with_tag(txt, "v=spf1")
}

/// Returns true if `txt` looks like a DMARC policy (`v=DMARC1…`), case-insensitive.
#[must_use]
pub fn is_dmarc_txt(txt: &str) -> bool {
    starts_with_tag(txt, "v=dmarc1")
}

/// Returns true if `txt` looks like an MTA-STS policy (`v=STSv1…`).
#[must_use]
pub fn is_mta_sts_txt(txt: &str) -> bool {
    starts_with_tag(txt, "v=stsv1")
}

/// Returns true if `txt` looks like a TLS-RPT policy (`v=TLSRPTv1…`).
#[must_use]
pub fn is_tls_rpt_txt(txt: &str) -> bool {
    starts_with_tag(txt, "v=tlsrptv1")
}

/// Returns true if `txt` looks like a BIMI record (`v=BIMI1…`).
#[must_use]
pub fn is_bimi_txt(txt: &str) -> bool {
    starts_with_tag(txt, "v=bimi1")
}

/// Extracts the first SPF record (`v=spf1…`) from `txt_records`.
#[must_use]
pub fn extract_spf_record(txt_records: &[String]) -> Option<String> {
    extract_first(txt_records, is_spf_txt)
}

/// Extracts the first DMARC record (`v=DMARC1…`) from `txt_records`.
#[must_use]
pub fn extract_dmarc_record(txt_records: &[String]) -> Option<String> {
    extract_first(txt_records, is_dmarc_txt)
}

/// Extracts the first MTA-STS TXT record from `txt_records`.
#[must_use]
pub fn extract_mta_sts_record(txt_records: &[String]) -> Option<String> {
    extract_first(txt_records, is_mta_sts_txt)
}

/// Extracts the first TLS-RPT TXT record from `txt_records`.
#[must_use]
pub fn extract_tls_rpt_record(txt_records: &[String]) -> Option<String> {
    extract_first(txt_records, is_tls_rpt_txt)
}

/// Extracts the first BIMI TXT record from `txt_records`.
#[must_use]
pub fn extract_bimi_record(txt_records: &[String]) -> Option<String> {
    extract_first(txt_records, is_bimi_txt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn classifiers_match_leading_space_and_case() {
        assert!(is_spf_txt("  V=SPF1 include:_spf.example.com ~all"));
        assert!(is_dmarc_txt("\tv=dmarc1; p=none"));
        assert!(is_mta_sts_txt(" v=STSv1; id=1"));
        assert!(is_tls_rpt_txt("V=TLSRPTv1; rua=mailto:a@b.c"));
        assert!(is_bimi_txt("  v=BIMI1; l=https://example.com/l.svg"));
    }

    #[test]
    fn classifiers_reject_non_matching_txt() {
        assert!(!is_spf_txt(""));
        assert!(!is_spf_txt("some other record"));
        assert!(!is_dmarc_txt("v=spf1 ~all"));
        assert!(!is_mta_sts_txt("v=TLSRPTv1; rua=mailto:a@b.c"));
        assert!(!is_tls_rpt_txt("v=STSv1; id=1"));
        assert!(!is_bimi_txt("not-bimi"));
    }

    #[test]
    fn extractors_return_first_match_trimmed() {
        assert_eq!(
            extract_spf_record(&strs(&[
                "some other record",
                "  v=spf1 include:_spf.google.com ~all",
            ])),
            Some("v=spf1 include:_spf.google.com ~all".to_string())
        );
        assert_eq!(
            extract_dmarc_record(&strs(&[
                "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
                "v=DMARC1; p=reject",
            ])),
            Some("v=DMARC1; p=none; rua=mailto:dmarc@example.com".to_string())
        );
        assert_eq!(extract_spf_record(&strs(&["nope"])), None);
        assert_eq!(extract_dmarc_record(&[]), None);
        assert_eq!(
            extract_dmarc_record(&strs(&["v=dmarc1; p=none"])),
            Some("v=dmarc1; p=none".to_string())
        );
    }

    #[test]
    fn extracts_mta_sts_tls_rpt_bimi() {
        let txts = strs(&[
            "v=STSv1; id=abc",
            "v=TLSRPTv1; rua=mailto:a@b.c",
            "v=BIMI1; l=https://example.com/l.svg",
        ]);
        assert_eq!(
            extract_mta_sts_record(&txts).as_deref(),
            Some("v=STSv1; id=abc")
        );
        assert_eq!(
            extract_tls_rpt_record(&txts).as_deref(),
            Some("v=TLSRPTv1; rua=mailto:a@b.c")
        );
        assert_eq!(
            extract_bimi_record(&txts).as_deref(),
            Some("v=BIMI1; l=https://example.com/l.svg")
        );
        assert_eq!(extract_mta_sts_record(&strs(&["nope"])), None);
        assert_eq!(extract_tls_rpt_record(&strs(&["nope"])), None);
        assert_eq!(extract_bimi_record(&strs(&["nope"])), None);
    }
}
