//! DNS and certificate-issuer technology matching (static, post-DNS enrichment).

use std::collections::HashMap;

use crate::fingerprint::models::FingerprintRuleset;
use crate::fingerprint::patterns::matches_pattern;

use super::signal_match::SignalMatch;

/// Result of a DNS or cert-issuer match for a single technology.
pub type DnsCertMatchResult = SignalMatch;

/// Matches technologies against DNS record haystacks and optional cert issuer.
///
/// `dns_records` keys are uppercase record types (`TXT`, `MX`, `NS`, `CNAME`, …)
/// mapped to lowercase concatenated record content.
pub(crate) fn check_dns_and_cert_with_ruleset(
    ruleset: &FingerprintRuleset,
    dns_records: &HashMap<String, String>,
    cert_issuer: Option<&str>,
) -> Vec<DnsCertMatchResult> {
    let mut results = Vec::new();
    let cert_issuer_lower = cert_issuer.map(str::to_lowercase);

    for (tech_name, tech) in &ruleset.technologies {
        if tech.dns.is_empty() && tech.cert_issuer.is_empty() {
            continue;
        }

        let mut matched = false;
        let mut version: Option<String> = None;

        for (record_type, patterns) in &tech.dns {
            let Some(haystack) = dns_records.get(&record_type.to_uppercase()) else {
                continue;
            };
            for pattern in patterns {
                let result = matches_pattern(pattern, haystack);
                if result.matched {
                    matched = true;
                    if version.is_none() && result.version.is_some() {
                        version = result.version;
                    }
                    if version.is_some() {
                        break;
                    }
                }
            }
            if version.is_some() {
                break;
            }
        }

        if let Some(ref issuer) = cert_issuer_lower {
            for pattern in &tech.cert_issuer {
                let result = matches_pattern(pattern, issuer);
                if result.matched {
                    matched = true;
                    if version.is_none() && result.version.is_some() {
                        version = result.version;
                    }
                    if version.is_some() {
                        break;
                    }
                }
            }
        }

        if matched {
            results.push(DnsCertMatchResult {
                tech_name: tech_name.clone(),
                version,
            });
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::models::{FingerprintMetadata, Technology};
    use std::time::SystemTime;

    fn ruleset_with(technologies: HashMap<String, Technology>) -> FingerprintRuleset {
        FingerprintRuleset {
            technologies,
            categories: HashMap::new(),
            metadata: FingerprintMetadata {
                source: "test".into(),
                version: "0".into(),
                last_updated: SystemTime::now(),
            },
        }
    }

    #[test]
    fn test_dns_txt_match() {
        let mut tech = Technology::default();
        tech.dns
            .insert("TXT".into(), vec!["google-site-verification".into()]);
        let ruleset = ruleset_with(HashMap::from([("Google Workspace".into(), tech)]));

        let dns = HashMap::from([("TXT".into(), "google-site-verification=abc123".to_string())]);
        let results = check_dns_and_cert_with_ruleset(&ruleset, &dns, None);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tech_name, "Google Workspace");
    }

    #[test]
    fn test_cert_issuer_match() {
        let mut tech = Technology::default();
        tech.cert_issuer.push("Let's Encrypt".into());
        let ruleset = ruleset_with(HashMap::from([("Lets Encrypt".into(), tech)]));

        let results =
            check_dns_and_cert_with_ruleset(&ruleset, &HashMap::new(), Some("CN=Let's Encrypt"));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tech_name, "Lets Encrypt");
    }

    #[test]
    fn test_no_match_when_signals_absent() {
        let mut tech = Technology::default();
        tech.dns.insert("MX".into(), vec!["google\\.com".into()]);
        let ruleset = ruleset_with(HashMap::from([("Gmail".into(), tech)]));

        let results = check_dns_and_cert_with_ruleset(&ruleset, &HashMap::new(), None);
        assert!(results.is_empty());
    }
}
