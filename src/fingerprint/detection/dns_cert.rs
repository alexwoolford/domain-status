//! DNS and certificate-issuer technology matching (static, post-DNS enrichment).

use std::collections::HashMap;

use crate::fingerprint::models::FingerprintRuleset;

use super::signal_match::SignalMatch;
use super::source::DetectionSource;

/// Result of a DNS or cert-issuer match for a single technology.
pub type DnsCertMatchResult = SignalMatch;

/// Matches technologies against DNS record haystacks and optional cert issuer.
///
/// Only **NS** and **CNAME** haystacks are consulted. TXT/MX/SPF/DMARC prove
/// that an org uses a vendor, not that this HTTP response is served by that
/// vendor — those records stay in satellite tables.
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
        let mut source: Option<DetectionSource> = None;
        let prepared = tech.prepared();

        for record_type in tech.dns.keys() {
            if !is_serving_stack_dns_type(record_type) {
                continue;
            }
            let Some(haystack) = dns_records.get(&record_type.to_uppercase()) else {
                continue;
            };
            let Some(patterns) = prepared.dns.get(record_type) else {
                continue;
            };
            for pattern in patterns {
                let result = pattern.evaluate(haystack);
                if result.matched {
                    matched = true;
                    if source.is_none() {
                        source = Some(if record_type.eq_ignore_ascii_case("CNAME") {
                            DetectionSource::Cname
                        } else {
                            DetectionSource::Ns
                        });
                    }
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
            for pattern in &prepared.cert_issuer {
                let result = pattern.evaluate(issuer);
                if result.matched {
                    matched = true;
                    if source.is_none() {
                        source = Some(DetectionSource::Cert);
                    }
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
                source: source.unwrap_or(DetectionSource::Ns),
            });
        }
    }

    results
}

fn is_serving_stack_dns_type(record_type: &str) -> bool {
    record_type.eq_ignore_ascii_case("NS") || record_type.eq_ignore_ascii_case("CNAME")
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
    fn test_dns_txt_org_proofs_are_not_technologies() {
        let mut docusign = Technology::default();
        docusign.dns.insert("TXT".into(), vec!["docusign".into()]);
        let mut miro = Technology::default();
        miro.dns
            .insert("TXT".into(), vec!["miro-verification=".into()]);
        let ruleset = ruleset_with(HashMap::from([
            ("DocuSign".into(), docusign),
            ("Miro".into(), miro),
        ]));

        let dns = HashMap::from([(
            "TXT".into(),
            "docusign=087098e3 miro-verification=abc v=spf1 include:docusign.net".to_string(),
        )]);
        let results = check_dns_and_cert_with_ruleset(&ruleset, &dns, None);
        assert!(
            results.is_empty(),
            "TXT/SPF vendor proofs must not become url_technologies, got {results:?}"
        );
    }

    #[test]
    fn test_dns_cname_still_matches() {
        let mut tech = Technology::default();
        tech.dns
            .insert("CNAME".into(), vec!["cloudfront\\.net".into()]);
        let ruleset = ruleset_with(HashMap::from([("Amazon CloudFront".into(), tech)]));

        let dns = HashMap::from([("CNAME".into(), "d111111abcdef8.cloudfront.net.".to_string())]);
        let results = check_dns_and_cert_with_ruleset(&ruleset, &dns, None);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tech_name, "Amazon CloudFront");
    }

    #[test]
    fn test_dns_ns_matches_route_53() {
        let mut tech = Technology::default();
        tech.dns.insert("NS".into(), vec![r"\.awsdns-\d+\.".into()]);
        let ruleset = ruleset_with(HashMap::from([("Amazon Route 53".into(), tech)]));

        let dns = HashMap::from([("NS".into(), "ns-520.awsdns-01.net.".to_string())]);
        let results = check_dns_and_cert_with_ruleset(&ruleset, &dns, None);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tech_name, "Amazon Route 53");
    }

    #[test]
    fn test_dns_mx_org_proofs_are_not_technologies() {
        let mut tech = Technology::default();
        tech.dns.insert("MX".into(), vec!["google\\.com".into()]);
        let ruleset = ruleset_with(HashMap::from([("Google Workspace".into(), tech)]));

        let dns = HashMap::from([("MX".into(), "10 aspmx.l.google.com.".to_string())]);
        let results = check_dns_and_cert_with_ruleset(&ruleset, &dns, None);
        assert!(
            results.is_empty(),
            "MX proves mail routing, not the HTTP serving stack, got {results:?}"
        );
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
