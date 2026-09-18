//! Header-based technology detection.
//!
//! Matches technologies against HTTP response headers (Wappalyzer `headers` map).

use std::collections::HashMap;

use crate::fingerprint::models::FingerprintRuleset;

use super::signal_match::{match_string_map_signal, SignalMatch};
use super::source::DetectionSource;

/// Result of header matching for a single technology.
pub type HeaderMatchResult = SignalMatch;

/// Checks all technologies against headers and returns matches.
pub(crate) fn check_headers_with_ruleset(
    ruleset: &FingerprintRuleset,
    headers: &HashMap<String, String>,
) -> Vec<HeaderMatchResult> {
    match_string_map_signal(
        ruleset,
        headers,
        |tech| &tech.headers,
        is_csp_allowlist_header,
        DetectionSource::Header,
    )
}

/// CSP allowlists name third parties the page may load; they are not evidence
/// that this response is served by that vendor (store those hosts in `url_csp_domains`).
fn is_csp_allowlist_header(name: &str) -> bool {
    name == "content-security-policy" || name == "content-security-policy-report-only"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::models::{FingerprintMetadata, Technology};

    fn empty_tech() -> Technology {
        Technology::default()
    }

    fn ruleset_with(technologies: HashMap<String, Technology>) -> FingerprintRuleset {
        FingerprintRuleset {
            technologies,
            categories: HashMap::new(),
            metadata: FingerprintMetadata {
                source: "test".into(),
                version: "0".into(),
                last_updated: std::time::SystemTime::now(),
            },
        }
    }

    /// Header keys must be lowercase in fixtures: the ruleset normalizes header
    /// names to lowercase on load, and `check_headers_with_ruleset` does an
    /// exact-key `get()` against the already-lowercased request headers.
    #[test]
    fn test_headers_detect_vercel_via_server_header() {
        let mut tech = empty_tech();
        tech.headers.insert("server".to_string(), "now".to_string());
        let mut technologies = HashMap::new();
        technologies.insert("Vercel".to_string(), tech);
        let ruleset = ruleset_with(technologies);

        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "now".to_string());

        let results = check_headers_with_ruleset(&ruleset, &headers);
        let tech_names: Vec<String> = results.iter().map(|r| r.tech_name.clone()).collect();
        assert!(
            tech_names.contains(&"Vercel".to_string()),
            "Could not get correct match for Vercel"
        );
    }

    /// Apache detection with version extraction from the `Server` header.
    #[test]
    fn test_headers_apache_with_version() {
        let mut tech = empty_tech();
        tech.headers.insert(
            "server".to_string(),
            r"Apache(?:/([\d.]+))?\;version:\1".to_string(),
        );
        let mut technologies = HashMap::new();
        technologies.insert("Apache HTTP Server".to_string(), tech);
        let ruleset = ruleset_with(technologies);

        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "Apache/2.4.29".to_string());

        let results = check_headers_with_ruleset(&ruleset, &headers);
        let tech_names: Vec<String> = results
            .iter()
            .map(|r| {
                if let Some(ref version) = r.version {
                    format!("{}:{}", r.tech_name, version)
                } else {
                    r.tech_name.clone()
                }
            })
            .collect();

        assert!(
            tech_names.contains(&"Apache HTTP Server:2.4.29".to_string()),
            "Could not match Apache with version, got: {tech_names:?}"
        );
    }

    /// Empty pattern (header exists, value doesn't matter): HSTS via
    /// `strict-transport-security`.
    #[test]
    fn test_headers_empty_pattern_hsts() {
        let mut tech = empty_tech();
        tech.headers
            .insert("strict-transport-security".to_string(), String::new());
        let mut technologies = HashMap::new();
        technologies.insert("HSTS".to_string(), tech);
        let ruleset = ruleset_with(technologies);

        let mut headers = HashMap::new();
        headers.insert(
            "strict-transport-security".to_string(),
            "max-age=31536000".to_string(),
        );

        let results = check_headers_with_ruleset(&ruleset, &headers);
        let tech_names: Vec<String> = results.iter().map(|r| r.tech_name.clone()).collect();
        assert!(
            tech_names.contains(&"HSTS".to_string()),
            "Could not detect HSTS via strict-transport-security header"
        );
    }

    #[test]
    fn test_csp_allowlist_does_not_match_amazon_s3() {
        let mut tech = empty_tech();
        tech.headers.insert(
            "content-security-policy".to_string(),
            r"s3[^ ]*\.amazonaws\.com".to_string(),
        );
        tech.headers
            .insert("server".to_string(), "AmazonS3".to_string());
        let ruleset = ruleset_with(HashMap::from([("Amazon S3".into(), tech)]));

        let mut csp_only = HashMap::new();
        csp_only.insert(
            "content-security-policy".to_string(),
            "img-src https://media.example.s3.amazonaws.com".to_string(),
        );
        let results = check_headers_with_ruleset(&ruleset, &csp_only);
        assert!(
            results.is_empty(),
            "CSP allowlists must not fingerprint Amazon S3, got {results:?}"
        );

        let mut report_only = HashMap::new();
        report_only.insert(
            "content-security-policy-report-only".to_string(),
            "script-src https://static.example.s3.amazonaws.com".to_string(),
        );
        let report_results = check_headers_with_ruleset(&ruleset, &report_only);
        assert!(
            report_results.is_empty(),
            "CSP report-only allowlists must not fingerprint Amazon S3, got {report_results:?}"
        );
    }

    #[test]
    fn test_server_amazons3_still_matches() {
        let mut tech = empty_tech();
        tech.headers.insert(
            "content-security-policy".to_string(),
            r"s3[^ ]*\.amazonaws\.com".to_string(),
        );
        tech.headers
            .insert("server".to_string(), "AmazonS3".to_string());
        let ruleset = ruleset_with(HashMap::from([("Amazon S3".into(), tech)]));

        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "amazons3".to_string());
        let results = check_headers_with_ruleset(&ruleset, &headers);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tech_name, "Amazon S3");
    }
}
