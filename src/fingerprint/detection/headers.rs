//! Header-based technology detection.
//!
//! This module matches technologies based on HTTP response headers,
//! following wappalyzergo's `checkHeaders()` and `matchMapString(headers, headersPart)` logic.

use std::collections::HashMap;

use crate::fingerprint::models::FingerprintRuleset;
use crate::fingerprint::patterns::matches_pattern;

/// Result of header matching for a single technology
#[derive(Debug, Clone)]
pub struct HeaderMatchResult {
    pub tech_name: String,
    pub version: Option<String>,
}

/// Checks all technologies against headers and returns matches.
///
/// Synchronous header check using a pre-fetched ruleset (for use on blocking threads).
pub(crate) fn check_headers_with_ruleset(
    ruleset: &FingerprintRuleset,
    headers: &HashMap<String, String>,
) -> Vec<HeaderMatchResult> {
    let mut results = Vec::new();
    for (tech_name, tech) in &ruleset.technologies {
        if tech.headers.is_empty() {
            continue;
        }
        let mut matched = false;
        let mut version: Option<String> = None;
        for (header_name, pattern) in &tech.headers {
            if let Some(header_value) = headers.get(header_name) {
                if pattern.is_empty() {
                    matched = true;
                    break;
                }
                let result = matches_pattern(pattern, header_value);
                if result.matched {
                    matched = true;
                    if version.is_none() && result.version.is_some() {
                        version.clone_from(&result.version);
                    }
                    if version.is_some() {
                        break;
                    }
                }
            }
        }
        if matched {
            results.push(HeaderMatchResult {
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

    fn empty_tech() -> Technology {
        Technology {
            cats: vec![],
            website: String::new(),
            headers: HashMap::new(),
            cookies: HashMap::new(),
            meta: HashMap::new(),
            script: vec![],
            html: vec![],
            url: vec![],
            js: HashMap::new(),
            implies: vec![],
            excludes: vec![],
        }
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
}
