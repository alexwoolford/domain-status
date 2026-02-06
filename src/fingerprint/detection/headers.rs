//! Header-based technology detection.
//!
//! This module matches technologies based on HTTP response headers,
//! following wappalyzergo's `checkHeaders()` and `matchMapString(headers, headersPart)` logic.

use std::collections::HashMap;

use crate::fingerprint::patterns::matches_pattern;
use crate::fingerprint::ruleset::get_ruleset;

/// Result of header matching for a single technology
#[derive(Debug, Clone)]
pub struct HeaderMatchResult {
    pub tech_name: String,
    pub version: Option<String>,
}

/// Checks all technologies against headers and returns matches.
///
/// This matches wappalyzergo's `checkHeaders()` → `matchMapString(headers, headersPart)` flow.
pub async fn check_headers(
    headers: &HashMap<String, String>,
) -> anyhow::Result<Vec<HeaderMatchResult>> {
    let ruleset = get_ruleset()
        .await
        .ok_or_else(|| {
            anyhow::anyhow!("Ruleset not initialized. Call init_ruleset() before running detection.")
        })?;

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
                    // Empty pattern means header exists (value doesn't matter)
                    matched = true;
                    break;
                }

                let result = matches_pattern(pattern, header_value);
                if result.matched {
                    matched = true;
                    if version.is_none() && result.version.is_some() {
                        version = result.version.clone();
                    }
                    // wappalyzergo breaks after first match with version
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

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::ruleset::init_ruleset;

    /// Test header detection matching wappalyzergo's TestHeadersDetect
    #[tokio::test]
    async fn test_headers_detect() {
        // Initialize ruleset (uses wappalyzergo format for exact parity)
        // Skip test if ruleset initialization fails (e.g., no network in CI)
        if init_ruleset(None, None).await.is_err() {
            eprintln!("Skipping test: ruleset initialization failed (likely no network access)");
            return;
        }

        // Test Vercel detection via Server header
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "now".to_string());

        let results = check_headers(&headers)
            .await
            .expect("Failed to check headers");
        let tech_names: Vec<String> = results.iter().map(|r| r.tech_name.clone()).collect();
        assert!(
            tech_names.contains(&"Vercel".to_string()),
            "Could not get correct match for Vercel"
        );
    }

    /// Test Apache detection with version (matching wappalyzergo's Test_All_Match_Paths)
    #[tokio::test]
    async fn test_headers_apache_with_version() {
        // Skip test if ruleset initialization fails (e.g., no network in CI)
        if init_ruleset(None, None).await.is_err() {
            eprintln!("Skipping test: ruleset initialization failed (likely no network access)");
            return;
        }

        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "Apache/2.4.29".to_string());

        let results = check_headers(&headers)
            .await
            .expect("Failed to check headers");
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
            "Could not match Apache with version"
        );
    }

    /// Test empty pattern (header exists, value doesn't matter)
    #[tokio::test]
    async fn test_headers_empty_pattern() {
        // Skip test if ruleset initialization fails (e.g., no network in CI)
        if init_ruleset(None, None).await.is_err() {
            eprintln!("Skipping test: ruleset initialization failed (likely no network access)");
            return;
        }

        // Test HSTS detection (strict-transport-security header with empty pattern)
        let mut headers = HashMap::new();
        headers.insert(
            "strict-transport-security".to_string(),
            "max-age=31536000".to_string(),
        );

        let results = check_headers(&headers)
            .await
            .expect("Failed to check headers");
        let tech_names: Vec<String> = results.iter().map(|r| r.tech_name.clone()).collect();
        assert!(
            tech_names.contains(&"HSTS".to_string()),
            "Could not detect HSTS via strict-transport-security header"
        );
    }
}
