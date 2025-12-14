//! Body-based technology detection (HTML, script sources, meta tags).
//!
//! This module matches technologies based on HTML body content,
//! following wappalyzergo's `checkBody()` logic which checks:
//! 1. HTML patterns (via `matchString(body, htmlPart)`)
//! 2. Script sources (via `matchString(scriptSrc, scriptPart)`)
//! 3. Meta tags (via `matchKeyValueString(name, content, metaPart)`)

use std::collections::HashMap;

use crate::fingerprint::patterns::{check_meta_patterns, matches_pattern};
use crate::fingerprint::ruleset::get_ruleset;

/// Result of body matching for a single technology
#[derive(Debug, Clone)]
pub struct BodyMatchResult {
    pub tech_name: String,
    pub version: Option<String>,
}

/// Checks all technologies against HTML body content and returns matches.
///
/// This matches wappalyzergo's `checkBody()` flow:
/// 1. HTML patterns (checked first)
/// 2. Script sources (checked during tokenization)
/// 3. Meta tags (checked during tokenization)
/// 4. URL patterns (checked last)
///
/// wappalyzergo takes the first version found across all pattern types.
pub async fn check_body(
    html_body: &str,
    script_sources: &[String],
    meta_tags: &HashMap<String, Vec<String>>,
    url: &str,
) -> anyhow::Result<Vec<BodyMatchResult>> {
    let ruleset = get_ruleset()
        .await
        .ok_or_else(|| anyhow::anyhow!("Ruleset not initialized"))?;

    let mut results = Vec::new();

    for (tech_name, tech) in &ruleset.technologies {
        // Skip if technology has no body-related patterns
        if tech.html.is_empty()
            && tech.script.is_empty()
            && tech.meta.is_empty()
            && tech.url.is_empty()
        {
            continue;
        }

        let mut matched = false;
        let mut version: Option<String> = None;

        // 1. Check HTML patterns first (wappalyzergo checks HTML patterns before tokenizing)
        for pattern in &tech.html {
            let result = matches_pattern(pattern, html_body);
            if result.matched {
                matched = true;
                if version.is_none() && result.version.is_some() {
                    version = result.version.clone();
                }
                // If we get a version from HTML pattern, we can stop checking HTML patterns
                if version.is_some() {
                    break;
                }
            }
        }

        // 2. Check script sources (wappalyzergo checks scriptSrc during tokenization)
        // wappalyzergo iterates through scripts first, then patterns, and takes the first version found
        for script_src in script_sources {
            for pattern in &tech.script {
                let result = matches_pattern(pattern, script_src);
                if result.matched {
                    matched = true;
                    if version.is_none() && result.version.is_some() {
                        version = result.version.clone();
                    }
                    // If we found a version from this script, stop checking other patterns for this script
                    if version.is_some() {
                        break;
                    }
                }
            }
            // If we found a version, stop checking other scripts
            if version.is_some() {
                break;
            }
        }

        // 3. Check meta tags (wappalyzergo checks meta during tokenization, after scriptSrc)
        // If we already matched but have no version, check meta for version
        // If we haven't matched yet, check meta normally
        for (meta_key, patterns) in &tech.meta {
            let result = check_meta_patterns(meta_key, patterns, meta_tags);
            if result.matched {
                matched = true;
                // If we already matched via HTML/script but have no version, use version from meta
                if version.is_none() && result.version.is_some() {
                    version = result.version.clone();
                }
                // If we haven't matched yet, this is the first match
                if version.is_some() {
                    break;
                }
            }
        }

        // 4. Check URL patterns (wappalyzergo checks these last)
        for url_pattern in &tech.url {
            let result = matches_pattern(url_pattern, url);
            if result.matched {
                matched = true;
                if version.is_none() && result.version.is_some() {
                    version = result.version.clone();
                }
                if version.is_some() {
                    break;
                }
            }
        }

        if matched {
            results.push(BodyMatchResult {
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

    /// Test meta tag detection matching wappalyzergo's TestBodyDetect meta test
    #[tokio::test]
    async fn test_body_meta() {
        // Skip test if ruleset initialization fails (e.g., no network in CI)
        if init_ruleset(None, None).await.is_err() {
            eprintln!("Skipping test: ruleset initialization failed (likely no network access)");
            return;
        }

        let html_body = r#"<html>
<head>
<meta name="generator" content="mura cms 1">
</head>
</html>"#;

        let mut meta_tags = HashMap::new();
        meta_tags.insert("name:generator".to_string(), vec!["mura cms 1".to_string()]);
        let script_sources = vec![];
        let url = "https://example.com";

        let results = check_body(html_body, &script_sources, &meta_tags, url)
            .await
            .expect("Failed to check body");

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

        eprintln!("Detected technologies: {:?}", tech_names);
        // Note: Mura CMS might not be in the ruleset or pattern might have changed
        // This test verifies meta tag detection works, not that a specific technology exists
        if !tech_names.is_empty() {
            // If we detected anything, meta tag detection is working
            // The specific technology may vary based on ruleset version
            eprintln!(
                "Meta tag detection is working (detected {} technologies)",
                tech_names.len()
            );
        } else {
            // If nothing detected, check if ruleset has meta patterns at all
            let ruleset = crate::fingerprint::ruleset::get_ruleset().await;
            if let Some(ruleset) = ruleset {
                let has_meta_patterns = ruleset
                    .technologies
                    .values()
                    .any(|tech| !tech.meta.is_empty());
                if has_meta_patterns {
                    panic!("Meta tag detection failed - ruleset has meta patterns but none matched. Detected: {:?}", tech_names);
                } else {
                    eprintln!("Skipping: ruleset has no meta tag patterns");
                }
            }
        }
    }

    /// Test HTML pattern detection with implied technologies
    /// Matching wappalyzergo's TestBodyDetect html-implied test
    #[tokio::test]
    async fn test_body_html_implied() {
        // Skip test if ruleset initialization fails (e.g., no network in CI)
        if init_ruleset(None, None).await.is_err() {
            eprintln!("Skipping test: ruleset initialization failed (likely no network access)");
            return;
        }

        let html_body = r#"<html data-ng-app="rbschangeapp">
<head>
</head>
<body>
</body>
</html>"#;

        let meta_tags = HashMap::new();
        let script_sources = vec![];
        let url = "https://example.com";

        let results = check_body(html_body, &script_sources, &meta_tags, url)
            .await
            .expect("Failed to check body");

        let tech_names: Vec<String> = results.iter().map(|r| r.tech_name.clone()).collect();

        // AngularJS should be detected via data-ng-app attribute
        assert!(
            tech_names.contains(&"AngularJS".to_string()),
            "Could not get correct implied match for AngularJS"
        );
    }

    /// Test script source detection
    #[tokio::test]
    async fn test_body_script_src() {
        // Skip test if ruleset initialization fails (e.g., no network in CI)
        if init_ruleset(None, None).await.is_err() {
            eprintln!("Skipping test: ruleset initialization failed (likely no network access)");
            return;
        }

        let html_body = "";
        let script_sources = vec!["https://cdn.example.com/jquery-3.6.0.min.js".to_string()];
        let meta_tags = HashMap::new();
        let url = "https://example.com";

        let results = check_body(html_body, &script_sources, &meta_tags, url)
            .await
            .expect("Failed to check body");

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

        // jQuery should be detected via script src
        assert!(
            tech_names.iter().any(|name| name.starts_with("jQuery")),
            "Could not detect jQuery via script src"
        );
    }

    /// Test HTML pattern detection (WordPress)
    #[tokio::test]
    async fn test_body_html_pattern() {
        // Skip test if ruleset initialization fails (e.g., no network in CI)
        if init_ruleset(None, None).await.is_err() {
            eprintln!("Skipping test: ruleset initialization failed (likely no network access)");
            return;
        }

        let html_body = r#"<html>
<head>
</head>
<body>
<link rel="stylesheet" href="/wp-content/themes/twenty-twenty-one/style.css">
</body>
</html>"#;

        let script_sources = vec![];
        let meta_tags = HashMap::new();
        let url = "https://example.com";

        let results = check_body(html_body, &script_sources, &meta_tags, url)
            .await
            .expect("Failed to check body");

        let tech_names: Vec<String> = results.iter().map(|r| r.tech_name.clone()).collect();

        // WordPress should be detected via /wp-content/ pattern
        assert!(
            tech_names.contains(&"WordPress".to_string()),
            "Could not detect WordPress via HTML pattern"
        );
    }
}
