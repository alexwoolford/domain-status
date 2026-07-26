//! Body-based technology detection (HTML, script sources, meta tags).
//!
//! This module matches technologies based on HTML body content,
//! following wappalyzergo's `checkBody()` logic which checks:
//! 1. HTML patterns (via `matchString(body, htmlPart)`)
//! 2. Script sources (via `matchString(scriptSrc, scriptPart)`)
//! 3. Meta tags (via `matchKeyValueString(name, content, metaPart)`)

use std::collections::HashMap;

use crate::fingerprint::models::FingerprintRuleset;
use crate::fingerprint::patterns::{check_meta_patterns, matches_pattern};

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
/// Synchronous body check using a pre-fetched ruleset (for use on blocking threads).
pub(crate) fn check_body_with_ruleset(
    ruleset: &FingerprintRuleset,
    html_body: &str,
    script_sources: &[String],
    meta_tags: &HashMap<String, Vec<String>>,
    url: &str,
) -> Vec<BodyMatchResult> {
    let mut results = Vec::new();
    for (tech_name, tech) in &ruleset.technologies {
        if tech.html.is_empty()
            && tech.script.is_empty()
            && tech.meta.is_empty()
            && tech.url.is_empty()
        {
            continue;
        }
        let mut matched = false;
        let mut version: Option<String> = None;
        for pattern in &tech.html {
            let result = matches_pattern(pattern, html_body);
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
        for script_src in script_sources {
            for pattern in &tech.script {
                let result = matches_pattern(pattern, script_src);
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
        for (meta_key, patterns) in &tech.meta {
            let result = check_meta_patterns(meta_key, patterns, meta_tags);
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
        for url_pattern in &tech.url {
            let result = matches_pattern(url_pattern, url);
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
        if matched {
            results.push(BodyMatchResult {
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

    /// Meta tag detection: `tech.meta` key `"generator"` matches `meta_tags` key
    /// `"name:generator"` (see `check_meta_patterns`).
    #[test]
    fn test_body_meta_generator_match() {
        let mut tech = empty_tech();
        tech.meta
            .insert("generator".to_string(), vec!["mura cms 1".to_string()]);
        let mut technologies = HashMap::new();
        technologies.insert("Mura CMS".to_string(), tech);
        let ruleset = ruleset_with(technologies);

        let html_body = r#"<html>
<head>
<meta name="generator" content="mura cms 1">
</head>
</html>"#;

        let mut meta_tags = HashMap::new();
        meta_tags.insert("name:generator".to_string(), vec!["mura cms 1".to_string()]);
        let script_sources = vec![];
        let url = "https://example.com";

        let results =
            check_body_with_ruleset(&ruleset, html_body, &script_sources, &meta_tags, url);

        let tech_names: Vec<String> = results.iter().map(|r| r.tech_name.clone()).collect();
        assert_eq!(
            tech_names,
            vec!["Mura CMS".to_string()],
            "Could not get correct match for Mura CMS via generator meta tag"
        );
    }

    /// HTML pattern detection via `data-ng-app` attribute (`AngularJS`).
    #[test]
    fn test_body_html_pattern_angularjs() {
        let mut tech = empty_tech();
        tech.html.push("data-ng-app".to_string());
        let mut technologies = HashMap::new();
        technologies.insert("AngularJS".to_string(), tech);
        let ruleset = ruleset_with(technologies);

        let html_body = r#"<html data-ng-app="rbschangeapp">
<head>
</head>
<body>
</body>
</html>"#;

        let meta_tags = HashMap::new();
        let script_sources = vec![];
        let url = "https://example.com";

        let results =
            check_body_with_ruleset(&ruleset, html_body, &script_sources, &meta_tags, url);

        let tech_names: Vec<String> = results.iter().map(|r| r.tech_name.clone()).collect();
        assert!(
            tech_names.contains(&"AngularJS".to_string()),
            "Could not get correct match for AngularJS via data-ng-app"
        );
    }

    /// Script source detection with version extraction (jQuery CDN URL).
    #[test]
    fn test_body_script_src_jquery() {
        let mut tech = empty_tech();
        tech.script
            .push(r"jquery(?:-(\d+\.\d+\.\d+))[/.-]\;version:\1".to_string());
        let mut technologies = HashMap::new();
        technologies.insert("jQuery".to_string(), tech);
        let ruleset = ruleset_with(technologies);

        let html_body = "";
        let script_sources = vec!["https://cdn.example.com/jquery-3.6.0.min.js".to_string()];
        let meta_tags = HashMap::new();
        let url = "https://example.com";

        let results =
            check_body_with_ruleset(&ruleset, html_body, &script_sources, &meta_tags, url);

        let result = results
            .iter()
            .find(|r| r.tech_name == "jQuery")
            .expect("Could not detect jQuery via script src");
        assert_eq!(result.version.as_deref(), Some("3.6.0"));
    }

    /// HTML pattern detection (`WordPress` via `/wp-content/`).
    #[test]
    fn test_body_html_pattern_wordpress() {
        let mut tech = empty_tech();
        tech.html.push("wp-content".to_string());
        let mut technologies = HashMap::new();
        technologies.insert("WordPress".to_string(), tech);
        let ruleset = ruleset_with(technologies);

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

        let results =
            check_body_with_ruleset(&ruleset, html_body, &script_sources, &meta_tags, url);

        let tech_names: Vec<String> = results.iter().map(|r| r.tech_name.clone()).collect();
        assert!(
            tech_names.contains(&"WordPress".to_string()),
            "Could not get correct match for WordPress via wp-content"
        );
    }

    #[test]
    fn test_check_body_with_empty_ruleset() {
        let ruleset = FingerprintRuleset::empty_for_tests();
        let html_body = "<html></html>";
        let script_sources = vec![];
        let meta_tags = HashMap::new();
        let url = "https://example.com";

        let results =
            check_body_with_ruleset(&ruleset, html_body, &script_sources, &meta_tags, url);
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_check_body_empty_inputs() {
        // Empty inputs must not panic; no remote ruleset required.
        let ruleset = FingerprintRuleset::empty_for_tests();

        let html_body = "";
        let script_sources = vec![];
        let meta_tags = HashMap::new();
        let url = "";

        let result = check_body_with_ruleset(&ruleset, html_body, &script_sources, &meta_tags, url);
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_check_body_very_large_html() {
        // Large HTML must not panic the matcher; no remote ruleset required.
        let ruleset = FingerprintRuleset::empty_for_tests();

        let large_html = format!("<html><body>{}</body></html>", "A".repeat(1_000_000));
        let script_sources = vec![];
        let meta_tags = HashMap::new();
        let url = "https://example.com";

        let _result =
            check_body_with_ruleset(&ruleset, &large_html, &script_sources, &meta_tags, url);
    }
}
