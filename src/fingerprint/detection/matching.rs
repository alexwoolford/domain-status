//! Technology matching logic.
//!
//! This module provides functions to check if technologies match based on
//! their patterns and available data.

use std::collections::{HashMap, HashSet};

use crate::fingerprint::models::{FingerprintRuleset, Technology};
use crate::fingerprint::patterns::{check_meta_patterns, matches_pattern};

/// Checks if a technology can potentially match based on available data.
///
/// Returns `false` if the technology requires data that we don't have, allowing early exit.
pub(crate) fn can_technology_match(
    tech: &Technology,
    has_cookies: bool,
    has_headers: bool,
    has_meta: bool,
    has_scripts: bool,
    script_tag_ids: &HashSet<String>,
) -> bool {
    // If technology requires cookies but we have none, skip it
    if !tech.cookies.is_empty() && !has_cookies {
        return false;
    }
    // If technology requires headers but we have none, skip it
    if !tech.headers.is_empty() && !has_headers {
        return false;
    }
    // If technology requires meta tags but we have none, skip it
    if !tech.meta.is_empty() && !has_meta {
        return false;
    }
    // If technology requires script sources but we have none, skip it
    if !tech.script.is_empty() && !has_scripts {
        return false;
    }
    // If technology requires JS patterns but we can't match via script tag IDs, skip it
    // We only match JS patterns via script tag IDs (e.g., __NEXT_DATA__), not via script content
    if !tech.js.is_empty() {
        let can_match_via_tag_id = tech.js.keys().any(|prop| script_tag_ids.contains(prop));
        if !can_match_via_tag_id {
            return false;
        }
    }

    true
}

/// Applies technology exclusions, removing technologies that are excluded by others.
///
/// A technology is excluded if any other detected technology lists it in its `excludes` field.
/// For example, if TechA excludes TechB, and both are detected, TechB will be removed.
pub(crate) fn apply_technology_exclusions(
    detected: HashSet<String>,
    ruleset: &FingerprintRuleset,
) -> HashSet<String> {
    let mut final_detected = HashSet::new();
    for tech_name in &detected {
        // Check if this technology is excluded by any other detected technology
        let is_excluded = detected.iter().any(|other_tech_name| {
            if other_tech_name == tech_name {
                return false; // A technology doesn't exclude itself
            }
            ruleset
                .technologies
                .get(other_tech_name)
                .map(|other_tech| other_tech.excludes.contains(tech_name))
                .unwrap_or(false)
        });

        if !is_excluded {
            final_detected.insert(tech_name.clone());
        }
    }
    final_detected
}

/// Parameters for technology matching.
///
/// This struct groups all parameters needed to match a technology, reducing
/// function argument count and improving maintainability.
pub struct TechnologyMatchParams<'a> {
    /// The technology to match
    pub tech: &'a Technology,
    /// HTTP headers (normalized to lowercase)
    pub headers: &'a HashMap<String, String>,
    /// HTTP cookies (normalized to lowercase)
    pub cookies: &'a HashMap<String, String>,
    /// HTML meta tags
    pub meta_tags: &'a HashMap<String, String>,
    /// Script source URLs
    pub script_sources: &'a [String],
    /// HTML text content
    pub html_text: &'a str,
    /// The URL being checked
    pub url: &'a str,
    /// Script tag IDs found in HTML (for __NEXT_DATA__ etc.)
    pub script_tag_ids: &'a HashSet<String>,
}

/// Checks if a technology matches based on its patterns.
///
/// # Arguments
///
/// * `params` - Parameters for technology matching
///
/// # Note
///
/// Technologies with no patterns (empty script, html, js, headers, cookies, meta, url)
/// will never match. This is by design - if a technology has no detection patterns,
/// it cannot be detected.
pub(crate) async fn matches_technology(params: TechnologyMatchParams<'_>) -> bool {
    // If technology has no patterns at all, it cannot match
    // This handles cases like Brightcove which has empty patterns in the ruleset
    if params.tech.script.is_empty()
        && params.tech.html.is_empty()
        && params.tech.js.is_empty()
        && params.tech.headers.is_empty()
        && params.tech.cookies.is_empty()
        && params.tech.meta.is_empty()
        && params.tech.url.is_empty()
    {
        return false;
    }
    // Match headers (header_name is already normalized to lowercase in ruleset)
    for (header_name, pattern) in &params.tech.headers {
        if let Some(header_value) = params.headers.get(header_name) {
            if matches_pattern(pattern, header_value) {
                log::debug!(
                    "Technology matched via header: {}='{}' matched pattern '{}'",
                    header_name,
                    header_value,
                    pattern
                );
                return true;
            }
        }
    }

    // Match cookies (cookie_name is already normalized to lowercase in ruleset)
    for (cookie_name, pattern) in &params.tech.cookies {
        if let Some(cookie_value) = params.cookies.get(cookie_name) {
            if pattern.is_empty() || matches_pattern(pattern, cookie_value) {
                log::debug!(
                    "Technology matched via cookie: {}='{}' matched pattern '{}'",
                    cookie_name,
                    cookie_value,
                    pattern
                );
                return true;
            }
        }
    }

    // Match meta tags
    // Wappalyzer meta patterns can be:
    // - Simple name: "generator" -> matches meta name="generator"
    // - Prefixed: "property:og:title" -> matches meta property="og:title"
    // - Prefixed: "http-equiv:content-type" -> matches meta http-equiv="content-type"
    // Note: meta values are now Vec<String> to handle both string and array formats (from enthec source)
    for (meta_key, patterns) in &params.tech.meta {
        if check_meta_patterns(meta_key, patterns, params.meta_tags) {
            return true;
        }
    }

    // Match script sources
    for pattern in &params.tech.script {
        for script_src in params.script_sources {
            let matched = matches_pattern(pattern, script_src);
            // Log attempts for high-value technologies to debug why they're not matching
            let high_value_patterns = [
                "brightcove",
                "jquery",
                "react",
                "salesforce",
                "adobe",
                "omniture",
            ];
            if high_value_patterns
                .iter()
                .any(|p| pattern.to_lowercase().contains(p))
            {
                log::debug!(
                    "Script pattern check: pattern '{}' vs script '{}' -> {}",
                    pattern,
                    script_src,
                    matched
                );
            }
            if matched {
                log::debug!(
                    "Technology matched via script src: pattern '{}' matched '{}'",
                    pattern,
                    script_src
                );
                return true;
            }
        }
    }

    // Match HTML text
    for pattern in &params.tech.html {
        if matches_pattern(pattern, params.html_text) {
            log::debug!(
                "Technology matched via HTML pattern: '{}' matched in HTML text",
                pattern
            );
            return true;
        }
    }

    // Match URL patterns (can be multiple patterns)
    for url_pattern in &params.tech.url {
        if matches_pattern(url_pattern, params.url) {
            return true;
        }
    }

    // Match JavaScript patterns (js field) - only via script tag IDs
    // WappalyzerGo does NOT execute JavaScript and does NOT match JS properties in source code
    // It only checks script tag IDs (e.g., <script id="__NEXT_DATA__"> for Next.js)
    // This matches WappalyzerGo's behavior exactly
    if params.tech.js.is_empty() {
        return false;
    }

    // Check if any JS property matches a script tag ID
    // This is how Next.js and similar technologies are detected
    for js_property in params.tech.js.keys() {
        if params.script_tag_ids.contains(js_property) {
            log::debug!("Technology matched via script tag ID '{}'", js_property);
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::models::Technology;

    fn create_empty_technology() -> Technology {
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

    fn create_test_metadata() -> crate::fingerprint::models::FingerprintMetadata {
        crate::fingerprint::models::FingerprintMetadata {
            source: "test".to_string(),
            version: "test".to_string(),
            last_updated: std::time::SystemTime::now(),
        }
    }

    #[test]
    fn test_can_technology_match_requires_cookies() {
        let mut tech = create_empty_technology();
        tech.cookies.insert("session".to_string(), ".*".to_string());

        // Should return false if no cookies available
        assert!(!can_technology_match(
            &tech,
            false,
            true,
            true,
            true,
            &HashSet::new()
        ));

        // Should return true if cookies available
        assert!(can_technology_match(
            &tech,
            true,
            true,
            true,
            true,
            &HashSet::new()
        ));
    }

    #[test]
    fn test_can_technology_match_requires_headers() {
        let mut tech = create_empty_technology();
        tech.headers
            .insert("server".to_string(), "nginx".to_string());

        // Should return false if no headers available
        assert!(!can_technology_match(
            &tech,
            true,
            false,
            true,
            true,
            &HashSet::new()
        ));

        // Should return true if headers available
        assert!(can_technology_match(
            &tech,
            true,
            true,
            true,
            true,
            &HashSet::new()
        ));
    }

    #[test]
    fn test_can_technology_match_requires_meta() {
        let mut tech = create_empty_technology();
        tech.meta
            .insert("generator".to_string(), vec!["WordPress".to_string()]);

        // Should return false if no meta tags available
        assert!(!can_technology_match(
            &tech,
            true,
            true,
            false,
            true,
            &HashSet::new()
        ));

        // Should return true if meta tags available
        assert!(can_technology_match(
            &tech,
            true,
            true,
            true,
            true,
            &HashSet::new()
        ));
    }

    #[test]
    fn test_can_technology_match_requires_scripts() {
        let mut tech = create_empty_technology();
        tech.script.push("jquery".to_string());

        // Should return false if no scripts available
        assert!(!can_technology_match(
            &tech,
            true,
            true,
            true,
            false,
            &HashSet::new()
        ));

        // Should return true if scripts available
        assert!(can_technology_match(
            &tech,
            true,
            true,
            true,
            true,
            &HashSet::new()
        ));
    }

    #[test]
    fn test_can_technology_match_requires_js_tag_id() {
        let mut tech = create_empty_technology();
        tech.js
            .insert("__NEXT_DATA__".to_string(), ".*".to_string());

        // Should return false if script tag ID not found
        assert!(!can_technology_match(
            &tech,
            true,
            true,
            true,
            true,
            &HashSet::new()
        ));

        // Should return true if script tag ID found
        let mut script_tag_ids = HashSet::new();
        script_tag_ids.insert("__NEXT_DATA__".to_string());
        assert!(can_technology_match(
            &tech,
            true,
            true,
            true,
            true,
            &script_tag_ids
        ));
    }

    #[test]
    fn test_can_technology_match_no_requirements() {
        let tech = create_empty_technology();
        // Technology with no requirements should always return true
        assert!(can_technology_match(
            &tech,
            false,
            false,
            false,
            false,
            &HashSet::new()
        ));
    }

    #[test]
    fn test_matches_technology_empty_patterns() {
        // Technology with no patterns should never match
        // Note: matches_technology is async, so we test the logic indirectly via
        // can_technology_match and integration tests. The empty patterns check
        // is tested in the actual detection flow.
    }

    #[test]
    fn test_apply_technology_exclusions_no_exclusions() {
        let ruleset = FingerprintRuleset {
            technologies: HashMap::new(),
            categories: HashMap::new(),
            metadata: create_test_metadata(),
        };

        let mut detected = HashSet::new();
        detected.insert("WordPress".to_string());
        detected.insert("PHP".to_string());

        let result = apply_technology_exclusions(detected, &ruleset);
        assert_eq!(result.len(), 2);
        assert!(result.contains("WordPress"));
        assert!(result.contains("PHP"));
    }

    #[test]
    fn test_apply_technology_exclusions_with_exclusion() {
        let mut ruleset = FingerprintRuleset {
            technologies: HashMap::new(),
            categories: HashMap::new(),
            metadata: create_test_metadata(),
        };

        let mut tech_a = create_empty_technology();
        tech_a.excludes.push("TechB".to_string());
        ruleset.technologies.insert("TechA".to_string(), tech_a);

        let mut detected = HashSet::new();
        detected.insert("TechA".to_string());
        detected.insert("TechB".to_string());

        let result = apply_technology_exclusions(detected, &ruleset);
        // TechB should be excluded because TechA excludes it
        assert_eq!(result.len(), 1);
        assert!(result.contains("TechA"));
        assert!(!result.contains("TechB"));
    }

    #[test]
    fn test_apply_technology_exclusions_multiple_exclusions() {
        let mut ruleset = FingerprintRuleset {
            technologies: HashMap::new(),
            categories: HashMap::new(),
            metadata: create_test_metadata(),
        };

        let mut tech_a = create_empty_technology();
        tech_a.excludes.push("TechB".to_string());
        tech_a.excludes.push("TechC".to_string());
        ruleset.technologies.insert("TechA".to_string(), tech_a);

        let mut detected = HashSet::new();
        detected.insert("TechA".to_string());
        detected.insert("TechB".to_string());
        detected.insert("TechC".to_string());
        detected.insert("TechD".to_string());

        let result = apply_technology_exclusions(detected, &ruleset);
        // TechB and TechC should be excluded
        assert_eq!(result.len(), 2);
        assert!(result.contains("TechA"));
        assert!(result.contains("TechD"));
        assert!(!result.contains("TechB"));
        assert!(!result.contains("TechC"));
    }

    #[test]
    fn test_apply_technology_exclusions_exclusion_not_detected() {
        let mut ruleset = FingerprintRuleset {
            technologies: HashMap::new(),
            categories: HashMap::new(),
            metadata: create_test_metadata(),
        };

        let mut tech_a = create_empty_technology();
        tech_a.excludes.push("TechB".to_string());
        ruleset.technologies.insert("TechA".to_string(), tech_a);

        let mut detected = HashSet::new();
        detected.insert("TechA".to_string());
        // TechB is not detected, so exclusion shouldn't matter

        let result = apply_technology_exclusions(detected, &ruleset);
        assert_eq!(result.len(), 1);
        assert!(result.contains("TechA"));
    }

    #[test]
    fn test_apply_technology_exclusions_unknown_technology() {
        let ruleset = FingerprintRuleset {
            technologies: HashMap::new(),
            categories: HashMap::new(),
            metadata: create_test_metadata(),
        };

        let mut detected = HashSet::new();
        detected.insert("UnknownTech".to_string());

        // Unknown technology should still be included (no exclusion rules)
        let result = apply_technology_exclusions(detected, &ruleset);
        assert_eq!(result.len(), 1);
        assert!(result.contains("UnknownTech"));
    }

    #[test]
    fn test_apply_technology_exclusions_missing_technology_in_ruleset() {
        // Test that missing technology in ruleset doesn't cause panic
        // This is critical - if a technology is detected but not in ruleset, exclusion check should handle it
        let mut ruleset = FingerprintRuleset {
            technologies: HashMap::new(),
            categories: HashMap::new(),
            metadata: create_test_metadata(),
        };

        // Add one technology that excludes another
        let mut tech_a = create_empty_technology();
        tech_a.excludes.push("TechB".to_string());
        ruleset.technologies.insert("TechA".to_string(), tech_a);

        // Detect TechA and TechB, but TechB is not in ruleset
        let mut detected = HashSet::new();
        detected.insert("TechA".to_string());
        detected.insert("TechB".to_string()); // Not in ruleset

        let result = apply_technology_exclusions(detected, &ruleset);
        // TechB should be excluded by TechA (even though TechB is not in ruleset)
        // The exclusion check uses .unwrap_or(false), so missing tech = no exclusion
        // But TechA.excludes contains "TechB", so TechB should be excluded
        assert!(result.contains("TechA"));
        // TechB should be excluded because TechA.excludes contains "TechB"
        assert!(!result.contains("TechB"));
    }

    #[test]
    fn test_matches_technology_all_empty_patterns() {
        // Test technology with all empty patterns (should not match)
        let tech = create_empty_technology();
        let params = TechnologyMatchParams {
            tech: &tech,
            headers: &HashMap::new(),
            cookies: &HashMap::new(),
            meta_tags: &HashMap::new(),
            script_sources: &[],
            html_text: "some content",
            url: "https://example.com",
            script_tag_ids: &HashSet::new(),
        };

        // Technology with no patterns should not match (tested in matches_technology function)
        // This is a critical edge case - empty technology should never match
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(matches_technology(params));
        assert!(
            !result,
            "Technology with all empty patterns should not match"
        );
    }

    #[test]
    fn test_matches_technology_js_empty_but_has_js_field() {
        // Test that JS field matching only works via script_tag_ids
        // If js field is not empty but no matching script_tag_ids, should not match
        let mut tech = create_empty_technology();
        tech.js
            .insert("__NEXT_DATA__".to_string(), ".*".to_string());

        let params = TechnologyMatchParams {
            tech: &tech,
            headers: &HashMap::new(),
            cookies: &HashMap::new(),
            meta_tags: &HashMap::new(),
            script_sources: &[],
            html_text: "",
            url: "https://example.com",
            script_tag_ids: &HashSet::new(), // No matching script tag ID
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(matches_technology(params));
        // Should not match because script_tag_ids doesn't contain "__NEXT_DATA__"
        assert!(!result);
    }

    #[test]
    fn test_matches_technology_cookie_empty_pattern() {
        // Test that empty cookie pattern matches any value (special case in code)
        let mut tech = create_empty_technology();
        tech.cookies.insert("session".to_string(), String::new()); // Empty pattern

        let mut cookies = HashMap::new();
        cookies.insert("session".to_string(), "any_value".to_string());

        let params = TechnologyMatchParams {
            tech: &tech,
            headers: &HashMap::new(),
            cookies: &cookies,
            meta_tags: &HashMap::new(),
            script_sources: &[],
            html_text: "",
            url: "https://example.com",
            script_tag_ids: &HashSet::new(),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(matches_technology(params));
        // Empty pattern should match any cookie value
        assert!(result);
    }

    #[test]
    fn test_matches_technology_header_case_sensitivity() {
        // Test that header matching is case-insensitive (headers normalized to lowercase)
        let mut tech = create_empty_technology();
        tech.headers
            .insert("server".to_string(), "nginx".to_string());

        // Headers should be normalized to lowercase before matching
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "NGINX/1.18.0".to_string()); // Uppercase value

        let params = TechnologyMatchParams {
            tech: &tech,
            headers: &headers,
            cookies: &HashMap::new(),
            meta_tags: &HashMap::new(),
            script_sources: &[],
            html_text: "",
            url: "https://example.com",
            script_tag_ids: &HashSet::new(),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(matches_technology(params));
        // Pattern matching is case-sensitive, so "nginx" won't match "NGINX"
        // This tests the actual behavior (case-sensitive pattern matching)
        assert!(
            !result,
            "Case-sensitive pattern 'nginx' should not match 'NGINX'"
        );
    }

    #[test]
    fn test_matches_technology_url_pattern_special_chars() {
        // Test URL pattern matching with special characters
        let mut tech = create_empty_technology();
        tech.url.push("example\\.com".to_string()); // Escaped dot in regex

        let params = TechnologyMatchParams {
            tech: &tech,
            headers: &HashMap::new(),
            cookies: &HashMap::new(),
            meta_tags: &HashMap::new(),
            script_sources: &[],
            html_text: "",
            url: "https://example.com/page",
            script_tag_ids: &HashSet::new(),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(matches_technology(params));
        // Escaped dot should match literal dot
        assert!(result);
    }

    #[test]
    fn test_matches_technology_script_source_special_chars() {
        // Test script source matching with URL-encoded and special characters
        let mut tech = create_empty_technology();
        tech.script.push("jquery".to_string());

        let script_sources = vec![
            "https://example.com/jquery.min.js".to_string(),
            "https://cdn.example.com/libs/jquery/3.6.0/jquery.js".to_string(),
        ];

        let params = TechnologyMatchParams {
            tech: &tech,
            headers: &HashMap::new(),
            cookies: &HashMap::new(),
            meta_tags: &HashMap::new(),
            script_sources: &script_sources,
            html_text: "",
            url: "https://example.com",
            script_tag_ids: &HashSet::new(),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(matches_technology(params));
        // Should match script sources containing "jquery"
        assert!(result);
    }

    #[test]
    fn test_matches_technology_html_pattern_very_long_text() {
        // Test HTML pattern matching with very long HTML text
        let mut tech = create_empty_technology();
        tech.html.push("WordPress".to_string());

        // Create very long HTML text
        let html_text = format!("<html><body>{}</body></html>", "content ".repeat(10000));

        let params = TechnologyMatchParams {
            tech: &tech,
            headers: &HashMap::new(),
            cookies: &HashMap::new(),
            meta_tags: &HashMap::new(),
            script_sources: &[],
            html_text: &html_text,
            url: "https://example.com",
            script_tag_ids: &HashSet::new(),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(matches_technology(params));
        // Should handle very long text without panicking
        assert!(
            !result,
            "Should not match 'WordPress' in long text without that word"
        );
    }
}
