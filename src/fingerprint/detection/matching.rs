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
    _script_tag_ids: &HashSet<String>,
) -> bool {
    // If technology requires cookies but we have none, skip it ONLY if cookies are the ONLY pattern type
    // If technology has other patterns (scriptSrc, headers, meta, html, url), we should still check it
    if !tech.cookies.is_empty() && !has_cookies {
        let has_other_patterns = !tech.headers.is_empty()
            || !tech.meta.is_empty()
            || !tech.script.is_empty()
            || !tech.html.is_empty()
            || !tech.url.is_empty();
        // Only skip if cookies are the ONLY pattern type
        if !has_other_patterns {
            return false;
        }
    }
    // If technology requires headers but we have none, skip it ONLY if headers are the ONLY pattern type
    if !tech.headers.is_empty() && !has_headers {
        let has_other_patterns = !tech.cookies.is_empty()
            || !tech.meta.is_empty()
            || !tech.script.is_empty()
            || !tech.html.is_empty()
            || !tech.url.is_empty();
        if !has_other_patterns {
            return false;
        }
    }
    // If technology requires meta tags but we have none, skip it ONLY if meta is the ONLY pattern type
    if !tech.meta.is_empty() && !has_meta {
        let has_other_patterns = !tech.cookies.is_empty()
            || !tech.headers.is_empty()
            || !tech.script.is_empty()
            || !tech.html.is_empty()
            || !tech.url.is_empty();
        if !has_other_patterns {
            return false;
        }
    }
    // If technology requires script sources but we have none, skip it
    if !tech.script.is_empty() && !has_scripts {
        return false;
    }
    // JS patterns are disabled to match wappalyzergo behavior (wappalyzergo doesn't check JS patterns)
    // If technology ONLY has JS patterns (no other patterns), skip it since we can't match JS
    if !tech.js.is_empty() {
        let has_other_patterns = !tech.headers.is_empty()
            || !tech.cookies.is_empty()
            || !tech.meta.is_empty()
            || !tech.script.is_empty()
            || !tech.html.is_empty()
            || !tech.url.is_empty();

        // If JS is the ONLY pattern type, skip it (we don't check JS patterns)
        if !has_other_patterns {
            return false;
        }
        // If technology has JS patterns AND other patterns, we still check it (via other patterns)
    }

    true
}

/// Applies technology exclusions, removing technologies that are excluded by others.
///
/// A technology is excluded if any other detected technology lists it in its `excludes` field.
/// For example, if TechA excludes TechB, and both are detected, TechB will be removed.
/// Extracts base technology name from formatted name (strips version if present).
/// "jQuery:3.6.0" -> "jQuery", "WordPress" -> "WordPress"
fn extract_base_tech_name(formatted_name: &str) -> &str {
    if let Some(colon_pos) = formatted_name.find(':') {
        &formatted_name[..colon_pos]
    } else {
        formatted_name
    }
}

pub(crate) fn apply_technology_exclusions(
    detected: HashSet<String>,
    ruleset: &FingerprintRuleset,
) -> HashSet<String> {
    let mut final_detected = HashSet::new();
    for tech_name in &detected {
        let base_tech_name = extract_base_tech_name(tech_name);

        // Check if this technology is excluded by any other detected technology
        let is_excluded = detected.iter().any(|other_tech_name| {
            if other_tech_name == tech_name {
                return false; // A technology doesn't exclude itself
            }
            let other_base_name = extract_base_tech_name(other_tech_name);

            // Check if the other technology excludes this one
            ruleset
                .technologies
                .get(other_base_name)
                .map(|other_tech| {
                    other_tech
                        .excludes
                        .iter()
                        .any(|excluded| excluded == base_tech_name)
                })
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
    /// The technology name (for exclusions and special cases)
    pub tech_name: &'a str,
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
    #[allow(dead_code)]
    // JS pattern matching is disabled to match wappalyzergo, but kept for potential future use
    pub script_tag_ids: &'a HashSet<String>, // Used for JS pattern matching (currently disabled)
}

/// Result of technology matching with optional version
pub struct TechnologyMatchResult {
    pub matched: bool,
    pub version: Option<String>,
}

/// Checks if a technology matches based on its patterns.
///
/// # Arguments
///
/// * `params` - Parameters for technology matching
///
/// # Returns
///
/// TechnologyMatchResult with match status and extracted version (if any)
///
/// # Note
///
/// Technologies with no patterns (empty script, html, js, headers, cookies, meta, url)
/// will never match. This is by design - if a technology has no detection patterns,
/// it cannot be detected.
pub(crate) async fn matches_technology(params: TechnologyMatchParams<'_>) -> TechnologyMatchResult {
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
        return TechnologyMatchResult {
            matched: false,
            version: None,
        };
    }
    // Match headers (header_name is already normalized to lowercase in ruleset)
    // wappalyzergo order: headers → cookies → body (HTML, scriptSrc, meta)
    // We match in the same order for consistency
    // Empty pattern means "header exists, value doesn't matter" (like cookies)
    // However, if header pattern matches without a version, we should continue checking other patterns
    // (meta) to find a version, as wappalyzergo takes the first version found across all patterns
    let mut header_matched = false;
    let mut header_version: Option<String> = None;
    for (header_name, pattern) in &params.tech.headers {
        if let Some(header_value) = params.headers.get(header_name) {
            if pattern.is_empty() {
                // Empty pattern means header exists (value doesn't matter)
                log::debug!(
                    "Technology matched via header: {} exists (empty pattern)",
                    header_name
                );
                header_matched = true;
                // Continue checking meta patterns for version
                break;
            }
            let result = matches_pattern(pattern, header_value);
            if result.matched {
                log::debug!(
                    "Technology matched via header: {}='{}' matched pattern '{}' (version: {:?})",
                    header_name,
                    header_value,
                    pattern,
                    result.version
                );
                header_matched = true;
                if header_version.is_none() && result.version.is_some() {
                    header_version = result.version.clone();
                }
                // If we found a version from header, we can return early
                if header_version.is_some() {
                    return TechnologyMatchResult {
                        matched: true,
                        version: header_version,
                    };
                }
                // Otherwise, continue checking meta patterns for version
            }
        }
    }

    // Match cookies (cookie_name is already normalized to lowercase in ruleset)
    // wappalyzergo supports wildcard cookie names (e.g., _ga_* matches _ga_123456)
    for (cookie_name, pattern) in &params.tech.cookies {
        // Check if cookie_name contains wildcard (*)
        if cookie_name.contains('*') {
            // Convert wildcard pattern to regex (e.g., _ga_* -> ^_ga_.*$)
            let wildcard_pattern = cookie_name.replace('*', ".*");
            let cookie_regex = match regex::Regex::new(&format!("^{}$", wildcard_pattern)) {
                Ok(re) => re,
                Err(_) => continue, // Invalid regex, skip this cookie pattern
            };

            // Check all cookies for a match
            for (actual_cookie_name, cookie_value) in params.cookies.iter() {
                if cookie_regex.is_match(actual_cookie_name) {
                    if pattern.is_empty() {
                        log::debug!(
                            "Technology matched via wildcard cookie: {} matches pattern '{}'",
                            actual_cookie_name,
                            cookie_name
                        );
                        return TechnologyMatchResult {
                            matched: true,
                            version: None,
                        };
                    }
                    let result = matches_pattern(pattern, cookie_value);
                    if result.matched {
                        log::debug!(
                            "Technology matched via wildcard cookie: {}='{}' matched pattern '{}' (cookie pattern: '{}')",
                            actual_cookie_name,
                            cookie_value,
                            pattern,
                            cookie_name
                        );
                        return TechnologyMatchResult {
                            matched: true,
                            version: result.version,
                        };
                    }
                }
            }
        } else {
            // Exact match (no wildcard)
            if let Some(cookie_value) = params.cookies.get(cookie_name) {
                if pattern.is_empty() {
                    return TechnologyMatchResult {
                        matched: true,
                        version: None,
                    };
                }
                let result = matches_pattern(pattern, cookie_value);
                if result.matched {
                    log::debug!(
                        "Technology matched via cookie: {}='{}' matched pattern '{}'",
                        cookie_name,
                        cookie_value,
                        pattern
                    );
                    return TechnologyMatchResult {
                        matched: true,
                        version: result.version,
                    };
                }
            }
        }
    }

    // Match HTML patterns (wappalyzergo checks HTML patterns first in body, before scriptSrc and meta)
    // This is because checkBody() calls matchString(bodyString, htmlPart) before tokenizing
    // However, if HTML pattern matches without a version, we should continue checking other patterns
    // (script, meta) to find a version, as wappalyzergo takes the first version found across all patterns
    let mut html_matched = false;
    for pattern in &params.tech.html {
        let result = matches_pattern(pattern, params.html_text);
        if result.matched {
            html_matched = true;
            log::debug!(
                "Technology matched via HTML pattern: '{}' matched in HTML text (version: {:?})",
                pattern,
                result.version
            );
            // If we get a version from HTML pattern, we can return early
            if result.version.is_some() {
                return TechnologyMatchResult {
                    matched: true,
                    version: result.version,
                };
            }
            // Otherwise, continue checking other patterns for version
            // Don't break - check all HTML patterns first, then move to script/meta
            log::debug!(
                "HTML pattern matched without version, will continue checking script/meta patterns for version"
            );
        }
    }

    // Match script sources (wappalyzergo checks scriptSrc during HTML tokenization, after HTML patterns)
    // wappalyzergo iterates through scripts first, then patterns, and takes the first version found
    // This ensures that if multiple scripts match, we use the version from the first script (in script order)
    // wappalyzergo checks ALL patterns (both regex and simple substring), not just regex ones
    let mut matched_version: Option<String> = None;
    let mut has_match = false;

    // Detailed logging for debugging - trace exact execution path
    let is_jquery = params.tech_name.eq_ignore_ascii_case("jquery");
    let is_jsdelivr = params.tech_name.eq_ignore_ascii_case("jsdelivr");
    if is_jquery || is_jsdelivr {
        log::info!(
            "[TRACE] Checking {}: {} script sources, {} script patterns",
            params.tech_name,
            params.script_sources.len(),
            params.tech.script.len()
        );
        for (idx, pattern) in params.tech.script.iter().enumerate() {
            log::info!("[TRACE]   Pattern {}: '{}'", idx, pattern);
        }
    }

    // Iterate through scripts first (matching wappalyzergo's behavior)
    for (script_idx, script_src) in params.script_sources.iter().enumerate() {
        if is_jquery || is_jsdelivr {
            log::info!("[TRACE] Checking script {}: '{}'", script_idx, script_src);
        }
        // For each script, check all patterns and take the first version found
        for (pattern_idx, pattern) in params.tech.script.iter().enumerate() {
            let result = matches_pattern(pattern, script_src);

            // Always log for jQuery/jsDelivr to trace execution
            if is_jquery || is_jsdelivr {
                log::info!(
                    "[TRACE]   Pattern {} '{}' vs script '{}' -> matched={}, version={:?}",
                    pattern_idx,
                    pattern,
                    script_src,
                    result.matched,
                    result.version
                );
            } else {
                // Log attempts for other high-value technologies
                let high_value_patterns = [
                    "brightcove",
                    "react",
                    "salesforce",
                    "adobe",
                    "omniture",
                    "baidu",
                    "google",
                    "gtag",
                    "analytics",
                    "wp-content",
                    "wp-includes",
                    "wordpress",
                ];
                if high_value_patterns
                    .iter()
                    .any(|p| pattern.to_lowercase().contains(p))
                {
                    log::debug!(
                        "Script pattern check: pattern '{}' vs script '{}' -> {} (version: {:?})",
                        pattern,
                        script_src,
                        result.matched,
                        result.version
                    );
                }
            }

            if result.matched {
                has_match = true;
                if is_jquery || is_jsdelivr {
                    log::info!(
                        "[TRACE]   ✓ MATCHED! Pattern {} '{}' matched script '{}' (version: {:?})",
                        pattern_idx,
                        pattern,
                        script_src,
                        result.version
                    );
                } else {
                    log::debug!(
                        "Technology matched via script src: pattern '{}' matched '{}' (version: {:?})",
                        pattern,
                        script_src,
                        result.version
                    );
                }
                // wappalyzergo behavior: take the first version found (from first script that matches)
                // Once we have a version from this script, we can stop checking other patterns for this script
                if matched_version.is_none() && result.version.is_some() {
                    matched_version = result.version.clone();
                    if is_jquery || is_jsdelivr {
                        log::info!("[TRACE]   Set version to: {:?}", matched_version);
                    }
                }
                // If we already have a version, we can break (first version wins)
                // But we still need to check if any pattern matches (for has_match flag)
                if matched_version.is_some() {
                    if is_jquery || is_jsdelivr {
                        log::info!("[TRACE]   Breaking pattern loop - version found");
                    }
                    break; // Found version from this script, move to next script
                } else if is_jquery || is_jsdelivr {
                    log::info!(
                        "[TRACE]   Pattern matched without version, continuing to check other patterns"
                    );
                } else {
                    log::debug!(
                        "Script pattern matched without version, will continue checking other patterns for version"
                    );
                }
            }
        }
        // If we found a match with a version, we can return early (first version wins)
        // But we still need to check all scripts to see if any match (for has_match flag)
        // Actually, wappalyzergo takes the first version found, so we can return once we have it
        if has_match && matched_version.is_some() {
            if is_jquery || is_jsdelivr {
                log::info!("[TRACE] Breaking script loop - match with version found");
            }
            break; // Found first version, stop checking other scripts
        }
    }

    if is_jquery || is_jsdelivr {
        log::info!(
            "[TRACE] Final result for {}: has_match={}, version={:?}",
            params.tech_name,
            has_match,
            matched_version
        );
    }
    if has_match {
        // If we found a version from script patterns, return it
        if matched_version.is_some() {
            return TechnologyMatchResult {
                matched: true,
                version: matched_version,
            };
        }
        // Otherwise, continue checking meta patterns for version
    }

    // Match meta tags (wappalyzergo checks meta during HTML tokenization, after scriptSrc)
    // Wappalyzer meta patterns can be:
    // - Simple name: "generator" -> matches meta name="generator"
    // - Prefixed: "property:og:title" -> matches meta property="og:title"
    // - Prefixed: "http-equiv:content-type" -> matches meta http-equiv="content-type"
    // Note: meta values are now Vec<String> to handle both string and array formats (from enthec source)
    // Meta patterns DO support version extraction (e.g., WordPress generator meta tag)
    // If we already matched via header/HTML/script but have no version, check meta for version
    // If we haven't matched yet, check meta normally
    if header_matched || html_matched || has_match {
        log::debug!(
            "Already matched via header/HTML/script (header_matched={}, html_matched={}, has_match={}), checking meta patterns for version",
            header_matched,
            html_matched,
            has_match
        );
    }
    for (meta_key, patterns) in &params.tech.meta {
        let result = check_meta_patterns(meta_key, patterns, params.meta_tags);
        if result.matched {
            log::debug!(
                "Technology matched via meta tag: {} (version: {:?})",
                meta_key,
                result.version
            );
            // If we already matched via header/HTML/script, use that match but take version from meta
            if header_matched || html_matched || has_match {
                log::debug!(
                    "Already matched via header/HTML/script, using version from meta: {:?}",
                    result.version
                );
                return TechnologyMatchResult {
                    matched: true,
                    version: result.version, // Use version from meta (first version found)
                };
            }
            // Otherwise, this is the first match
            return TechnologyMatchResult {
                matched: true,
                version: result.version,
            };
        } else if header_matched || html_matched || has_match {
            // Log when meta check fails but we already have a match (for debugging)
            log::debug!(
                "Meta pattern check failed for key '{}' (already matched via header/HTML/script, continuing to check other meta keys)",
                meta_key
            );
        }
    }

    // If we matched via header/HTML/script but found no version in meta, return match without version
    if header_matched || html_matched || has_match {
        return TechnologyMatchResult {
            matched: true,
            version: None,
        };
    }

    // Match URL patterns (can be multiple patterns)
    for url_pattern in &params.tech.url {
        let result = matches_pattern(url_pattern, params.url);
        if result.matched {
            return TechnologyMatchResult {
                matched: true,
                version: result.version,
            };
        }
    }

    // Match JavaScript patterns (js field) - DISABLED to match wappalyzergo behavior
    // wappalyzergo does NOT check JS patterns at all (commented out in fingerprint_body.go lines 50-57)
    // The TODO comment says: "JS requires a running VM, for checking properties. Only possible with headless for now :("
    // Therefore, we also disable JS pattern matching to achieve parity with wappalyzergo
    //
    // NOTE: This means technologies that ONLY have JS patterns (and no other patterns) will never be detected
    // This matches wappalyzergo's behavior exactly

    // JS patterns are disabled - return false (no match via JS)
    TechnologyMatchResult {
        matched: false,
        version: None,
    }
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
    fn test_can_technology_match_js_only_patterns_skipped() {
        // Test that technologies with ONLY JS patterns are skipped (JS patterns are disabled)
        let mut tech = create_empty_technology();
        tech.js
            .insert("__NEXT_DATA__".to_string(), ".*".to_string());

        // If JS is the ONLY pattern type, should return false (we don't check JS patterns)
        assert!(!can_technology_match(
            &tech,
            true,
            true,
            true,
            true,
            &HashSet::new()
        ));

        // Even if script tag ID exists, should still return false (JS patterns are disabled)
        let mut _script_tag_ids = HashSet::new();
        _script_tag_ids.insert("__NEXT_DATA__".to_string());
        assert!(!can_technology_match(
            &tech,
            true,
            true,
            true,
            true,
            &_script_tag_ids
        ));
    }

    #[test]
    fn test_can_technology_match_js_with_other_patterns() {
        // Test that technologies with JS patterns AND other patterns are still checked
        let mut tech = create_empty_technology();
        tech.js
            .insert("__NEXT_DATA__".to_string(), ".*".to_string());
        tech.headers
            .insert("x-powered-by".to_string(), "next.js".to_string());

        // Should return true because it has header patterns (even though JS patterns are disabled)
        assert!(can_technology_match(
            &tech,
            true, // has_headers
            true,
            true,
            true,
            &HashSet::new()
        ));
    }

    #[test]
    fn test_can_technology_match_js_with_other_patterns_shopify() {
        // Test that technologies with JS patterns AND other patterns (like Shopify)
        // are not skipped even if JS can't match
        let mut tech = create_empty_technology();
        tech.js.insert("Shopify".to_string(), ".*".to_string());
        tech.headers
            .insert("powered-by".to_string(), "shopify".to_string());
        tech.cookies
            .insert("_shopify_y".to_string(), "".to_string());

        // Should return true even if script tag ID not found, because headers/cookies exist
        assert!(can_technology_match(
            &tech,
            true, // has_cookies
            true, // has_headers
            true,
            true,
            &HashSet::new() // No script tag IDs
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
            tech_name: "TestTech",
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
            !result.matched,
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
            tech_name: "TestTech",
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
        assert!(!result.matched);
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
            tech_name: "TestTech",
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
        assert!(result.matched);
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
            tech_name: "TestTech",
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
        // Pattern matching is case-insensitive now (to match wappalyzergo), so "nginx" will match "NGINX"
        // Headers are normalized to lowercase, so this should match
        assert!(
            result.matched,
            "Case-insensitive pattern 'nginx' should match 'NGINX' (normalized)"
        );
    }

    #[test]
    fn test_matches_technology_url_pattern_special_chars() {
        // Test URL pattern matching with special characters
        let mut tech = create_empty_technology();
        tech.url.push("example\\.com".to_string()); // Escaped dot in regex

        let params = TechnologyMatchParams {
            tech: &tech,
            tech_name: "TestTech",
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
        assert!(result.matched);
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
            tech_name: "TestTech",
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
        assert!(result.matched);
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
            tech_name: "TestTech",
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
            !result.matched,
            "Should not match 'WordPress' in long text without that word"
        );
    }

    #[test]
    fn test_matches_technology_script_version_selection_order() {
        // Test that when multiple scripts match different patterns, we take the version from the first script
        // This reproduces the 1liberty.com issue where:
        // - Script 1: jquery-3.2.1.slim.min.js matches pattern 2, extracts 3.2.1
        // - Script 2: jquery/3.3.1/jquery.min.js matches pattern 1, extracts 3.3.1
        // wappalyzergo detects 3.2.1 (from first script), so we should too
        let mut tech = create_empty_technology();
        tech.script
            .push(r"/(\d+\.\d+\.\d+)/jquery[/.-][^u]\;version:\1".to_string()); // Pattern 1: matches script 2
        tech.script
            .push(r"/jquery(?:-(\d+\.\d+\.\d+))[/.-]\;version:\1".to_string()); // Pattern 2: matches script 1

        let script_sources = vec![
            "https://code.jquery.com/jquery-3.2.1.slim.min.js".to_string(), // Script 1: matches pattern 2, version 3.2.1
            "https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js".to_string(), // Script 2: matches pattern 1, version 3.3.1
        ];

        let params = TechnologyMatchParams {
            tech: &tech,
            tech_name: "TestTech",
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

        assert!(result.matched, "Should match jQuery");
        // Should detect version 3.2.1 (from first script), not 3.3.1 (from second script)
        assert_eq!(
            result.version,
            Some("3.2.1".to_string()),
            "Should detect version 3.2.1 from first script (matching wappalyzergo behavior)"
        );
    }

    #[test]
    fn test_can_technology_match_with_cookies_and_scripts() {
        // Test that technologies with both cookies and scriptSrc patterns are still checked
        // even if we don't have cookies, because they can match via scriptSrc
        // This fixes the Google Analytics detection issue
        let mut tech = create_empty_technology();
        tech.cookies.insert("_ga".to_string(), String::new()); // Cookie pattern
        tech.script
            .push("googletagmanager\\.com/gtag/js".to_string()); // Script pattern

        // Should return true even if no cookies, because it has script patterns
        assert!(can_technology_match(
            &tech,
            false, // has_cookies = false
            true,
            true,
            true, // has_scripts = true
            &HashSet::new()
        ));

        // Should return false if no cookies AND no scripts (can't match via either)
        assert!(!can_technology_match(
            &tech,
            false, // has_cookies = false
            true,
            true,
            false, // has_scripts = false
            &HashSet::new()
        ));
    }

    #[test]
    fn test_matches_technology_google_analytics_via_script() {
        // Test Google Analytics detection via scriptSrc pattern (even without cookies)
        let mut tech = create_empty_technology();
        tech.cookies.insert("_ga".to_string(), String::new()); // Cookie pattern (not required)
        tech.script
            .push("googletagmanager\\.com/gtag/js".to_string()); // Script pattern

        let script_sources =
            vec!["https://www.googletagmanager.com/gtag/js?id=UA-821816-93".to_string()];

        let params = TechnologyMatchParams {
            tech: &tech,
            tech_name: "TestTech",
            headers: &HashMap::new(),
            cookies: &HashMap::new(), // No cookies, but should still match via script
            meta_tags: &HashMap::new(),
            script_sources: &script_sources,
            html_text: "",
            url: "https://example.com",
            script_tag_ids: &HashSet::new(),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(matches_technology(params));

        assert!(
            result.matched,
            "Should match Google Analytics via scriptSrc pattern"
        );
    }

    #[test]
    fn test_matches_technology_wordpress_version_from_meta_after_html_match() {
        // Test WordPress version extraction from meta generator tag when HTML pattern matches first
        // This reproduces the 4dmoleculartherapeutics.com issue
        let mut tech = create_empty_technology();
        tech.html
            .push(r#"<link rel=["']stylesheet["'] [^>]+/wp-(?:content|includes)/"#.to_string()); // HTML pattern (matches first)
        tech.meta.insert(
            "generator".to_string(),
            vec![r"^wordpress(?: ([\d.]+))?\;version:\1".to_string()],
        ); // Meta pattern with version

        let mut meta_tags = HashMap::new();
        meta_tags.insert("name:generator".to_string(), "WordPress 6.8.3".to_string());

        let params = TechnologyMatchParams {
            tech: &tech,
            tech_name: "TestTech",
            headers: &HashMap::new(),
            cookies: &HashMap::new(),
            meta_tags: &meta_tags,
            script_sources: &[],
            html_text: r#"<link rel='stylesheet' href='/wp-content/themes/style.css'>"#, // HTML that matches
            url: "https://example.com",
            script_tag_ids: &HashSet::new(),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(matches_technology(params));

        assert!(result.matched, "Should match WordPress");
        assert_eq!(
            result.version,
            Some("6.8.3".to_string()),
            "Should extract version 6.8.3 from meta generator tag even when HTML pattern matches first"
        );
    }
}
