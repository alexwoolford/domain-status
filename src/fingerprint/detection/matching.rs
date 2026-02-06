//! Technology matching logic.
//!
//! This module provides functions to check if technologies match based on
//! their patterns and available data.

use std::collections::HashSet;

use crate::fingerprint::models::FingerprintRuleset;
#[cfg(test)]
use crate::fingerprint::models::Technology;
#[cfg(test)]
use crate::fingerprint::patterns::{check_meta_patterns, matches_pattern};

/// Checks if a technology can potentially match based on available data.
///
/// Returns `false` if the technology requires data that we don't have, allowing early exit.
///
/// # Note
/// This function is currently only used in tests. The main detection flow uses
/// `check_headers`, `check_cookies`, and `check_body` instead.
#[cfg(test)]
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
    detected: &HashSet<String>,
    ruleset: &FingerprintRuleset,
) -> HashSet<String> {
    let mut final_detected = HashSet::new();
    for tech_name in detected {
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
///
/// # Note
/// This struct is currently only used in tests. The main detection flow uses
/// `check_headers`, `check_cookies`, and `check_body` instead.
#[cfg(test)]
pub struct TechnologyMatchParams<'a> {
    /// The technology to match
    pub tech: &'a Technology,
    /// The technology name (for exclusions and special cases)
    #[allow(dead_code)]
    pub tech_name: &'a str,
    /// HTTP headers (normalized to lowercase)
    pub headers: &'a std::collections::HashMap<String, String>,
    /// HTTP cookies (normalized to lowercase)
    pub cookies: &'a std::collections::HashMap<String, String>,
    /// HTML meta tags
    pub meta_tags: &'a std::collections::HashMap<String, Vec<String>>, // Vec to handle multiple meta tags with same name
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
///
/// # Note
/// This struct is currently only used in tests. The main detection flow uses
/// `HeaderMatchResult`, `CookieMatchResult`, and `BodyMatchResult` instead.
#[cfg(test)]
pub struct TechnologyMatchResult {
    pub matched: bool,
    pub version: Option<String>,
}

/// Matches technology patterns against headers.
///
/// Returns match status and version if found. If a version is found, it should be returned immediately.
/// If no version is found but a match occurs, the caller should continue checking other patterns.
///
/// # Arguments
///
/// * `headers` - HTTP headers (normalized to lowercase)
/// * `header_patterns` - Technology header patterns (header_name -> pattern)
///
/// # Returns
///
/// `(matched: bool, version: Option<String>)` - Match status and optional version
#[cfg(test)]
fn match_headers(
    headers: &std::collections::HashMap<String, String>,
    header_patterns: &std::collections::HashMap<String, String>,
) -> (bool, Option<String>) {
    let mut matched = false;
    let mut version: Option<String> = None;

    for (header_name, pattern) in header_patterns {
        if let Some(header_value) = headers.get(header_name) {
            if pattern.is_empty() {
                // Empty pattern means header exists (value doesn't matter)
                log::debug!(
                    "Technology matched via header: {} exists (empty pattern)",
                    header_name
                );
                matched = true;
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
                matched = true;
                if version.is_none() && result.version.is_some() {
                    version = result.version.clone();
                }
                // If we found a version from header, we can return early
                if version.is_some() {
                    return (true, version);
                }
                // Otherwise, continue checking meta patterns for version
            }
        }
    }

    (matched, version)
}

/// Matches technology patterns against cookies, supporting wildcard cookie names.
///
/// Returns match status and version if found. Wildcard patterns (e.g., `_ga_*`) are converted to regex.
///
/// # Arguments
///
/// * `cookies` - HTTP cookies (normalized to lowercase)
/// * `cookie_patterns` - Technology cookie patterns (cookie_name -> pattern)
///
/// # Returns
///
/// `Option<Option<String>>` - `None` if no match, `Some(version)` if matched (version may be None)
#[cfg(test)]
fn match_cookies(
    cookies: &std::collections::HashMap<String, String>,
    cookie_patterns: &std::collections::HashMap<String, String>,
) -> Option<Option<String>> {
    for (cookie_name, pattern) in cookie_patterns {
        // Check if cookie_name contains wildcard (*)
        if cookie_name.contains('*') {
            // Convert wildcard pattern to regex (e.g., _ga_* -> ^_ga_.*$)
            let wildcard_pattern = cookie_name.replace('*', ".*");
            let cookie_regex = match regex::Regex::new(&format!("^{}$", wildcard_pattern)) {
                Ok(re) => re,
                Err(_) => continue, // Invalid regex, skip this cookie pattern
            };

            // Check all cookies for a match
            for (actual_cookie_name, cookie_value) in cookies.iter() {
                if cookie_regex.is_match(actual_cookie_name) {
                    if pattern.is_empty() {
                        log::debug!(
                            "Technology matched via wildcard cookie: {} matches pattern '{}'",
                            actual_cookie_name,
                            cookie_name
                        );
                        return Some(None);
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
                        return Some(result.version);
                    }
                }
            }
        } else {
            // Exact match (no wildcard)
            if let Some(cookie_value) = cookies.get(cookie_name) {
                if pattern.is_empty() {
                    return Some(None);
                }
                let result = matches_pattern(pattern, cookie_value);
                if result.matched {
                    log::debug!(
                        "Technology matched via cookie: {}='{}' matched pattern '{}'",
                        cookie_name,
                        cookie_value,
                        pattern
                    );
                    return Some(result.version);
                }
            }
        }
    }

    None
}

/// Matches technology HTML patterns against HTML text.
///
/// Returns match status and version if found. If a version is found, it should be returned immediately.
/// If no version is found but a match occurs, the caller should continue checking other patterns.
///
/// # Arguments
///
/// * `html_text` - HTML text content
/// * `html_patterns` - Technology HTML patterns
///
/// # Returns
///
/// `(matched: bool, version: Option<String>)` - Match status and optional version
#[cfg(test)]
fn match_html(html_text: &str, html_patterns: &[String]) -> (bool, Option<String>) {
    let mut matched = false;

    for pattern in html_patterns {
        let result = matches_pattern(pattern, html_text);
        if result.matched {
            matched = true;
            log::debug!(
                "Technology matched via HTML pattern: '{}' matched in HTML text (version: {:?})",
                pattern,
                result.version
            );
            // If we get a version from HTML pattern, we can return early
            if result.version.is_some() {
                return (true, result.version);
            }
            // Otherwise, continue checking other patterns for version
            // Don't break - check all HTML patterns first, then move to script/meta
            log::debug!(
                "HTML pattern matched without version, will continue checking script/meta patterns for version"
            );
        }
    }

    (matched, None)
}

/// Matches technology script source patterns against script URLs.
///
/// Returns match status and version if found. wappalyzergo iterates through scripts first,
/// then patterns, and takes the first version found.
///
/// # Arguments
///
/// * `script_sources` - Script source URLs
/// * `script_patterns` - Technology script patterns
///
/// # Returns
///
/// `(matched: bool, version: Option<String>)` - Match status and optional version
#[cfg(test)]
fn match_scripts(script_sources: &[String], script_patterns: &[String]) -> (bool, Option<String>) {
    let mut matched_version: Option<String> = None;
    let mut has_match = false;

    // Iterate through scripts first (matching wappalyzergo's behavior)
    for script_src in script_sources {
        // For each script, check all patterns and take the first version found
        for pattern in script_patterns {
            let result = matches_pattern(pattern, script_src);

            if result.matched {
                has_match = true;
                log::debug!(
                    "Technology matched via script src: pattern '{}' matched '{}' (version: {:?})",
                    pattern,
                    script_src,
                    result.version
                );
                // wappalyzergo behavior: take the first version found (from first script that matches)
                // Once we have a version from this script, we can stop checking other patterns for this script
                if matched_version.is_none() && result.version.is_some() {
                    matched_version = result.version.clone();
                }
                // If we already have a version, we can break (first version wins)
                if matched_version.is_some() {
                    break; // Found version from this script, move to next script
                }
            }
        }
        // If we found a match with a version, we can return early (first version wins)
        if has_match && matched_version.is_some() {
            break; // Found first version, stop checking other scripts
        }
    }

    (has_match, matched_version)
}

/// Matches technology meta tag patterns against meta tags.
///
/// Returns match status and version if found. If already matched via other patterns,
/// this function can still provide a version.
///
/// # Arguments
///
/// * `meta_tags` - HTML meta tags (key format: "prefix:name")
/// * `meta_patterns` - Technology meta patterns (meta_key -> patterns)
///
/// # Returns
///
/// `Option<Option<String>>` - `None` if no match, `Some(version)` if matched (version may be None)
#[cfg(test)]
fn match_meta(
    meta_tags: &std::collections::HashMap<String, Vec<String>>,
    meta_patterns: &std::collections::HashMap<String, Vec<String>>,
) -> Option<Option<String>> {
    for (meta_key, patterns) in meta_patterns {
        let result = check_meta_patterns(meta_key, patterns, meta_tags);
        if result.matched {
            log::debug!(
                "Technology matched via meta tag: {} (version: {:?})",
                meta_key,
                result.version
            );
            return Some(result.version);
        }
    }

    None
}

/// Matches technology URL patterns against the URL.
///
/// # Arguments
///
/// * `url` - The URL being checked
/// * `url_patterns` - Technology URL patterns
///
/// # Returns
///
/// `Option<Option<String>>` - `None` if no match, `Some(version)` if matched (version may be None)
#[cfg(test)]
fn match_url(url: &str, url_patterns: &[String]) -> Option<Option<String>> {
    for url_pattern in url_patterns {
        let result = matches_pattern(url_pattern, url);
        if result.matched {
            return Some(result.version);
        }
    }

    None
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
///
/// # Note
/// This function is currently only used in tests. The main detection flow uses
/// `check_headers`, `check_cookies`, and `check_body` instead.
#[cfg(test)]
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
    let (header_matched, header_version) = match_headers(params.headers, &params.tech.headers);

    // If we found a version from header, return early
    if header_matched && header_version.is_some() {
        return TechnologyMatchResult {
            matched: true,
            version: header_version,
        };
    }

    // Match cookies (cookie_name is already normalized to lowercase in ruleset)
    // wappalyzergo supports wildcard cookie names (e.g., _ga_* matches _ga_123456)
    if let Some(cookie_version) = match_cookies(params.cookies, &params.tech.cookies) {
        return TechnologyMatchResult {
            matched: true,
            version: cookie_version,
        };
    }

    // Match HTML patterns (wappalyzergo checks HTML patterns first in body, before scriptSrc and meta)
    // This is because checkBody() calls matchString(bodyString, htmlPart) before tokenizing
    // However, if HTML pattern matches without a version, we should continue checking other patterns
    // (script, meta) to find a version, as wappalyzergo takes the first version found across all patterns
    let (html_matched, html_version) = match_html(params.html_text, &params.tech.html);

    // If we get a version from HTML pattern, return early
    if html_matched && html_version.is_some() {
        return TechnologyMatchResult {
            matched: true,
            version: html_version,
        };
    }

    // Match script sources (wappalyzergo checks scriptSrc during HTML tokenization, after HTML patterns)
    // wappalyzergo iterates through scripts first, then patterns, and takes the first version found
    // This ensures that if multiple scripts match, we use the version from the first script (in script order)
    // wappalyzergo checks ALL patterns (both regex and simple substring), not just regex ones
    let (has_match, script_version) = match_scripts(params.script_sources, &params.tech.script);

    // If we found a version from script patterns, return it
    if has_match && script_version.is_some() {
        return TechnologyMatchResult {
            matched: true,
            version: script_version,
        };
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

    if let Some(meta_version) = match_meta(params.meta_tags, &params.tech.meta) {
        // If we already matched via header/HTML/script, use that match but take version from meta
        if header_matched || html_matched || has_match {
            log::debug!(
                "Already matched via header/HTML/script, using version from meta: {:?}",
                meta_version
            );
            return TechnologyMatchResult {
                matched: true,
                version: meta_version, // Use version from meta (first version found)
            };
        }
        // Otherwise, this is the first match
        return TechnologyMatchResult {
            matched: true,
            version: meta_version,
        };
    }

    // If we matched via header/HTML/script but found no version in meta, return match without version
    if header_matched || html_matched || has_match {
        return TechnologyMatchResult {
            matched: true,
            version: None,
        };
    }

    // Match URL patterns (can be multiple patterns)
    if let Some(url_version) = match_url(params.url, &params.tech.url) {
        return TechnologyMatchResult {
            matched: true,
            version: url_version,
        };
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
    use std::collections::HashMap;

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
        let mut script_tag_ids = HashSet::new();
        script_tag_ids.insert("__NEXT_DATA__".to_string());
        assert!(!can_technology_match(
            &tech,
            true,
            true,
            true,
            true,
            &script_tag_ids
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

        let result = apply_technology_exclusions(&detected, &ruleset);
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

        let result = apply_technology_exclusions(&detected, &ruleset);
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

        let result = apply_technology_exclusions(&detected, &ruleset);
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

        let result = apply_technology_exclusions(&detected, &ruleset);
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
        let result = apply_technology_exclusions(&detected, &ruleset);
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

        let result = apply_technology_exclusions(&detected, &ruleset);
        // TechB should be excluded by TechA (even though TechB is not in ruleset)
        // The exclusion check uses .unwrap_or(false), so missing tech = no exclusion
        // But TechA.excludes contains "TechB", so TechB should be excluded
        assert!(result.contains("TechA"));
        // TechB should be excluded because TechA.excludes contains "TechB"
        assert!(!result.contains("TechB"));
    }

    #[tokio::test]
    async fn test_matches_technology_all_empty_patterns() {
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
        let result = matches_technology(params).await;
        assert!(
            !result.matched,
            "Technology with all empty patterns should not match"
        );
    }

    #[tokio::test]
    async fn test_matches_technology_js_empty_but_has_js_field() {
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

        let result = matches_technology(params).await;
        // Should not match because script_tag_ids doesn't contain "__NEXT_DATA__"
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_matches_technology_cookie_empty_pattern() {
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

        let result = matches_technology(params).await;
        // Empty pattern should match any cookie value
        assert!(result.matched);
    }

    #[tokio::test]
    async fn test_matches_technology_header_case_sensitivity() {
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

        let result = matches_technology(params).await;
        // Pattern matching is case-insensitive now (to match wappalyzergo), so "nginx" will match "NGINX"
        // Headers are normalized to lowercase, so this should match
        assert!(
            result.matched,
            "Case-insensitive pattern 'nginx' should match 'NGINX' (normalized)"
        );
    }

    #[tokio::test]
    async fn test_matches_technology_url_pattern_special_chars() {
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

        let result = matches_technology(params).await;
        // Escaped dot should match literal dot
        assert!(result.matched);
    }

    #[tokio::test]
    async fn test_matches_technology_script_source_special_chars() {
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

        let result = matches_technology(params).await;
        // Should match script sources containing "jquery"
        assert!(result.matched);
    }

    #[tokio::test]
    async fn test_matches_technology_html_pattern_very_long_text() {
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

        let result = matches_technology(params).await;
        // Should handle very long text without panicking
        assert!(
            !result.matched,
            "Should not match 'WordPress' in long text without that word"
        );
    }

    #[tokio::test]
    async fn test_matches_technology_script_version_selection_order() {
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

        let result = matches_technology(params).await;

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

    #[tokio::test]
    async fn test_matches_technology_google_analytics_via_script() {
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

        let result = matches_technology(params).await;

        assert!(
            result.matched,
            "Should match Google Analytics via scriptSrc pattern"
        );
    }

    // Tests for extracted helper functions

    #[test]
    fn test_match_headers_empty_pattern() {
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "nginx/1.18.0".to_string());

        let mut header_patterns = HashMap::new();
        header_patterns.insert("server".to_string(), String::new()); // Empty pattern

        let (matched, version) = match_headers(&headers, &header_patterns);
        assert!(matched, "Empty pattern should match when header exists");
        assert_eq!(version, None, "Empty pattern should not extract version");
    }

    #[test]
    fn test_match_headers_with_version() {
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "nginx/1.18.0".to_string());

        let mut header_patterns = HashMap::new();
        header_patterns.insert(
            "server".to_string(),
            r"nginx/(\d+\.\d+)\;version:\1".to_string(),
        );

        let (matched, version) = match_headers(&headers, &header_patterns);
        assert!(matched, "Should match nginx pattern");
        assert_eq!(version, Some("1.18".to_string()), "Should extract version");
    }

    #[test]
    fn test_match_headers_no_match() {
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "apache/2.4".to_string());

        let mut header_patterns = HashMap::new();
        header_patterns.insert("server".to_string(), "nginx".to_string());

        let (matched, version) = match_headers(&headers, &header_patterns);
        assert!(!matched, "Should not match different server");
        assert_eq!(version, None);
    }

    #[test]
    fn test_match_cookies_exact_match() {
        let mut cookies = HashMap::new();
        cookies.insert("session".to_string(), "abc123".to_string());

        let mut cookie_patterns = HashMap::new();
        cookie_patterns.insert("session".to_string(), ".*".to_string());

        let result = match_cookies(&cookies, &cookie_patterns);
        assert!(result.is_some(), "Should match cookie");
        assert_eq!(result.unwrap(), None, "Pattern should match but no version");
    }

    #[test]
    fn test_match_cookies_wildcard() {
        let mut cookies = HashMap::new();
        cookies.insert("_ga_123456".to_string(), "value".to_string());

        let mut cookie_patterns = HashMap::new();
        cookie_patterns.insert("_ga_*".to_string(), String::new()); // Wildcard pattern

        let result = match_cookies(&cookies, &cookie_patterns);
        assert!(result.is_some(), "Should match wildcard cookie");
    }

    #[test]
    fn test_match_cookies_no_match() {
        let mut cookies = HashMap::new();
        cookies.insert("other".to_string(), "value".to_string());

        let mut cookie_patterns = HashMap::new();
        cookie_patterns.insert("session".to_string(), ".*".to_string());

        let result = match_cookies(&cookies, &cookie_patterns);
        assert!(result.is_none(), "Should not match different cookie");
    }

    #[test]
    fn test_match_html_simple() {
        let html_text = "<html><body>Powered by WordPress</body></html>";
        let html_patterns = vec!["WordPress".to_string()];

        let (matched, version) = match_html(html_text, &html_patterns);
        assert!(matched, "Should match WordPress in HTML");
        assert_eq!(version, None, "Simple pattern should not extract version");
    }

    #[test]
    fn test_match_html_with_version() {
        let html_text = "<html><body>jQuery 3.6.0</body></html>";
        let html_patterns = vec![r"jQuery (\d+\.\d+\.\d+)\;version:\1".to_string()];

        let (matched, version) = match_html(html_text, &html_patterns);
        assert!(matched, "Should match jQuery pattern");
        assert_eq!(version, Some("3.6.0".to_string()), "Should extract version");
    }

    #[test]
    fn test_match_html_no_match() {
        let html_text = "<html><body>Some content</body></html>";
        let html_patterns = vec!["WordPress".to_string()];

        let (matched, version) = match_html(html_text, &html_patterns);
        assert!(!matched, "Should not match when pattern not found");
        assert_eq!(version, None);
    }

    #[test]
    fn test_match_scripts_simple() {
        let script_sources = vec!["https://example.com/jquery.min.js".to_string()];
        let script_patterns = vec!["jquery".to_string()];

        let (matched, version) = match_scripts(&script_sources, &script_patterns);
        assert!(matched, "Should match jQuery script");
        assert_eq!(version, None, "Simple pattern should not extract version");
    }

    #[test]
    fn test_match_scripts_with_version() {
        let script_sources = vec!["https://code.jquery.com/jquery-3.6.0.min.js".to_string()];
        let script_patterns = vec![r"jquery-(\d+\.\d+\.\d+)\;version:\1".to_string()];

        let (matched, version) = match_scripts(&script_sources, &script_patterns);
        assert!(matched, "Should match jQuery script with version");
        assert_eq!(version, Some("3.6.0".to_string()), "Should extract version");
    }

    #[test]
    fn test_match_scripts_version_from_first_script() {
        // Test that version is taken from first matching script
        let script_sources = vec![
            "https://code.jquery.com/jquery-3.2.1.min.js".to_string(),
            "https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js".to_string(),
        ];
        let script_patterns = vec![
            r"/(\d+\.\d+\.\d+)/jquery[/.-]\;version:\1".to_string(),
            r"jquery-(\d+\.\d+\.\d+)\;version:\1".to_string(),
        ];

        let (matched, version) = match_scripts(&script_sources, &script_patterns);
        assert!(matched, "Should match jQuery");
        // Should get version from first script (3.2.1), not second (3.3.1)
        assert_eq!(
            version,
            Some("3.2.1".to_string()),
            "Should take version from first script"
        );
    }

    #[test]
    fn test_match_meta_simple() {
        let mut meta_tags = HashMap::new();
        meta_tags.insert("name:generator".to_string(), vec!["WordPress".to_string()]);

        let mut meta_patterns = HashMap::new();
        meta_patterns.insert("generator".to_string(), vec!["WordPress".to_string()]);

        let result = match_meta(&meta_tags, &meta_patterns);
        assert!(result.is_some(), "Should match meta tag");
        assert_eq!(
            result.unwrap(),
            None,
            "Simple pattern should not extract version"
        );
    }

    #[test]
    fn test_match_meta_with_version() {
        let mut meta_tags = HashMap::new();
        meta_tags.insert(
            "name:generator".to_string(),
            vec!["WordPress 6.8.3".to_string()],
        );

        let mut meta_patterns = HashMap::new();
        meta_patterns.insert(
            "generator".to_string(),
            vec![r"^wordpress(?: ([\d.]+))?\;version:\1".to_string()],
        );

        let result = match_meta(&meta_tags, &meta_patterns);
        assert!(result.is_some(), "Should match meta tag");
        assert_eq!(
            result.unwrap(),
            Some("6.8.3".to_string()),
            "Should extract version from meta"
        );
    }

    #[test]
    fn test_match_meta_no_match() {
        let mut meta_tags = HashMap::new();
        meta_tags.insert("name:generator".to_string(), vec!["Drupal".to_string()]);

        let mut meta_patterns = HashMap::new();
        meta_patterns.insert("generator".to_string(), vec!["WordPress".to_string()]);

        let result = match_meta(&meta_tags, &meta_patterns);
        assert!(result.is_none(), "Should not match different generator");
    }

    #[test]
    fn test_match_url_simple() {
        let url = "https://example.com/page";
        let url_patterns = vec!["example\\.com".to_string()];

        let result = match_url(url, &url_patterns);
        assert!(result.is_some(), "Should match URL pattern");
        assert_eq!(
            result.unwrap(),
            None,
            "Simple pattern should not extract version"
        );
    }

    #[test]
    fn test_match_url_with_version() {
        let url = "https://example.com/v1.2.3/api";
        let url_patterns = vec![r"/v(\d+\.\d+\.\d+)/\;version:\1".to_string()];

        let result = match_url(url, &url_patterns);
        assert!(result.is_some(), "Should match URL pattern");
        assert_eq!(
            result.unwrap(),
            Some("1.2.3".to_string()),
            "Should extract version from URL"
        );
    }

    #[test]
    fn test_match_url_no_match() {
        let url = "https://other.com/page";
        let url_patterns = vec!["example\\.com".to_string()];

        let result = match_url(url, &url_patterns);
        assert!(result.is_none(), "Should not match different domain");
    }

    #[tokio::test]
    async fn test_matches_technology_wordpress_version_from_meta_after_html_match() {
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
        meta_tags.insert(
            "name:generator".to_string(),
            vec!["WordPress 6.8.3".to_string()],
        );

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

        let result = matches_technology(params).await;

        assert!(result.matched, "Should match WordPress");
        assert_eq!(
            result.version,
            Some("6.8.3".to_string()),
            "Should extract version 6.8.3 from meta generator tag even when HTML pattern matches first"
        );
    }
}
