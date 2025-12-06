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
pub(crate) fn apply_technology_exclusions(
    detected: HashSet<String>,
    ruleset: &FingerprintRuleset,
) -> HashSet<String> {
    let mut final_detected = HashSet::new();
    for tech_name in &detected {
        let tech = ruleset.technologies.get(tech_name);
        let is_excluded = tech
            .map(|t| t.excludes.iter().any(|ex| detected.contains(ex)))
            .unwrap_or(false);

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
