//! Technology matching logic.
//!
//! This module provides functions to check if technologies match based on
//! their patterns and available data.

use std::collections::{HashMap, HashSet};

use crate::fingerprint::javascript::check_js_property_async;
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
    has_script_content: bool,
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
    // If technology requires JS execution but we have no script content, skip it
    // (unless it can match via script tag IDs)
    if !tech.js.is_empty() && !has_script_content {
        // Check if any JS property could match via script tag IDs
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

/// Checks if a technology matches based on its patterns
#[allow(clippy::too_many_arguments)] // Technology matching requires many parameters
pub(crate) async fn matches_technology(
    tech: &Technology,
    headers: &HashMap<String, String>,
    cookies: &HashMap<String, String>,
    meta_tags: &HashMap<String, String>,
    script_sources: &[String],
    all_script_content: &str, // Combined inline + external scripts for JS execution
    html_text: &str,
    url: &str,
    script_tag_ids: &HashSet<String>, // Script tag IDs found in HTML (for __NEXT_DATA__ etc.)
    js_property_results: &HashMap<String, bool>, // Batch JS property check results
) -> bool {
    // Match headers (header_name is already normalized to lowercase in ruleset)
    for (header_name, pattern) in &tech.headers {
        if let Some(header_value) = headers.get(header_name) {
            if matches_pattern(pattern, header_value) {
                return true;
            }
        }
    }

    // Match cookies (cookie_name is already normalized to lowercase in ruleset)
    for (cookie_name, pattern) in &tech.cookies {
        if let Some(cookie_value) = cookies.get(cookie_name) {
            if pattern.is_empty() || matches_pattern(pattern, cookie_value) {
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
    for (meta_key, patterns) in &tech.meta {
        if check_meta_patterns(meta_key, patterns, meta_tags) {
            return true;
        }
    }

    // Match script sources
    for pattern in &tech.script {
        for script_src in script_sources {
            if matches_pattern(pattern, script_src) {
                return true;
            }
        }
    }

    // Match HTML text
    for pattern in &tech.html {
        if matches_pattern(pattern, html_text) {
            return true;
        }
    }

    // Match URL patterns (can be multiple patterns)
    for url_pattern in &tech.url {
        if matches_pattern(url_pattern, url) {
            return true;
        }
    }

    // Match JavaScript object properties (js field)
    // Use batch results if available, otherwise fall back to individual checks
    // Note: This is the slowest check, so it's done last (after all fast checks)
    if !tech.js.is_empty() {
        log::debug!(
            "Checking {} JS properties for technology ({} bytes of script content)",
            tech.js.len(),
            all_script_content.len()
        );
    }
    for (js_property, pattern) in &tech.js {
        // Special case: Properties that match script tag IDs (like __NEXT_DATA__)
        // The Golang Wappalyzer checks for script tag IDs when the js property matches
        // This is how Next.js detection works - it looks for <script id="__NEXT_DATA__">
        if script_tag_ids.contains(js_property) {
            log::info!("Technology matched via script tag ID '{}'", js_property);
            return true;
        }

        // Check batch results first (much faster)
        // Batch results use composite key (property:pattern)
        let key = format!("{}:{}", js_property, pattern);
        if let Some(&found) = js_property_results.get(&key) {
            if found {
                log::info!(
                    "Technology matched via JS property '{}' (from batch)",
                    js_property
                );
                return true;
            }
            continue; // Property not found in batch, skip to next
        }

        // Fallback to individual check if not in batch results (shouldn't happen, but safety)
        if !all_script_content.trim().is_empty()
            && check_js_property_async(all_script_content, js_property, pattern).await
        {
            log::info!(
                "Technology matched via JS property '{}' (individual check)",
                js_property
            );
            return true;
        }
    }

    false
}
