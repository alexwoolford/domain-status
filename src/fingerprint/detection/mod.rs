//! Technology detection and matching logic.
//!
//! This module provides the main technology detection function that matches
//! fingerprint rules against extracted HTML data, headers, cookies, and URL patterns.

mod matching;
mod utils;

use anyhow::Result;
use reqwest::header::HeaderMap;
use std::collections::{HashMap, HashSet};

use crate::fingerprint::ruleset::get_ruleset;

use matching::{apply_technology_exclusions, can_technology_match, matches_technology};
use utils::{extract_cookies_from_headers, normalize_headers_to_map};

/// Detects technologies from extracted HTML data, headers, and URL.
///
/// This is a simplified matcher that only uses single-request fields:
/// - Headers
/// - Cookies (from SET_COOKIE and Cookie headers)
/// - Meta tags (name, property, http-equiv)
/// - Script sources
/// - Script content (inline scripts for js field detection)
/// - HTML text patterns
/// - URL patterns
/// - JavaScript object properties (js field)
///
/// # Arguments
///
/// * `meta_tags` - Map of meta tag name/property/http-equiv -> content
/// * `script_sources` - Vector of script src URLs
/// * `script_content` - Inline script content for js field detection
/// * `html_text` - HTML text content (first 50KB)
/// * `headers` - HTTP response headers
/// * `url` - The URL being analyzed
/// * `script_tag_ids` - Script tag IDs found in HTML (for __NEXT_DATA__ etc.)
pub async fn detect_technologies(
    meta_tags: &HashMap<String, String>,
    script_sources: &[String],
    script_content: &str,
    html_text: &str,
    headers: &HeaderMap,
    url: &str,
    script_tag_ids: &HashSet<String>,
) -> Result<HashSet<String>> {
    // Get the ruleset
    let ruleset = get_ruleset()
        .await
        .ok_or_else(|| anyhow::anyhow!("Ruleset not initialized. Call init_ruleset() first"))?;

    // Extract and normalize cookies and headers
    let cookies = extract_cookies_from_headers(headers);
    let header_map = normalize_headers_to_map(headers);

    log::debug!(
        "Technology detection for {}: {} inline script bytes, {} external script sources (URLs only, not fetched)",
        url,
        script_content.len(),
        script_sources.len()
    );

    // Pre-filter technologies for early exit optimization
    let has_cookies = !cookies.is_empty();
    let has_headers = !header_map.is_empty();
    let has_meta = !meta_tags.is_empty();
    let has_scripts = !script_sources.is_empty();

    // Note: We only use inline script content (matches WappalyzerGo's behavior)
    // WappalyzerGo does NOT fetch external scripts - it only analyzes the initial HTML
    // JS property matching is disabled - we only match via script tag IDs (WappalyzerGo behavior)
    // Script source patterns match against URLs from HTML, not fetched content

    // Match each technology (now using batch JS results)
    // Pre-allocate HashSet with estimated capacity (most sites have 5-20 technologies)
    let mut detected = HashSet::with_capacity(32);
    let mut checked_count = 0;
    let mut skipped_count = 0;
    for (tech_name, tech) in &ruleset.technologies {
        // Early exit: skip technologies that can't match
        if !can_technology_match(
            tech,
            has_cookies,
            has_headers,
            has_meta,
            has_scripts,
            script_tag_ids,
        ) {
            skipped_count += 1;
            continue;
        }
        checked_count += 1;

        // Log when checking high-value technologies for debugging
        let high_value_techs = [
            "jQuery",
            "React",
            "Google Analytics",
            "Salesforce",
            "Adobe DTM",
            "Omniture",
            "Brightcove",
        ];
        if high_value_techs.contains(&tech_name.as_str()) {
            log::debug!(
                "Checking {}: {} headers, {} cookies, {} meta, {} script patterns, {} html patterns, {} js properties",
                tech_name,
                tech.headers.len(),
                tech.cookies.len(),
                tech.meta.len(),
                tech.script.len(),
                tech.html.len(),
                tech.js.len()
            );
        }

        if matches_technology(matching::TechnologyMatchParams {
            tech,
            headers: &header_map,
            cookies: &cookies,
            meta_tags,
            script_sources,
            html_text,
            url,
            script_tag_ids,
        })
        .await
        {
            detected.insert(tech_name.clone());
            log::debug!("Detected technology: {}", tech_name);

            // Add implied technologies
            for implied in &tech.implies {
                detected.insert(implied.clone());
                log::debug!("Added implied technology: {} (from {})", implied, tech_name);
            }
        }
    }

    // Remove excluded technologies
    let detected_count = detected.len();
    let final_detected = apply_technology_exclusions(detected, &ruleset);
    let final_count = final_detected.len();

    log::debug!(
        "Technology detection summary for {}: checked {} technologies ({} skipped by early exit), {} detected ({} after exclusions)",
        url,
        checked_count,
        skipped_count,
        detected_count,
        final_count
    );

    Ok(final_detected)
}

/// Gets the category name for a technology, if available.
///
/// Returns the category name from the first category ID in the technology's `cats` array.
/// Returns `None` if the technology is not found, has no categories, or the category ID is not in the ruleset.
pub async fn get_technology_category(tech_name: &str) -> Option<String> {
    let ruleset = get_ruleset().await?;

    let tech = ruleset.technologies.get(tech_name)?;
    let first_cat_id = tech.cats.first()?;
    ruleset.categories.get(first_cat_id).cloned()
}
