//! Technology detection and matching logic.
//!
//! This module provides the main technology detection function that matches
//! fingerprint rules against extracted HTML data, headers, cookies, and URL patterns.

mod matching;
mod utils;

use anyhow::Result;
use reqwest::header::HeaderMap;
use std::collections::{HashMap, HashSet};

use crate::fingerprint::javascript::fetch_and_combine_scripts;
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

    // Fetch external scripts and combine with inline scripts for JavaScript execution
    // This matches the behavior of the Golang Wappalyzer tool
    let all_script_content = fetch_and_combine_scripts(script_sources, script_content, url).await;

    log::debug!(
        "Technology detection for {}: {} inline script bytes, {} external script sources, {} total script bytes",
        url,
        script_content.len(),
        script_sources.len(),
        all_script_content.len()
    );

    // Pre-filter technologies for early exit optimization
    let has_cookies = !cookies.is_empty();
    let has_headers = !header_map.is_empty();
    let has_meta = !meta_tags.is_empty();
    let has_scripts = !script_sources.is_empty();
    let has_script_content = !all_script_content.trim().is_empty();

    // Match each technology
    let mut detected = HashSet::new();
    for (tech_name, tech) in &ruleset.technologies {
        // Early exit: skip technologies that can't match
        if !can_technology_match(
            tech,
            has_cookies,
            has_headers,
            has_meta,
            has_scripts,
            has_script_content,
            script_tag_ids,
        ) {
            continue;
        }

        // Log when checking New Relic for debugging
        if tech_name == "New Relic" {
            log::debug!(
                "Checking New Relic technology with {} JS properties",
                tech.js.len()
            );
        }

        if matches_technology(
            tech,
            &header_map,
            &cookies,
            meta_tags,
            script_sources,
            &all_script_content,
            html_text,
            url,
            script_tag_ids,
        )
        .await
        {
            detected.insert(tech_name.clone());

            // Add implied technologies
            for implied in &tech.implies {
                detected.insert(implied.clone());
            }
        }
    }

    // Remove excluded technologies
    let final_detected = apply_technology_exclusions(detected, &ruleset);

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

