//! Technology detection and matching logic.
//!
//! This module provides the main technology detection function that matches
//! fingerprint rules against extracted HTML data, headers, cookies, and URL patterns.

mod matching;
mod utils;

use anyhow::Result;
use reqwest::header::HeaderMap;
use std::collections::{HashMap, HashSet};

use crate::fingerprint::javascript::{check_js_properties_batch, fetch_and_combine_scripts};
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

    // Collect all JS properties that need to be checked (for batch execution)
    // This avoids creating a new QuickJS context for each property check
    // Pre-allocate with estimated capacity to reduce reallocations
    let mut js_properties_to_check: Vec<(String, String)> = Vec::with_capacity(64);
    let mut js_property_map: HashMap<String, Vec<String>> = HashMap::with_capacity(32); // property -> list of tech names that need it

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

        // Collect JS properties for this technology
        for (js_property, pattern) in &tech.js {
            // Skip if already in script_tag_ids (fast check, no JS execution needed)
            if script_tag_ids.contains(js_property) {
                continue;
            }

            // Add to batch list if not already present (deduplicate by property+pattern)
            if !js_properties_to_check
                .iter()
                .any(|(p, pat)| p == js_property && pat == pattern)
            {
                js_properties_to_check.push((js_property.clone(), pattern.clone()));
            }

            // Track which technologies need this property
            js_property_map
                .entry(js_property.clone())
                .or_default()
                .push(tech_name.clone());
        }
    }

    // Execute batch JS property check (if we have script content and properties to check)
    let js_property_results: HashMap<String, bool> =
        if !all_script_content.trim().is_empty() && !js_properties_to_check.is_empty() {
            log::debug!(
                "Batch checking {} JS properties for {} technologies",
                js_properties_to_check.len(),
                js_property_map.len()
            );

            // Run batch check in spawn_blocking with timeout (same as individual checks)
            let script_content = all_script_content.clone();
            let properties = js_properties_to_check.clone();
            let timeout_duration =
                std::time::Duration::from_millis(crate::config::MAX_JS_EXECUTION_TIME_MS * 3); // 3x timeout for batch

            let handle = tokio::task::spawn_blocking(move || {
                check_js_properties_batch(&script_content, &properties)
            });

            match tokio::time::timeout(timeout_duration, handle).await {
                Ok(Ok(results)) => results.unwrap_or_default(),
                Ok(Err(e)) => {
                    log::debug!("Batch JS property check failed: {e}");
                    HashMap::new()
                }
                Err(_) => {
                    log::debug!(
                        "Batch JS property check timed out after {}ms",
                        timeout_duration.as_millis()
                    );
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };

    // Match each technology (now using batch JS results)
    // Pre-allocate HashSet with estimated capacity (most sites have 5-20 technologies)
    let mut detected = HashSet::with_capacity(32);
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
            &js_property_results, // Pass batch results
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
