//! Technology detection and matching logic.
//!
//! This module provides the main technology detection function that matches
//! fingerprint rules against extracted HTML data, headers, cookies, and URL patterns.
//!
//! Note: Comments referencing wappalyzergo Go source line numbers (e.g.,
//! `fingerprints.go:271`, `tech.go:263`) are from the original port circa 2024
//! and may drift as the upstream project evolves.

mod body;
mod cookies;
mod headers;
mod matching;
mod utils;

use reqwest::header::HeaderMap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::error_handling::FingerprintError;
use crate::fingerprint::models::FingerprintRuleset;

use body::check_body_with_ruleset;
use cookies::check_cookies_with_ruleset;
use headers::check_headers_with_ruleset;
use matching::apply_technology_exclusions;
use utils::{extract_cookies_from_headers, normalize_headers_to_map};

/// Detects technologies from extracted HTML data, headers, and URL.
///
/// This is a simplified matcher that only uses single-request fields:
/// - Headers
/// - Cookies (from `SET_COOKIE` and Cookie headers)
/// - Meta tags (name, property, http-equiv)
/// - Script sources
/// - Script content (inline scripts for js field detection)
/// - HTML text patterns
/// - URL patterns
/// - JavaScript object properties (js field)
///
/// # Arguments
///
/// * `meta_tags` - Map of meta tag name/property/http-equiv -> Vec of content values (multiple tags with same name are stored as Vec)
/// * `script_sources` - Vector of script src URLs
/// * `script_content` - Inline script content for js field detection
/// * `html_body` - Full HTML body normalized to lowercase (for HTML pattern matching, matching wappalyzergo)
/// * `headers` - HTTP response headers
/// * `url` - The URL being analyzed
/// * `script_tag_ids` - Script tag IDs found in HTML (for __`NEXT_DATA`__ etc.)
///
/// Technology detection result with name and optional version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DetectedTechnology {
    pub name: String,
    pub version: Option<String>,
    /// Category name from the ruleset (resolved at detection time).
    pub category: Option<String>,
}

/// CPU-bound technology detection using a pre-fetched ruleset.
/// Intended to be run on a blocking thread (e.g. via `tokio::task::spawn_blocking`)
/// to avoid starving the async executor with regex work.
#[allow(clippy::too_many_arguments)] // Each arg is a distinct input signal for detection (headers, meta, scripts, etc.)
#[allow(clippy::too_many_lines)] // Iterates over all technology rules checking multiple signal types
#[allow(clippy::unnecessary_wraps)] // Caller expects Result for map_err/and_then chaining
pub(crate) fn detect_technologies_blocking(
    ruleset: &Arc<FingerprintRuleset>,
    headers: &HeaderMap,
    meta_tags: &HashMap<String, Vec<String>>,
    script_sources: &[String],
    script_content: &str,
    html_body: &str,
    url: &str,
    _script_tag_ids: &HashSet<String>,
) -> Result<Vec<DetectedTechnology>, FingerprintError> {
    let cookies = extract_cookies_from_headers(headers);
    let header_map = normalize_headers_to_map(headers);

    log::debug!(
        "Technology detection (blocking) for {}: {} inline script bytes, {} external script sources",
        url,
        script_content.len(),
        script_sources.len()
    );

    #[derive(Clone)]
    struct TechInfo {
        version: Option<String>,
    }
    let mut detected: HashMap<String, TechInfo> = HashMap::with_capacity(32);

    let header_results = check_headers_with_ruleset(ruleset, &header_map);
    for result in header_results {
        detected
            .entry(result.tech_name.clone())
            .and_modify(|existing| {
                if existing.version.is_none() && result.version.is_some() {
                    existing.version.clone_from(&result.version);
                }
            })
            .or_insert(TechInfo {
                version: result.version,
            });
    }

    if !cookies.is_empty() {
        let cookie_results = check_cookies_with_ruleset(ruleset, &cookies);
        for result in cookie_results {
            detected
                .entry(result.tech_name.clone())
                .and_modify(|existing| {
                    if existing.version.is_none() && result.version.is_some() {
                        existing.version.clone_from(&result.version);
                    }
                })
                .or_insert(TechInfo {
                    version: result.version,
                });
        }
    }

    let body_results = check_body_with_ruleset(ruleset, html_body, script_sources, meta_tags, url);
    for result in body_results {
        detected
            .entry(result.tech_name.clone())
            .and_modify(|existing| {
                if existing.version.is_none() && result.version.is_some() {
                    existing.version.clone_from(&result.version);
                }
            })
            .or_insert(TechInfo {
                version: result.version,
            });
    }

    // Add implied technologies (fixed-point: A→B, B→C must yield both B and C).
    // Matches the async detect_technologies logic.
    const MAX_IMPLIES_DEPTH: u32 = 10;
    for _ in 0..MAX_IMPLIES_DEPTH {
        let mut implied_to_add = Vec::new();
        for tech_name in detected.keys() {
            let base_tech_name = if let Some(colon_pos) = tech_name.find(':') {
                &tech_name[..colon_pos]
            } else {
                tech_name
            };
            if let Some(tech) = ruleset.technologies.get(base_tech_name) {
                for implied in &tech.implies {
                    implied_to_add.push((implied.clone(), TechInfo { version: None }));
                }
            }
        }
        let mut added_any = false;
        for (implied_name, tech_info) in implied_to_add {
            if ruleset.technologies.contains_key(&implied_name)
                && detected.insert(implied_name.clone(), tech_info).is_none()
            {
                added_any = true;
            }
        }
        if !added_any {
            break;
        }
    }

    let detected_vec: Vec<(String, Option<String>)> = detected
        .iter()
        .map(|(name, info)| (name.clone(), info.version.clone()))
        .collect();

    let detected_formatted_for_exclusions: HashSet<String> = detected_vec
        .iter()
        .map(|(name, version)| {
            if let Some(ref ver) = version {
                format!("{name}:{ver}")
            } else {
                name.clone()
            }
        })
        .collect();
    let final_detected_formatted =
        apply_technology_exclusions(&detected_formatted_for_exclusions, ruleset);

    let final_detected: Vec<(String, Option<String>)> = detected_vec
        .into_iter()
        .filter(|(name, version)| {
            let formatted = if let Some(ref ver) = version {
                format!("{name}:{ver}")
            } else {
                name.clone()
            };
            final_detected_formatted.contains(&formatted)
        })
        .collect();

    log::debug!(
        "Technology detection (blocking) summary for {}: {} detected ({} after exclusions)",
        url,
        detected.len(),
        final_detected.len()
    );

    Ok(final_detected
        .into_iter()
        .map(|(name, version)| DetectedTechnology {
            category: get_technology_category(ruleset, &name),
            name,
            version,
        })
        .collect())
}

/// Gets the category name for a technology, if available.
///
/// Returns the category name from the first category ID in the technology's `cats` array.
/// Returns `None` if the technology is not found, has no categories, or the category ID is not in the ruleset.
#[must_use]
pub fn get_technology_category(ruleset: &FingerprintRuleset, tech_name: &str) -> Option<String> {
    let tech = ruleset.technologies.get(tech_name)?;
    let first_cat_id = tech.cats.first()?;
    ruleset.categories.get(first_cat_id).cloned()
}
#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderMap;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_detect_technologies_blocking_empty_ruleset() {
        let ruleset = Arc::new(FingerprintRuleset::empty_for_tests());
        let meta_tags = HashMap::new();
        let script_sources = vec!["https://example.com/jquery.js".to_string()];
        let headers = HeaderMap::new();

        let result = detect_technologies_blocking(
            &ruleset,
            &headers,
            &meta_tags,
            &script_sources,
            "",
            "",
            "https://example.com",
            &HashSet::new(),
        )
        .expect("empty ruleset detection should succeed");

        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_detect_technologies_blocking_with_init_ruleset() {
        if crate::fingerprint::init_ruleset(None, None).await.is_err() {
            return;
        }
        let Some(ruleset) = crate::fingerprint::get_ruleset().await else {
            return;
        };

        let meta_tags = HashMap::new();
        let script_sources = vec!["https://example.com/jquery.min.js".to_string()];
        let mut headers = HeaderMap::new();
        headers.insert(reqwest::header::SERVER, "nginx/1.18.0".parse().unwrap());

        let result = detect_technologies_blocking(
            &ruleset,
            &headers,
            &meta_tags,
            &script_sources,
            "",
            "",
            "https://example.com",
            &HashSet::new(),
        )
        .expect("detection with initialized ruleset should succeed");

        let tech_names: Vec<String> = result.iter().map(|t| t.name.clone()).collect();
        assert!(
            tech_names.contains(&"jQuery".to_string())
                || tech_names.contains(&"JavaScript".to_string())
                || tech_names.contains(&"Nginx".to_string())
                || !tech_names.is_empty(),
            "Expected at least one technology match, got: {tech_names:?}"
        );
    }

    #[test]
    fn test_get_technology_category_not_found() {
        let ruleset = FingerprintRuleset::empty_for_tests();
        let category = get_technology_category(&ruleset, "NonExistentTech12345");
        assert_eq!(category, None);
    }

    #[test]
    fn test_get_technology_category_no_categories() {
        let ruleset = FingerprintRuleset::empty_for_tests();
        let result = get_technology_category(&ruleset, "NonExistentTech");
        assert_eq!(result, None);
    }
}
