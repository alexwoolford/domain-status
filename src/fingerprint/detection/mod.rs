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
/// Static matcher using single-request fields only (no JavaScript execution):
/// - Headers
/// - Cookies (from `SET_COOKIE` and Cookie headers)
/// - Meta tags (name, property, http-equiv)
/// - Script sources (`src` URLs)
/// - Script tag IDs (static HTML `id` attributes, e.g. `__NEXT_DATA__`)
/// - HTML text patterns
/// - URL patterns
///
/// Technologies with only runtime `js` object patterns (and no other signals) are not detected.
///
/// # Arguments
///
/// * `meta_tags` - Map of meta tag name/property/http-equiv -> Vec of content values
/// * `script_sources` - Vector of script src URLs
/// * `html_body` - Full HTML body normalized to lowercase
/// * `headers` - HTTP response headers
/// * `url` - The URL being analyzed
/// * `script_tag_ids` - Script tag IDs found in HTML (matched against ruleset `js` keys)
///
/// Technology detection result with name and optional version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DetectedTechnology {
    pub name: String,
    pub version: Option<String>,
    /// Category name from the ruleset (resolved at detection time).
    pub category: Option<String>,
    /// True when this technology was added only via another tech's `implies` list.
    pub is_implied: bool,
}

/// Drops version strings that look like content/git hashes rather than semver.
///
/// Upstream Bootstrap (and similar) patterns often capture hex digests from hashed
/// asset filenames. Those pollute `technology_version` without being useful versions.
#[must_use]
pub(crate) fn sanitize_technology_version(version: Option<String>) -> Option<String> {
    let version = version?;
    let trimmed = version.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Pure hex digests of length >= 7 (common content-hash / git short-hash captures).
    if trimmed.len() >= 7 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(version)
}

/// CPU-bound technology detection using a pre-fetched ruleset.
/// Intended to be run on a blocking thread (e.g. via `tokio::task::spawn_blocking`)
/// to avoid starving the async executor with regex work.
#[allow(clippy::too_many_arguments)] // Distinct input signals for detection
#[allow(clippy::too_many_lines)] // Iterates over all technology rules checking multiple signal types
#[allow(clippy::unnecessary_wraps)] // Caller expects Result for map_err/and_then chaining
pub(crate) fn detect_technologies_blocking(
    ruleset: &Arc<FingerprintRuleset>,
    headers: &HeaderMap,
    meta_tags: &HashMap<String, Vec<String>>,
    script_sources: &[String],
    html_body: &str,
    url: &str,
    script_tag_ids: &HashSet<String>,
) -> Result<Vec<DetectedTechnology>, FingerprintError> {
    let cookies = extract_cookies_from_headers(headers);
    let header_map = normalize_headers_to_map(headers);

    log::debug!(
        "Technology detection (blocking) for {}: {} script tag ids, {} external script sources",
        url,
        script_tag_ids.len(),
        script_sources.len()
    );

    #[derive(Clone)]
    struct TechInfo {
        version: Option<String>,
        is_implied: bool,
    }
    let mut detected: HashMap<String, TechInfo> = HashMap::with_capacity(32);

    let merge_observed =
        |detected: &mut HashMap<String, TechInfo>, tech_name: String, version: Option<String>| {
            let version = sanitize_technology_version(version);
            detected
                .entry(tech_name)
                .and_modify(|existing| {
                    existing.is_implied = false;
                    if existing.version.is_none() && version.is_some() {
                        existing.version.clone_from(&version);
                    }
                })
                .or_insert(TechInfo {
                    version,
                    is_implied: false,
                });
        };

    let header_results = check_headers_with_ruleset(ruleset, &header_map);
    for result in header_results {
        merge_observed(&mut detected, result.tech_name, result.version);
    }

    if !cookies.is_empty() {
        let cookie_results = check_cookies_with_ruleset(ruleset, &cookies);
        for result in cookie_results {
            merge_observed(&mut detected, result.tech_name, result.version);
        }
    }

    let body_results = check_body_with_ruleset(ruleset, html_body, script_sources, meta_tags, url);
    for result in body_results {
        merge_observed(&mut detected, result.tech_name, result.version);
    }

    // Static script-tag ID match against ruleset `js` keys (e.g. id="__NEXT_DATA__").
    // This is HTML attribute matching, not JavaScript execution.
    if !script_tag_ids.is_empty() {
        for (tech_name, tech) in &ruleset.technologies {
            if tech.js.is_empty() {
                continue;
            }
            if tech.js.keys().any(|js_key| script_tag_ids.contains(js_key)) {
                merge_observed(&mut detected, tech_name.clone(), None);
            }
        }
    }

    // Add implied technologies (fixed-point: A→B, B→C must yield both B and C).
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
                    implied_to_add.push(implied.clone());
                }
            }
        }
        let mut added_any = false;
        for implied_name in implied_to_add {
            if ruleset.technologies.contains_key(&implied_name)
                && !detected.contains_key(&implied_name)
            {
                detected.insert(
                    implied_name,
                    TechInfo {
                        version: None,
                        is_implied: true,
                    },
                );
                added_any = true;
            }
        }
        if !added_any {
            break;
        }
    }

    let detected_vec: Vec<(String, Option<String>, bool)> = detected
        .iter()
        .map(|(name, info)| (name.clone(), info.version.clone(), info.is_implied))
        .collect();

    let detected_formatted_for_exclusions: HashSet<String> = detected_vec
        .iter()
        .map(|(name, version, _)| {
            if let Some(ref ver) = version {
                format!("{name}:{ver}")
            } else {
                name.clone()
            }
        })
        .collect();
    let final_detected_formatted =
        apply_technology_exclusions(&detected_formatted_for_exclusions, ruleset);

    let final_detected: Vec<(String, Option<String>, bool)> = detected_vec
        .into_iter()
        .filter(|(name, version, _)| {
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
        .map(|(name, version, is_implied)| DetectedTechnology {
            category: get_technology_category(ruleset, &name),
            name,
            version,
            is_implied,
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
    fn test_sanitize_technology_version_keeps_semver() {
        assert_eq!(
            sanitize_technology_version(Some("3.6.0".to_string())),
            Some("3.6.0".to_string())
        );
        assert_eq!(
            sanitize_technology_version(Some("1.24.0".to_string())),
            Some("1.24.0".to_string())
        );
    }

    #[test]
    fn test_sanitize_technology_version_drops_hex_hashes() {
        assert_eq!(
            sanitize_technology_version(Some(
                "f0fe27bc311aec88752269bad7be520f4ccf4fe7".to_string()
            )),
            None
        );
        assert_eq!(
            sanitize_technology_version(Some("87df60d54091cf1e8f8173c2e568260c".to_string())),
            None
        );
        assert_eq!(
            sanitize_technology_version(Some("749908d4a842".to_string())),
            None
        );
    }

    #[test]
    fn test_sanitize_technology_version_keeps_short_hex() {
        // Short hex-looking strings that could be real version fragments stay.
        assert_eq!(
            sanitize_technology_version(Some("abc123".to_string())),
            Some("abc123".to_string())
        );
    }

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
            "https://example.com",
            &HashSet::new(),
        )
        .expect("empty ruleset detection should succeed");

        assert!(result.is_empty());
    }

    fn empty_tech() -> crate::fingerprint::models::Technology {
        crate::fingerprint::models::Technology {
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

    /// Offline implies fixed-point: A→B→C must yield A,B,C with B/C marked implied.
    #[test]
    fn test_detect_implies_fixed_point_offline() {
        let mut technologies = HashMap::new();
        let mut tech_a = empty_tech();
        tech_a.html.push("marker-tech-a".to_string());
        tech_a.implies.push("TechB".to_string());
        technologies.insert("TechA".to_string(), tech_a);

        let mut tech_b = empty_tech();
        tech_b.implies.push("TechC".to_string());
        technologies.insert("TechB".to_string(), tech_b);

        technologies.insert("TechC".to_string(), empty_tech());

        let ruleset = Arc::new(FingerprintRuleset {
            technologies,
            categories: HashMap::new(),
            metadata: crate::fingerprint::models::FingerprintMetadata {
                source: "test".into(),
                version: "0".into(),
                last_updated: std::time::SystemTime::now(),
            },
        });

        let result = detect_technologies_blocking(
            &ruleset,
            &HeaderMap::new(),
            &HashMap::new(),
            &[],
            "<html>marker-tech-a</html>",
            "https://example.com",
            &HashSet::new(),
        )
        .expect("detect");

        let by_name: HashMap<_, _> = result.iter().map(|t| (t.name.as_str(), t)).collect();
        assert_eq!(by_name.len(), 3, "expected A,B,C got {:?}", by_name.keys());
        assert!(!by_name["TechA"].is_implied);
        assert!(by_name["TechB"].is_implied);
        assert!(by_name["TechC"].is_implied);
    }

    /// Offline: observed `TechA` excludes `TechC` even when `TechC` arrives via implies.
    #[test]
    fn test_detect_implies_then_exclude_offline() {
        let mut technologies = HashMap::new();
        let mut tech_a = empty_tech();
        tech_a.html.push("marker-tech-a".to_string());
        tech_a.implies.push("TechB".to_string());
        tech_a.excludes.push("TechC".to_string());
        technologies.insert("TechA".to_string(), tech_a);

        let mut tech_b = empty_tech();
        tech_b.implies.push("TechC".to_string());
        technologies.insert("TechB".to_string(), tech_b);
        technologies.insert("TechC".to_string(), empty_tech());

        let ruleset = Arc::new(FingerprintRuleset {
            technologies,
            categories: HashMap::new(),
            metadata: crate::fingerprint::models::FingerprintMetadata {
                source: "test".into(),
                version: "0".into(),
                last_updated: std::time::SystemTime::now(),
            },
        });

        let result = detect_technologies_blocking(
            &ruleset,
            &HeaderMap::new(),
            &HashMap::new(),
            &[],
            "<html>marker-tech-a</html>",
            "https://example.com",
            &HashSet::new(),
        )
        .expect("detect");

        let names: HashSet<_> = result.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains("TechA"));
        assert!(names.contains("TechB"));
        assert!(
            !names.contains("TechC"),
            "TechC must be excluded despite implies chain; got {names:?}"
        );
    }

    /// Versioned detected name `TechB:1.2` is excluded by base-name `excludes: ["TechB"]`.
    #[test]
    fn test_detect_versioned_exclude_offline() {
        let mut technologies = HashMap::new();
        let mut tech_a = empty_tech();
        tech_a.html.push("marker-tech-a".to_string());
        tech_a.excludes.push("TechB".to_string());
        technologies.insert("TechA".to_string(), tech_a);

        let mut tech_b = empty_tech();
        tech_b.html.push("marker-tech-b".to_string());
        // Capture a version from the HTML so detection yields TechB with version.
        tech_b
            .html
            .push("marker-tech-b-v([0-9.]+)\\;version:\\1".to_string());
        technologies.insert("TechB".to_string(), tech_b);

        let ruleset = Arc::new(FingerprintRuleset {
            technologies,
            categories: HashMap::new(),
            metadata: crate::fingerprint::models::FingerprintMetadata {
                source: "test".into(),
                version: "0".into(),
                last_updated: std::time::SystemTime::now(),
            },
        });

        let result = detect_technologies_blocking(
            &ruleset,
            &HeaderMap::new(),
            &HashMap::new(),
            &[],
            "<html>marker-tech-a marker-tech-b-v1.2</html>",
            "https://example.com",
            &HashSet::new(),
        )
        .expect("detect");

        let names: HashSet<_> = result.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains("TechA"));
        assert!(
            !names.contains("TechB"),
            "versioned TechB must be excluded by base name; got {result:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires network for default fingerprint sources; use offline fixture tests instead"]
    async fn test_detect_technologies_blocking_with_init_ruleset() {
        crate::fingerprint::init_ruleset(None, None)
            .await
            .expect("init_ruleset should succeed when network is available");
        let ruleset = crate::fingerprint::get_ruleset()
            .await
            .expect("ruleset should be loaded after init");

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
            "https://example.com",
            &HashSet::new(),
        )
        .expect("detection with initialized ruleset should succeed");

        let tech_names: Vec<String> = result.iter().map(|t| t.name.clone()).collect();
        assert!(
            tech_names.contains(&"jQuery".to_string()) || tech_names.contains(&"Nginx".to_string()),
            "Expected jQuery or Nginx from fixture signals, got: {tech_names:?}"
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
