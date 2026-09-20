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
mod dns_cert;
mod headers;
mod interstitial;
mod matching;
mod signal_match;
mod source;
mod utils;

#[cfg(test)]
mod gold_set;

use reqwest::header::HeaderMap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::error_handling::FingerprintError;
use crate::fingerprint::models::FingerprintRuleset;
use crate::fingerprint::patterns::parse_technology_reference;

use body::{check_body_with_ruleset, check_scripts_with_ruleset};
use cookies::check_cookies_with_ruleset;
use dns_cert::check_dns_and_cert_with_ruleset;
use headers::check_headers_with_ruleset;
use matching::{apply_technology_exclusions, apply_technology_requires};
use source::DetectionSource;
use utils::{extract_cookies_from_headers, normalize_headers_to_map};

pub(crate) use interstitial::is_challenge_interstitial;

/// Detects technologies from extracted HTML data, headers, and URL.
///
/// Static matcher (no JavaScript execution):
/// - Headers
/// - Cookies (from `SET_COOKIE` and Cookie headers)
/// - Meta tags (name, property, http-equiv)
/// - Script sources (`src` URLs from HTML — not fetched)
/// - Inline `<script>` text (`scripts` patterns; same matcher as fetched bodies)
/// - Script tag IDs (static HTML `id` attributes, e.g. `__NEXT_DATA__`)
/// - HTML text patterns
/// - URL patterns
///
/// Late signals (NS/CNAME / cert issuer / fetched script bodies) are merged after
/// `parallel_enrich` via [`supplement_technologies_with_dns_cert`] and
/// [`supplement_technologies_with_script_text`]. TXT/MX/SPF/DMARC and CSP
/// allowlists are not treated as serving-stack technologies. Certificate
/// authorities matched via `certIssuer` are dropped (use `ssl_cert_issuer`).
///
/// Technologies with only runtime `js` object patterns (and no other signals) are not detected.
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
    /// Static signal that produced the match (`header`, `html`, `scriptSrc`, `ns`, …).
    pub detection_source: Option<String>,
}

#[derive(Clone)]
struct TechInfo {
    version: Option<String>,
    is_implied: bool,
    source: DetectionSource,
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

fn merge_observed(
    detected: &mut HashMap<String, TechInfo>,
    tech_name: String,
    version: Option<String>,
    source: DetectionSource,
) {
    let version = sanitize_technology_version(version);
    detected
        .entry(tech_name)
        .and_modify(|existing| {
            if existing.is_implied {
                existing.source = source;
            }
            existing.is_implied = false;
            if existing.version.is_none() && version.is_some() {
                existing.version.clone_from(&version);
            }
        })
        .or_insert(TechInfo {
            version,
            is_implied: false,
            source,
        });
}

/// Expands `implies` to a fixed point, stripping upstream `\;…` metadata from names.
fn expand_implies(detected: &mut HashMap<String, TechInfo>, ruleset: &FingerprintRuleset) {
    const MAX_IMPLIES_DEPTH: u32 = 10;
    for _ in 0..MAX_IMPLIES_DEPTH {
        let mut implied_to_add: Vec<(String, Option<String>)> = Vec::new();
        for tech_name in detected.keys() {
            // Keys are bare technology names (may contain ':'); never split on colon.
            if let Some(tech) = ruleset.technologies.get(tech_name) {
                for implied in &tech.implies {
                    let (name, version) = parse_technology_reference(implied);
                    implied_to_add.push((name, version));
                }
            }
        }
        let mut added_any = false;
        for (implied_name, version) in implied_to_add {
            if !ruleset.technologies.contains_key(&implied_name) {
                continue;
            }
            let version = sanitize_technology_version(version);
            match detected.get_mut(&implied_name) {
                Some(existing) => {
                    if existing.version.is_none() && version.is_some() {
                        existing.version = version;
                    }
                }
                None => {
                    detected.insert(
                        implied_name,
                        TechInfo {
                            version,
                            is_implied: true,
                            source: DetectionSource::Implied,
                        },
                    );
                    added_any = true;
                }
            }
        }
        if !added_any {
            break;
        }
    }
}

/// Protocol / transport flags and CAs that belong in headers/TLS columns, not the stack inventory.
fn is_denylisted_technology(name: &str, ruleset: &FingerprintRuleset) -> bool {
    if name.eq_ignore_ascii_case("HTTP/2")
        || name.eq_ignore_ascii_case("HTTP/3")
        || name.eq_ignore_ascii_case("HSTS")
    {
        return true;
    }
    technology_in_category(ruleset, name, "SSL/TLS certificate authorities")
}

/// True when any of the technology's category IDs resolve to `category`.
fn technology_in_category(ruleset: &FingerprintRuleset, name: &str, category: &str) -> bool {
    let Some(tech) = ruleset.technologies.get(name) else {
        return false;
    };
    tech.cats.iter().any(|id| {
        ruleset
            .categories
            .get(id)
            .is_some_and(|c| c.eq_ignore_ascii_case(category))
    })
}

fn finalize_detections(
    detected: HashMap<String, TechInfo>,
    ruleset: &FingerprintRuleset,
) -> Vec<DetectedTechnology> {
    let detected_names: HashSet<String> = detected.keys().cloned().collect();
    let after_exclusions = apply_technology_exclusions(&detected_names, ruleset);
    let kept_names = apply_technology_requires(&after_exclusions, ruleset);

    detected
        .into_iter()
        .filter(|(name, _)| kept_names.contains(name))
        .filter_map(|(name, info)| {
            if is_denylisted_technology(&name, ruleset) {
                return None;
            }
            Some(DetectedTechnology {
                category: get_technology_category(ruleset, &name),
                detection_source: Some(info.source.as_str().to_string()),
                name,
                version: info.version,
                is_implied: info.is_implied,
            })
        })
        .collect()
}

fn detected_to_map(techs: &[DetectedTechnology]) -> HashMap<String, TechInfo> {
    let mut detected = HashMap::with_capacity(techs.len());
    for tech in techs {
        let source = tech
            .detection_source
            .as_deref()
            .and_then(parse_detection_source)
            .unwrap_or(if tech.is_implied {
                DetectionSource::Implied
            } else {
                DetectionSource::Html
            });
        detected.insert(
            tech.name.clone(),
            TechInfo {
                version: tech.version.clone(),
                is_implied: tech.is_implied,
                source,
            },
        );
    }
    detected
}

fn parse_detection_source(raw: &str) -> Option<DetectionSource> {
    Some(match raw {
        "header" => DetectionSource::Header,
        "cookie" => DetectionSource::Cookie,
        "html" => DetectionSource::Html,
        "scriptSrc" => DetectionSource::ScriptSrc,
        "scripts" => DetectionSource::Scripts,
        "url" => DetectionSource::Url,
        "js" => DetectionSource::Js,
        "ns" => DetectionSource::Ns,
        "cname" => DetectionSource::Cname,
        "cert" => DetectionSource::Cert,
        "implied" => DetectionSource::Implied,
        _ => return None,
    })
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
    inline_script_text: &str,
) -> Result<Vec<DetectedTechnology>, FingerprintError> {
    let cookies = extract_cookies_from_headers(headers);
    let header_map = normalize_headers_to_map(headers);

    log::debug!(
        "Technology detection (blocking) for {}: {} script tag ids, {} external script sources",
        url,
        script_tag_ids.len(),
        script_sources.len()
    );

    let mut detected: HashMap<String, TechInfo> = HashMap::with_capacity(32);

    let header_results = check_headers_with_ruleset(ruleset, &header_map);
    for result in header_results {
        merge_observed(
            &mut detected,
            result.tech_name,
            result.version,
            result.source,
        );
    }

    if !cookies.is_empty() {
        let cookie_results = check_cookies_with_ruleset(ruleset, &cookies);
        for result in cookie_results {
            merge_observed(
                &mut detected,
                result.tech_name,
                result.version,
                result.source,
            );
        }
    }

    let body_results = check_body_with_ruleset(
        ruleset,
        html_body,
        script_sources,
        meta_tags,
        url,
        inline_script_text,
    );
    for result in body_results {
        merge_observed(
            &mut detected,
            result.tech_name,
            result.version,
            result.source,
        );
    }

    // Static script-tag ID match against ruleset `js` keys (e.g. id="__NEXT_DATA__").
    // This is HTML attribute matching, not JavaScript execution.
    if !script_tag_ids.is_empty() {
        for (tech_name, tech) in &ruleset.technologies {
            if tech.js.is_empty() {
                continue;
            }
            if tech.js.keys().any(|js_key| script_tag_ids.contains(js_key)) {
                merge_observed(&mut detected, tech_name.clone(), None, DetectionSource::Js);
            }
        }
    }

    expand_implies(&mut detected, ruleset);

    let before_exclusions = detected.len();
    let mut final_detected = finalize_detections(detected, ruleset);
    drop_github_pages_on_github_dot_com(&mut final_detected, url);

    log::debug!(
        "Technology detection (blocking) summary for {}: {} detected ({} after exclusions)",
        url,
        before_exclusions,
        final_detected.len()
    );

    Ok(final_detected)
}

/// Upstream GitHub Pages matches `Server: GitHub.com`, which is also the product
/// site's header. Keep Pages on `*.github.io` and third-party Pages hosts.
fn drop_github_pages_on_github_dot_com(techs: &mut Vec<DetectedTechnology>, url: &str) {
    if !is_github_dot_com_host(url) {
        return;
    }
    techs.retain(|tech| tech.name != "GitHub Pages");
}

fn is_github_dot_com_host(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    parsed.host_str().is_some_and(|host| {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        host == "github.com" || host == "www.github.com"
    })
}

/// Merges DNS / cert-issuer matches into an existing detection set and re-runs
/// implies / excludes. Intended to run after DNS/TLS enrichment completes.
pub(crate) fn supplement_technologies_with_dns_cert(
    ruleset: &FingerprintRuleset,
    already_detected: Vec<DetectedTechnology>,
    dns_records: &HashMap<String, String>,
    cert_issuer: Option<&str>,
) -> Vec<DetectedTechnology> {
    if dns_records.is_empty() && cert_issuer.is_none() {
        return already_detected;
    }

    let mut detected = detected_to_map(&already_detected);
    let supplemental = check_dns_and_cert_with_ruleset(ruleset, dns_records, cert_issuer);
    if supplemental.is_empty() {
        return already_detected;
    }

    for result in supplemental {
        merge_observed(
            &mut detected,
            result.tech_name,
            result.version,
            result.source,
        );
    }
    expand_implies(&mut detected, ruleset);
    finalize_detections(detected, ruleset)
}

/// Matches Wappalyzer `scripts` patterns against fetched (or other) script text
/// and merges into an existing detection set, then re-runs implies / excludes.
///
/// Uses the same matcher as inline script text in the first tech pass
/// ([`check_scripts_with_ruleset`]). Intended after `--scan-external-scripts`
/// returns concatenated first-party bodies.
pub(crate) fn supplement_technologies_with_script_text(
    ruleset: &FingerprintRuleset,
    already_detected: Vec<DetectedTechnology>,
    script_text: &str,
) -> Vec<DetectedTechnology> {
    if script_text.is_empty() {
        return already_detected;
    }

    let supplemental = check_scripts_with_ruleset(ruleset, script_text);
    if supplemental.is_empty() {
        return already_detected;
    }

    let mut detected = detected_to_map(&already_detected);
    for result in supplemental {
        merge_observed(
            &mut detected,
            result.tech_name,
            result.version,
            result.source,
        );
    }
    expand_implies(&mut detected, ruleset);
    finalize_detections(detected, ruleset)
}

/// Builds lowercase DNS haystacks used for technology matching.
///
/// Only NS and CNAME are serving-stack evidence. TXT/MX/SPF/DMARC stay in
/// satellite tables (`url_txt_records`, `url_mx_records`) and are not copied
/// into `url_technologies`.
#[must_use]
pub(crate) fn dns_records_haystack(
    nameservers: Option<&str>,
    cname_chain: Option<&str>,
) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let push = |map: &mut HashMap<String, String>, key: &str, value: Option<&str>| {
        if let Some(v) = value {
            if !v.is_empty() {
                map.insert(key.to_string(), v.to_lowercase());
            }
        }
    };
    push(&mut map, "NS", nameservers);
    push(&mut map, "CNAME", cname_chain);
    map
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
    fn test_finalize_detections_drops_http2_http3_and_hsts() {
        let mut detected = HashMap::new();
        detected.insert(
            "HTTP/2".to_string(),
            TechInfo {
                version: None,
                is_implied: false,
                source: DetectionSource::Header,
            },
        );
        detected.insert(
            "HTTP/3".to_string(),
            TechInfo {
                version: None,
                is_implied: false,
                source: DetectionSource::Header,
            },
        );
        detected.insert(
            "HSTS".to_string(),
            TechInfo {
                version: None,
                is_implied: false,
                source: DetectionSource::Header,
            },
        );
        detected.insert(
            "nginx".to_string(),
            TechInfo {
                version: Some("1.18".to_string()),
                is_implied: false,
                source: DetectionSource::Header,
            },
        );
        detected.insert(
            "Re:amaze".to_string(),
            TechInfo {
                version: Some("2".to_string()),
                is_implied: false,
                source: DetectionSource::Header,
            },
        );
        let ruleset = FingerprintRuleset {
            technologies: HashMap::new(),
            categories: HashMap::new(),
            metadata: crate::fingerprint::models::FingerprintMetadata {
                source: "test".into(),
                version: "0".into(),
                last_updated: std::time::SystemTime::now(),
            },
        };
        let out = finalize_detections(detected, &ruleset);
        let names: Vec<_> = out.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"nginx"));
        assert!(names.contains(&"Re:amaze"));
        assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("HTTP/2")));
        assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("HTTP/3")));
        assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("HSTS")));
        let re = out.iter().find(|t| t.name == "Re:amaze").unwrap();
        assert_eq!(re.version.as_deref(), Some("2"));
    }

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
            "",
        )
        .expect("empty ruleset detection should succeed");

        assert!(result.is_empty());
    }

    fn empty_tech() -> crate::fingerprint::models::Technology {
        crate::fingerprint::models::Technology::default()
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
            "",
        )
        .expect("detect");

        let by_name: HashMap<_, _> = result.iter().map(|t| (t.name.as_str(), t)).collect();
        assert_eq!(by_name.len(), 3, "expected A,B,C got {:?}", by_name.keys());
        assert!(!by_name["TechA"].is_implied);
        assert!(by_name["TechB"].is_implied);
        assert!(by_name["TechC"].is_implied);
    }

    /// Upstream encodes `implies` with `\;confidence:` — must still resolve.
    #[test]
    fn test_detect_implies_strips_confidence_metadata() {
        let mut technologies = HashMap::new();
        let mut hhvm = empty_tech();
        hhvm.html.push("marker-hhvm".to_string());
        hhvm.implies.push("PHP\\;confidence:75".to_string());
        technologies.insert("HHVM".to_string(), hhvm);
        technologies.insert("PHP".to_string(), empty_tech());

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
            "<html>marker-hhvm</html>",
            "https://example.com",
            &HashSet::new(),
            "",
        )
        .expect("detect");

        let php = result
            .iter()
            .find(|t| t.name == "PHP")
            .expect("PHP implied");
        assert!(php.is_implied);
        assert!(php.version.is_none());
    }

    /// Upstream encodes `implies` with `\;version:N` — name resolves and version is kept.
    #[test]
    fn test_detect_implies_applies_literal_version() {
        let mut technologies = HashMap::new();
        let mut theme = empty_tech();
        theme.html.push("marker-hyva".to_string());
        theme.implies.push("Magento\\;version:2".to_string());
        technologies.insert("Hyva Themes".to_string(), theme);
        technologies.insert("Magento".to_string(), empty_tech());

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
            "<html>marker-hyva</html>",
            "https://example.com",
            &HashSet::new(),
            "",
        )
        .expect("detect");

        let magento = result
            .iter()
            .find(|t| t.name == "Magento")
            .expect("Magento implied");
        assert!(magento.is_implied);
        assert_eq!(magento.version.as_deref(), Some("2"));
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
            "",
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

    /// Excludes with `\;confidence:` metadata still match base technology names.
    #[test]
    fn test_detect_excludes_strips_metadata() {
        let mut technologies = HashMap::new();
        let mut tech_a = empty_tech();
        tech_a.html.push("marker-tech-a".to_string());
        tech_a.excludes.push("TechB\\;confidence:50".to_string());
        technologies.insert("TechA".to_string(), tech_a);

        let mut tech_b = empty_tech();
        tech_b.html.push("marker-tech-b".to_string());
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
            "<html>marker-tech-a marker-tech-b</html>",
            "https://example.com",
            &HashSet::new(),
            "",
        )
        .expect("detect");

        let names: HashSet<_> = result.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains("TechA"));
        assert!(!names.contains("TechB"));
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
            "",
        )
        .expect("detect");

        let names: HashSet<_> = result.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains("TechA"));
        assert!(
            !names.contains("TechB"),
            "versioned TechB must be excluded by base name; got {result:?}"
        );
    }

    #[test]
    fn test_supplement_dns_cert_merges_and_implies() {
        let mut technologies = HashMap::new();
        let mut ns_tech = empty_tech();
        ns_tech.dns.insert("NS".into(), vec![r"awsdns-\d+".into()]);
        ns_tech.implies.push("Amazon Web Services".to_string());
        technologies.insert("Amazon Route 53".to_string(), ns_tech);
        technologies.insert("Amazon Web Services".to_string(), empty_tech());

        let ruleset = FingerprintRuleset {
            technologies,
            categories: HashMap::new(),
            metadata: crate::fingerprint::models::FingerprintMetadata {
                source: "test".into(),
                version: "0".into(),
                last_updated: std::time::SystemTime::now(),
            },
        };

        let dns = HashMap::from([("NS".into(), "ns-520.awsdns-01.net.".to_string())]);
        let result = supplement_technologies_with_dns_cert(&ruleset, Vec::new(), &dns, None);
        let names: HashSet<_> = result.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains("Amazon Route 53"));
        assert!(names.contains("Amazon Web Services"));
    }

    #[test]
    fn test_supplement_txt_mx_org_proofs_are_not_technologies() {
        let mut technologies = HashMap::new();
        let mut docusign = empty_tech();
        docusign.dns.insert("TXT".into(), vec!["docusign=".into()]);
        let mut miro = empty_tech();
        miro.dns
            .insert("TXT".into(), vec!["miro-verification=".into()]);
        let mut gmail = empty_tech();
        gmail.dns.insert("MX".into(), vec!["google\\.com".into()]);
        technologies.insert("DocuSign".into(), docusign);
        technologies.insert("Miro".into(), miro);
        technologies.insert("Gmail".into(), gmail);

        let ruleset = FingerprintRuleset {
            technologies,
            categories: HashMap::new(),
            metadata: crate::fingerprint::models::FingerprintMetadata {
                source: "test".into(),
                version: "0".into(),
                last_updated: std::time::SystemTime::now(),
            },
        };

        let dns = HashMap::from([
            (
                "TXT".into(),
                "docusign=087098e3 miro-verification=abc v=spf1 include:docusign.net".to_string(),
            ),
            ("MX".into(), "10 aspmx.l.google.com.".to_string()),
        ]);
        let result = supplement_technologies_with_dns_cert(&ruleset, Vec::new(), &dns, None);
        assert!(
            result.is_empty(),
            "TXT/MX vendor proofs must not become url_technologies, got {result:?}"
        );
    }

    #[test]
    fn test_supplement_cert_issuer_lets_encrypt() {
        let mut tech = empty_tech();
        tech.cert_issuer.push("Let's Encrypt".into());
        tech.cats.push(70);
        let ruleset = FingerprintRuleset {
            technologies: HashMap::from([("Let's Encrypt".into(), tech)]),
            categories: HashMap::from([(70, "SSL/TLS certificate authorities".into())]),
            metadata: crate::fingerprint::models::FingerprintMetadata {
                source: "test".into(),
                version: "0".into(),
                last_updated: std::time::SystemTime::now(),
            },
        };

        let result = supplement_technologies_with_dns_cert(
            &ruleset,
            Vec::new(),
            &HashMap::new(),
            Some("C = US, O = Let's Encrypt, CN = R3"),
        );
        assert!(
            result.is_empty(),
            "certificate authorities must not become url_technologies, got {result:?}"
        );
    }

    #[test]
    fn test_finalize_drops_ca_category() {
        let mut detected = HashMap::new();
        detected.insert(
            "Custom CA".to_string(),
            TechInfo {
                version: None,
                is_implied: false,
                source: DetectionSource::Cert,
            },
        );
        detected.insert(
            "nginx".to_string(),
            TechInfo {
                version: None,
                is_implied: false,
                source: DetectionSource::Header,
            },
        );
        let mut ca = empty_tech();
        ca.cats.push(70);
        let ruleset = FingerprintRuleset {
            technologies: HashMap::from([("Custom CA".into(), ca)]),
            categories: HashMap::from([(70, "SSL/TLS certificate authorities".into())]),
            metadata: crate::fingerprint::models::FingerprintMetadata {
                source: "test".into(),
                version: "0".into(),
                last_updated: std::time::SystemTime::now(),
            },
        };
        let out = finalize_detections(detected, &ruleset);
        let names: Vec<_> = out.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"nginx"));
        assert!(!names.contains(&"Custom CA"));
    }

    #[test]
    fn test_finalize_drops_ca_when_not_first_category() {
        let mut detected = HashMap::new();
        detected.insert(
            "Mixed".to_string(),
            TechInfo {
                version: None,
                is_implied: false,
                source: DetectionSource::Cert,
            },
        );
        let mut mixed = empty_tech();
        mixed.cats.push(1);
        mixed.cats.push(70);
        let ruleset = FingerprintRuleset {
            technologies: HashMap::from([("Mixed".into(), mixed)]),
            categories: HashMap::from([
                (1, "CMS".into()),
                (70, "SSL/TLS certificate authorities".into()),
            ]),
            metadata: crate::fingerprint::models::FingerprintMetadata {
                source: "test".into(),
                version: "0".into(),
                last_updated: std::time::SystemTime::now(),
            },
        };
        let out = finalize_detections(detected, &ruleset);
        assert!(
            out.iter().all(|t| t.name != "Mixed"),
            "CA category must drop even when it is not the first cat, got {out:?}"
        );
    }

    #[test]
    fn dns_records_haystack_is_ns_and_cname_only() {
        let map = dns_records_haystack(Some("ns-520.awsdns-01.net"), Some("cdn.example.net"));
        assert_eq!(
            map.get("NS").map(String::as_str),
            Some("ns-520.awsdns-01.net")
        );
        assert_eq!(
            map.get("CNAME").map(String::as_str),
            Some("cdn.example.net")
        );
        assert!(!map.contains_key("TXT"));
        assert!(!map.contains_key("MX"));
    }

    #[test]
    fn github_com_server_header_is_not_github_pages() {
        let ruleset = github_pages_ruleset();
        let headers = server_header("GitHub.com");
        let result = detect_named(&ruleset, &headers, "https://github.com/");
        assert!(
            result.iter().all(|t| t.name != "GitHub Pages"),
            "github.com product site must not be labeled GitHub Pages, got {result:?}"
        );

        let www = detect_named(&ruleset, &headers, "https://www.github.com/login");
        assert!(
            www.iter().all(|t| t.name != "GitHub Pages"),
            "www.github.com must not be labeled GitHub Pages, got {www:?}"
        );
    }

    #[test]
    fn github_pages_still_matches_github_io_and_third_party_hosts() {
        let ruleset = github_pages_ruleset();
        let io = detect_named(&ruleset, &HeaderMap::new(), "https://example.github.io/");
        assert!(
            io.iter().any(|t| t.name == "GitHub Pages"),
            "github.io hosts should still match GitHub Pages, got {io:?}"
        );

        let other_host = detect_named(
            &ruleset,
            &server_header("GitHub.com"),
            "https://pages.example.org/",
        );
        assert!(
            other_host.iter().any(|t| t.name == "GitHub Pages"),
            "non-github.com Server: GitHub.com should still match Pages, got {other_host:?}"
        );
    }

    #[test]
    fn csp_allowlist_does_not_detect_amazon_s3_on_full_pass() {
        let mut s3 = empty_tech();
        s3.headers.insert(
            "content-security-policy".into(),
            r"s3[^ ]*\.amazonaws\.com".into(),
        );
        s3.headers.insert("server".into(), "AmazonS3".into());
        let ruleset = Arc::new(FingerprintRuleset {
            technologies: HashMap::from([("Amazon S3".into(), s3)]),
            categories: HashMap::new(),
            metadata: crate::fingerprint::models::FingerprintMetadata {
                source: "test".into(),
                version: "0".into(),
                last_updated: std::time::SystemTime::now(),
            },
        });

        let mut csp = HeaderMap::new();
        csp.insert(
            reqwest::header::HeaderName::from_static("content-security-policy"),
            "img-src https://media.example.s3.amazonaws.com"
                .parse()
                .unwrap(),
        );
        let csp_only = detect_named(&ruleset, &csp, "https://example.com/");
        assert!(
            csp_only.iter().all(|t| t.name != "Amazon S3"),
            "CSP allowlists must not insert Amazon S3, got {csp_only:?}"
        );

        let hosted = detect_named(&ruleset, &server_header("AmazonS3"), "https://example.com/");
        assert!(
            hosted.iter().any(|t| t.name == "Amazon S3"),
            "Server: AmazonS3 should still fingerprint S3 hosting, got {hosted:?}"
        );
    }

    fn github_pages_ruleset() -> Arc<FingerprintRuleset> {
        let mut pages = empty_tech();
        pages
            .headers
            .insert("server".into(), r"^GitHub\.com$".into());
        pages.url.push(r"\.github\.io".into());
        Arc::new(FingerprintRuleset {
            technologies: HashMap::from([("GitHub Pages".into(), pages)]),
            categories: HashMap::new(),
            metadata: crate::fingerprint::models::FingerprintMetadata {
                source: "test".into(),
                version: "0".into(),
                last_updated: std::time::SystemTime::now(),
            },
        })
    }

    fn server_header(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(reqwest::header::SERVER, value.parse().unwrap());
        headers
    }

    fn detect_named(
        ruleset: &Arc<FingerprintRuleset>,
        headers: &HeaderMap,
        url: &str,
    ) -> Vec<DetectedTechnology> {
        detect_technologies_blocking(
            ruleset,
            headers,
            &HashMap::new(),
            &[],
            "",
            url,
            &HashSet::new(),
            "",
        )
        .expect("detect")
    }

    #[test]
    fn test_supplement_script_text_detects_scripts_only_tech() {
        let mut technologies = HashMap::new();
        let mut webpack = empty_tech();
        webpack
            .scripts
            .push(r"function webpackJsonpCallback\(data\) \{".to_string());
        webpack.implies.push("JavaScript".to_string());
        technologies.insert("Webpack".to_string(), webpack);
        technologies.insert("JavaScript".to_string(), empty_tech());

        let ruleset = FingerprintRuleset {
            technologies,
            categories: HashMap::new(),
            metadata: crate::fingerprint::models::FingerprintMetadata {
                source: "test".into(),
                version: "0".into(),
                last_updated: std::time::SystemTime::now(),
            },
        };

        let body = "function webpackJsonpCallback(data) { return data; }";
        let result =
            supplement_technologies_with_script_text(&ruleset, Vec::new(), &body.to_lowercase());
        let names: HashSet<_> = result.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains("Webpack"));
        assert!(names.contains("JavaScript"));
    }

    #[test]
    fn test_supplement_script_text_empty_is_noop() {
        let prior = vec![DetectedTechnology {
            name: "Nginx".into(),
            version: None,
            category: None,
            is_implied: false,
            detection_source: Some("header".into()),
        }];
        let ruleset = FingerprintRuleset::empty_for_tests();
        let result = supplement_technologies_with_script_text(&ruleset, prior.clone(), "");
        assert_eq!(result, prior);
    }

    #[tokio::test]
    #[ignore = "requires network for default fingerprint sources; use offline fixture tests instead"]
    async fn test_detect_technologies_blocking_with_init_ruleset() {
        crate::fingerprint::init_ruleset(None, None, true)
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
            "",
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

    /// Kills: rewriting any `parse_detection_source` match arm (e.g. `"header"`
    /// → `Cookie`, or dropping `"scriptSrc"`) or the `_ => return None` default.
    #[rstest::rstest]
    #[case("header", Some(DetectionSource::Header))]
    #[case("cookie", Some(DetectionSource::Cookie))]
    #[case("html", Some(DetectionSource::Html))]
    #[case("scriptSrc", Some(DetectionSource::ScriptSrc))]
    #[case("scripts", Some(DetectionSource::Scripts))]
    #[case("url", Some(DetectionSource::Url))]
    #[case("js", Some(DetectionSource::Js))]
    #[case("ns", Some(DetectionSource::Ns))]
    #[case("cname", Some(DetectionSource::Cname))]
    #[case("cert", Some(DetectionSource::Cert))]
    #[case("implied", Some(DetectionSource::Implied))]
    #[case("", None)]
    #[case("HEADER", None)]
    #[case("Header", None)]
    fn test_parse_detection_source_maps_exact_variant(
        #[case] raw: &str,
        #[case] expected: Option<DetectionSource>,
    ) {
        assert_eq!(parse_detection_source(raw), expected);
    }

    /// Kills: dropping `to_ascii_lowercase` / `trim_end_matches('.')`, treating
    /// `github.com` as a prefix of another registrable host, or rejecting
    /// userinfo on `https://user@github.com/` (the host is still `github.com`).
    #[rstest::rstest]
    #[case("https://github.com/octocat", true)]
    #[case("https://www.github.com/login", true)]
    #[case("https://GitHub.com/", true)]
    #[case("https://github.com./", true)]
    #[case("https://user@github.com/", true)]
    #[case("https://github.com.example.net/", false)]
    #[case("https://notgithub.example.com/", false)]
    #[case("not a url", false)]
    #[case("user@github.com", false)]
    fn test_is_github_dot_com_host_contract(#[case] url: &str, #[case] expected: bool) {
        assert_eq!(is_github_dot_com_host(url), expected);
    }

    /// Kills: deleting `!` on `cookies.is_empty()` (or skipping
    /// `check_cookies_with_ruleset`) so a present `_uetsid` cookie is not
    /// observed as `cookie`.
    #[test]
    fn detect_technologies_blocking_set_cookie_is_cookie_source() {
        let mut tech = empty_tech();
        tech.cookies.insert("_uetsid".to_string(), String::new());
        let ruleset = Arc::new(FingerprintRuleset {
            technologies: HashMap::from([("Microsoft Advertising".into(), tech)]),
            categories: HashMap::new(),
            metadata: crate::fingerprint::models::FingerprintMetadata {
                source: "test".into(),
                version: "0".into(),
                last_updated: std::time::SystemTime::now(),
            },
        });
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::SET_COOKIE,
            "_uetsid=ABCDEF".parse().unwrap(),
        );
        let result = detect_technologies_blocking(
            &ruleset,
            &headers,
            &HashMap::new(),
            &[],
            "",
            "https://example.com/",
            &HashSet::new(),
            "",
        )
        .expect("detect");
        let hit = result
            .iter()
            .find(|t| t.name == "Microsoft Advertising")
            .expect("cookie gate must run");
        assert_eq!(hit.detection_source.as_deref(), Some("cookie"));
    }

    /// Kills: deleting `!` on `script_tag_ids.is_empty()` so a `__NEXT_DATA__`
    /// script-tag id is not observed as `js`.
    #[test]
    fn detect_technologies_blocking_script_tag_id_is_js_source() {
        let mut tech = empty_tech();
        tech.js.insert("__NEXT_DATA__".to_string(), String::new());
        let ruleset = Arc::new(FingerprintRuleset {
            technologies: HashMap::from([("Next.js".into(), tech)]),
            categories: HashMap::new(),
            metadata: crate::fingerprint::models::FingerprintMetadata {
                source: "test".into(),
                version: "0".into(),
                last_updated: std::time::SystemTime::now(),
            },
        });
        let script_tag_ids = HashSet::from(["__NEXT_DATA__".to_string()]);
        let result = detect_technologies_blocking(
            &ruleset,
            &HeaderMap::new(),
            &HashMap::new(),
            &[],
            "",
            "https://example.com/",
            &script_tag_ids,
            "",
        )
        .expect("detect");
        let hit = result
            .iter()
            .find(|t| t.name == "Next.js")
            .expect("script-tag gate must run");
        assert_eq!(hit.detection_source.as_deref(), Some("js"));
    }
}
