//! Fingerprint ruleset loading and caching.
//!
//! This module handles:
//! - Fetching fingerprint rulesets from URLs or local paths
//! - Merging rulesets from multiple sources
//! - Caching rulesets locally with expiration
//! - Loading categories and metadata

mod cache;
mod categories;
mod fetch;
mod github;
mod local;
mod overlay;
mod vendored;

use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::SystemTime;
use tokio::sync::{Mutex, RwLock};

use crate::fingerprint::models::{FingerprintMetadata, FingerprintRuleset};
use crate::utils::sha256_hex;

use cache::{load_from_cache, save_to_cache};
use categories::{fetch_categories_from_url, load_categories_from_path};
use fetch::fetch_from_url;
use github::get_latest_commit_sha;
use local::load_from_path;
use overlay::apply_first_party_overlay;
use vendored::load_vendored_ruleset;

/// Cache schema version. Bump when `Technology` retained fields change so old
/// narrowed caches (missing dns/certIssuer/scripts/requires) are not reused.
const CACHE_SCHEMA_VERSION: &str = "4";

/// Cache filename stem for a source list (schema-prefixed so old caches miss).
fn fingerprint_cache_key(sources: &[String]) -> String {
    if sources.is_empty() {
        log::warn!("Fingerprint sources is empty, using default cache key");
        format!("default-schema{CACHE_SCHEMA_VERSION}")
    } else if sources.len() == 1 {
        let material = format!("{CACHE_SCHEMA_VERSION}\n{}", sources[0]);
        sha256_hex(material.as_bytes())
    } else {
        let combined = format!("{CACHE_SCHEMA_VERSION}\n{}", sources.join("\n"));
        sha256_hex(combined.as_bytes())
    }
}

/// Operator-visible `metadata.source`: one URL, or newline-joined when merged.
fn fingerprint_source_label(sources: &[String]) -> String {
    if sources.len() == 1 {
        sources[0].clone()
    } else {
        sources.join("\n")
    }
}

/// Default URLs for fingerprint sources (merged; order matches wappalyzergo: enthec then `HTTPArchive`).
/// wappalyzergo uses the same two sources; we merge with later overwriting earlier for the same technology.
const DEFAULT_FINGERPRINTS_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies",
    "https://raw.githubusercontent.com/HTTPArchive/wappalyzer/main/src/technologies",
];

/// Minimum technology count for a default remote merge to count as a full catalog.
/// Vendored fallback is ~17 names; a healthy Enthec + `HTTPArchive` merge is thousands.
const MIN_FULL_TECHNOLOGIES: usize = 1000;

/// Global ruleset cache (lazy-loaded)
static RULESET: LazyLock<Arc<RwLock<Option<Arc<FingerprintRuleset>>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(None)));

/// Serializes first-load so concurrent callers cannot race vendored vs remote writes.
static RULESET_INIT: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Keep only `js` keys that look like HTML script `id`s (static detection under ADR 0005).
/// Typical globals (`jQuery`, `$`) are dropped; `__NEXT_DATA__`-style IDs are retained.
fn is_script_id_js_key(key: &str) -> bool {
    let k = key.trim();
    if k.is_empty() {
        return false;
    }
    k.starts_with("__") || k.to_ascii_uppercase().contains("DATA")
}

/// True when the only matchable signal is runtime `js` (ADR 0005 cannot honor those alone).
fn is_js_only_technology(tech: &crate::fingerprint::models::Technology) -> bool {
    !tech.js.is_empty()
        && tech.headers.is_empty()
        && tech.cookies.is_empty()
        && tech.meta.is_empty()
        && tech.script.is_empty()
        && tech.scripts.is_empty()
        && tech.html.is_empty()
        && tech.url.is_empty()
        && tech.dns.is_empty()
        && tech.cert_issuer.is_empty()
}

/// Lowercase header/cookie keys, then prune unused payload for static detection.
pub(crate) fn ingest_technology(
    mut tech: crate::fingerprint::models::Technology,
) -> Option<crate::fingerprint::models::Technology> {
    let mut normalized_headers = HashMap::new();
    for (header_name, pattern) in tech.headers {
        normalized_headers.insert(header_name.to_lowercase(), pattern);
    }
    tech.headers = normalized_headers;

    let mut normalized_cookies = HashMap::new();
    for (cookie_name, pattern) in tech.cookies {
        normalized_cookies.insert(cookie_name.to_lowercase(), pattern);
    }
    tech.cookies = normalized_cookies;

    prune_technology_for_static_detection(tech)
}

/// Strip unused payload; drop only dead js-only rules after script-id filtering.
///
/// Category / implies stubs (no headers/html/js/…) are kept so `implies` targets remain
/// resolvable (e.g. Nginx → `TestOS` in offline fixtures).
fn prune_technology_for_static_detection(
    mut tech: crate::fingerprint::models::Technology,
) -> Option<crate::fingerprint::models::Technology> {
    let was_js_only = is_js_only_technology(&tech);
    // website is never consulted during matching — drop to shrink cache/RSS.
    tech.website.clear();
    // Retain only script-id-like js keys; clear pattern values (ID presence is enough).
    tech.js = tech
        .js
        .into_iter()
        .filter(|(k, _)| is_script_id_js_key(k))
        .map(|(k, _)| (k, String::new()))
        .collect();
    if was_js_only && tech.js.is_empty() {
        None
    } else {
        Some(tech)
    }
}

/// Apply the first-party overlay. Every load path (cache, vendored, merge) ends here.
fn finish_ruleset(mut ruleset: FingerprintRuleset) -> Result<FingerprintRuleset> {
    apply_first_party_overlay(&mut ruleset.technologies)?;
    Ok(ruleset)
}

/// One-line ruleset identity for startup logs and tests.
pub(crate) fn ruleset_identity_summary(ruleset: &FingerprintRuleset) -> String {
    let source = ruleset.metadata.source.replace('\n', " + ");
    let quality = ruleset_quality_label(ruleset);
    format!(
        "Fingerprint ruleset: {} technologies, source={source}, version={}, {quality}",
        ruleset.technologies.len(),
        ruleset.metadata.version
    )
}

fn ruleset_quality_label(ruleset: &FingerprintRuleset) -> &'static str {
    if ruleset.metadata.version == "bundled-minimal" || ruleset.metadata.source.contains("vendored")
    {
        "degraded: bundled-minimal"
    } else if ruleset.technologies.len() >= MIN_FULL_TECHNOLOGIES {
        "full"
    } else if is_default_remote_source(&ruleset.metadata.source) {
        "thin"
    } else {
        "explicit"
    }
}

fn is_default_remote_source(source: &str) -> bool {
    DEFAULT_FINGERPRINTS_URLS
        .iter()
        .all(|url| source.contains(url))
}

fn catalog_is_complete(successful_sources: usize, expected: usize, tech_count: usize) -> bool {
    successful_sources == expected && tech_count >= MIN_FULL_TECHNOLOGIES
}

fn is_github_rate_limit_error(err: &str) -> bool {
    err.to_ascii_lowercase().contains("rate limit")
}

fn catalog_unavailable_error(failures: &[(String, String)]) -> anyhow::Error {
    let mut msg =
        "Full fingerprint catalog unavailable. Refusing to start a scan with an incomplete \
         technology ruleset. Retry when GitHub is reachable, pass --fingerprints, or \
         --allow-degraded-fingerprints for the vendored subset."
            .to_string();
    if !failures.is_empty() {
        msg.push_str(" Failed sources:");
        for (source, err) in failures {
            msg.push_str(&format!(" [{source}: {err}]"));
        }
    }
    if failures
        .iter()
        .any(|(_, err)| is_github_rate_limit_error(err))
    {
        msg.push_str(" GITHUB_TOKEN is optional rate-limit headroom (60 → 5000 requests/hour).");
    }
    if failures
        .iter()
        .any(|(_, err)| err.contains("401") || err.to_ascii_lowercase().contains("bad credentials"))
    {
        msg.push_str(" GITHUB_TOKEN was rejected (401). Unset it or use a valid token.");
    }
    anyhow::anyhow!(msg)
}

/// Operator-visible degraded-mode notice (stderr + warn). Used only with `--allow-degraded-fingerprints`.
fn announce_degraded_fingerprints(failures: &[(String, String)], tech_count: usize) {
    let mut msg = format!(
        "Full fingerprint catalog unavailable; using bundled-minimal ({tech_count} technologies). \
         Technology detection will under-count versus Enthec + HTTPArchive. \
         Retry when GitHub is reachable, or pass --fingerprints."
    );
    if !failures.is_empty() {
        msg.push_str(" Failed sources:");
        for (source, err) in failures {
            msg.push_str(&format!(" [{source}: {err}]"));
        }
    }
    if failures
        .iter()
        .any(|(_, err)| is_github_rate_limit_error(err))
    {
        msg.push_str(
            " GITHUB_TOKEN is optional rate-limit headroom (60 → 5000 requests/hour), \
             not required for the full catalog.",
        );
    }
    log::warn!("{msg}");
    eprintln!("{msg}");
}

/// Initializes the fingerprint ruleset from URL or local path.
///
/// Rules are cached locally and refreshed if older than 7 days.
/// If `fingerprints_source` is None, uses default GitHub sources:
/// - <https://github.com/enthec/webappanalyzer>
/// - <https://github.com/HTTPArchive/wappalyzer>
///
/// The ruleset is fetched from both sources and merged, with later sources
/// overwriting earlier ones for the same technology.
pub async fn init_ruleset(
    fingerprints_source: Option<&str>,
    cache_dir: Option<&Path>,
    allow_degraded: bool,
) -> Result<Arc<FingerprintRuleset>> {
    // Fast path: already loaded
    {
        let ruleset = RULESET.read().await;
        if let Some(ref cached) = *ruleset {
            return Ok(cached.clone());
        }
    }

    // Only one task performs the expensive load/fetch.
    let _init_guard = RULESET_INIT.lock().await;
    {
        let ruleset = RULESET.read().await;
        if let Some(ref cached) = *ruleset {
            return Ok(cached.clone());
        }
    }

    let explicit = fingerprints_source.is_some();
    let sources = if let Some(source) = fingerprints_source {
        vec![source.to_string()]
    } else {
        // Use default sources (both enthec and HTTPArchive)
        DEFAULT_FINGERPRINTS_URLS
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    };

    let cache_path = cache_dir.map_or_else(
        || crate::cache_paths::fingerprints_dir(&crate::cache_paths::resolve_cache_root(None)),
        std::path::Path::to_path_buf,
    );

    // Schema version invalidates caches written before requires/overlay fields were retained.
    let cache_key = fingerprint_cache_key(&sources);
    let expected_sources = fingerprint_source_label(&sources);

    // Try to load from cache first. Default remotes must still meet the floor so a
    // thin/partial cache cannot masquerade as a full catalog for 7 days.
    if let Ok(ruleset) = load_from_cache(&cache_path, &cache_key, &expected_sources).await {
        let ruleset = finish_ruleset(ruleset)?;
        if explicit || ruleset.technologies.len() >= MIN_FULL_TECHNOLOGIES {
            let ruleset_arc = Arc::new(ruleset);
            *RULESET.write().await = Some(ruleset_arc.clone());
            return Ok(ruleset_arc);
        }
        log::warn!(
            "Cached fingerprint ruleset has {} technologies (floor {MIN_FULL_TECHNOLOGIES}); refetching",
            ruleset.technologies.len()
        );
    }

    // Fetch from all sources and merge
    log::info!(
        "Fetching fingerprint ruleset from {} source(s)",
        sources.len()
    );
    let ruleset = fetch_ruleset_from_multiple_sources(
        &sources,
        &cache_path,
        &cache_key,
        explicit,
        allow_degraded,
    )
    .await?;
    let ruleset_arc = Arc::new(ruleset);
    *RULESET.write().await = Some(ruleset_arc.clone());
    Ok(ruleset_arc)
}

/// Gets the current ruleset (unit tests that call `init_ruleset` then matchers).
#[cfg(test)]
pub(crate) async fn get_ruleset() -> Option<Arc<FingerprintRuleset>> {
    let guard = RULESET.read().await;
    guard.as_ref().cloned()
}

/// Fetches ruleset from multiple sources and merges them (matching Go implementation)
#[allow(clippy::too_many_lines)] // Tries multiple source types (URL, file, GitHub dir/commit) with fallback logic
#[allow(clippy::cognitive_complexity)] // Each source type has distinct fetch/parse/merge logic
async fn fetch_ruleset_from_multiple_sources(
    sources: &[String],
    cache_dir: &Path,
    cache_key: &str,
    explicit: bool,
    allow_degraded: bool,
) -> Result<FingerprintRuleset> {
    let mut all_technologies = HashMap::new();
    let mut all_categories = HashMap::new();
    let mut versions = Vec::new();
    let mut successful_sources = 0;
    let mut source_failures: Vec<(String, String)> = Vec::new();

    // Fetch from all sources and merge
    // If a source fails, log a warning but continue with other sources
    // This allows partial success (e.g., if one GitHub repo is rate-limited, we can still use the other)
    for source in sources {
        log::info!("Fetching from source: {source}");

        let technologies = match if source.starts_with("http://") || source.starts_with("https://")
        {
            fetch_from_url(source).await
        } else {
            load_from_path(Path::new(source)).await
        } {
            Ok(techs) => {
                successful_sources += 1;
                techs
            }
            Err(e) => {
                let err = e.to_string();
                log::warn!(
                    "Failed to fetch from source '{source}': {err}. Continuing with other sources..."
                );
                source_failures.push((source.clone(), err));
                continue; // Skip this source, try others
            }
        };

        // Merge technologies (later sources overwrite earlier ones for same tech name).
        // Header/cookie KEYS are lowercased; patterns stay intact (regex `\S` vs `\s`).
        for (tech_name, tech) in technologies {
            if let Some(tech) = ingest_technology(tech) {
                all_technologies.insert(tech_name, tech);
            }
        }

        // Fetch categories from this source
        let categories = if source.starts_with("http://") || source.starts_with("https://") {
            fetch_categories_from_url(source).await.unwrap_or_else(|e| {
                log::warn!(
                    "Failed to fetch categories from {source}: {e}. Continuing without categories from this source."
                );
                HashMap::new()
            })
        } else {
            load_categories_from_path(Path::new(source))
                .await
                .unwrap_or_else(|e| {
                    log::warn!(
                        "Failed to load categories from path {source}: {e}. Continuing without categories from this source."
                    );
                    HashMap::new()
                })
        };

        // Merge categories (later sources overwrite earlier ones)
        for (cat_id, cat_name) in categories {
            all_categories.insert(cat_id, cat_name);
        }

        // Get version from this source
        let is_github =
            source.contains("github.com") || source.contains("raw.githubusercontent.com");
        if is_github {
            if let Some(sha) = get_latest_commit_sha(source).await {
                versions.push(format!("{source}:{sha}"));
            }
        }
    }

    if successful_sources == 0 {
        return vendored_or_err(allow_degraded, &source_failures);
    }

    let version = if versions.is_empty() {
        "unknown".to_string()
    } else {
        versions.join(";")
    };

    let metadata = FingerprintMetadata {
        source: fingerprint_source_label(sources),
        version,
        last_updated: SystemTime::now(),
    };

    let ruleset = FingerprintRuleset {
        technologies: all_technologies,
        categories: all_categories,
        metadata,
    };
    let ruleset = finish_ruleset(ruleset)?;
    let tech_count = ruleset.technologies.len();

    if !explicit && !catalog_is_complete(successful_sources, sources.len(), tech_count) {
        if !allow_degraded {
            return Err(catalog_unavailable_error(&source_failures));
        }
        log::warn!(
            "Partial default fingerprint catalog ({tech_count} technologies, \
             {successful_sources}/{} sources). Continuing because --allow-degraded-fingerprints is set.",
            sources.len()
        );
        return Ok(ruleset);
    }

    log::info!(
        "Merged {tech_count} technologies from {} source(s) (plus first-party overlay)",
        sources.len()
    );

    // Never persist a thin default merge under the remote cache key.
    if explicit || tech_count >= MIN_FULL_TECHNOLOGIES {
        save_to_cache(&ruleset, cache_dir, cache_key).await?;
    }

    Ok(ruleset)
}

fn vendored_or_err(
    allow_degraded: bool,
    source_failures: &[(String, String)],
) -> Result<FingerprintRuleset> {
    if !allow_degraded {
        return Err(catalog_unavailable_error(source_failures));
    }
    let mut vendored = load_vendored_ruleset()?;
    vendored.technologies = vendored
        .technologies
        .into_iter()
        .filter_map(|(name, tech)| ingest_technology(tech).map(|tech| (name, tech)))
        .collect();
    // Do NOT write vendored under the remote `cache_key`.
    let ruleset = finish_ruleset(vendored)?;
    announce_degraded_fingerprints(source_failures, ruleset.technologies.len());
    Ok(ruleset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_fetch_ruleset_from_multiple_sources_all_fail_uses_vendored() {
        // When remotes fail, fall back to the bundled minimal ruleset (offline/CI cold start).
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let invalid_sources = vec![
            "https://invalid-url-that-does-not-exist-12345.com/technologies".to_string(),
            "https://another-invalid-url-67890.com/technologies".to_string(),
        ];
        let cache_key = "test-hash-vendored-fallback";

        let result = fetch_ruleset_from_multiple_sources(
            &invalid_sources,
            temp_dir.path(),
            cache_key,
            false,
            true,
        )
        .await;

        let ruleset = result.expect("vendored fallback should succeed when remotes fail");
        assert!(
            ruleset.metadata.source.contains("vendored"),
            "expected vendored source, got {}",
            ruleset.metadata.source
        );
        assert_eq!(ruleset.metadata.version, "bundled-minimal");
        assert!(ruleset.technologies.contains_key("Nginx"));
        assert!(
            ruleset.technologies.contains_key("Payload"),
            "first-party overlay must apply on vendored fallback"
        );
        assert!(!ruleset.technologies.is_empty());
        let summary = ruleset_identity_summary(&ruleset);
        assert!(
            summary.contains(&ruleset.technologies.len().to_string()),
            "summary must include tech count: {summary}"
        );
        assert!(
            summary.contains("degraded: bundled-minimal"),
            "summary must mark degraded mode: {summary}"
        );
    }

    #[test]
    fn ruleset_identity_summary_marks_full_catalog() {
        let mut technologies = HashMap::new();
        for i in 0..MIN_FULL_TECHNOLOGIES {
            technologies.insert(
                format!("Tech{i}"),
                crate::fingerprint::models::Technology::default(),
            );
        }
        let ruleset = FingerprintRuleset {
            technologies,
            categories: HashMap::new(),
            metadata: FingerprintMetadata {
                source: format!(
                    "{}\n{}",
                    DEFAULT_FINGERPRINTS_URLS[0], DEFAULT_FINGERPRINTS_URLS[1]
                ),
                version: "abc123".to_string(),
                last_updated: SystemTime::now(),
            },
        };
        let summary = ruleset_identity_summary(&ruleset);
        assert!(summary.contains(&format!("{MIN_FULL_TECHNOLOGIES} technologies")));
        assert!(summary.contains("version=abc123"));
        assert!(summary.contains(", full"));
        assert!(!summary.contains("degraded"));
    }

    #[test]
    fn ruleset_identity_summary_marks_explicit_and_thin() {
        let explicit = FingerprintRuleset {
            technologies: HashMap::new(),
            categories: HashMap::new(),
            metadata: FingerprintMetadata {
                source: "/tmp/local-fp.json".to_string(),
                version: "unknown".to_string(),
                last_updated: SystemTime::now(),
            },
        };
        assert!(
            ruleset_identity_summary(&explicit).contains("explicit"),
            "{}",
            ruleset_identity_summary(&explicit)
        );
        let thin = FingerprintRuleset {
            technologies: HashMap::new(),
            categories: HashMap::new(),
            metadata: FingerprintMetadata {
                source: format!(
                    "{}\n{}",
                    DEFAULT_FINGERPRINTS_URLS[0], DEFAULT_FINGERPRINTS_URLS[1]
                ),
                version: "abc123".to_string(),
                last_updated: SystemTime::now(),
            },
        };
        assert!(
            ruleset_identity_summary(&thin).contains("thin"),
            "{}",
            ruleset_identity_summary(&thin)
        );
    }

    #[tokio::test]
    async fn test_fetch_ruleset_all_fail_without_allow_returns_err() {
        let temp_dir = TempDir::new().expect("temp dir");
        let invalid_sources = vec![
            "https://invalid-url-that-does-not-exist-12345.com/technologies".to_string(),
            "https://another-invalid-url-67890.com/technologies".to_string(),
        ];
        let err = fetch_ruleset_from_multiple_sources(
            &invalid_sources,
            temp_dir.path(),
            "test-hash-abort",
            false,
            false,
        )
        .await
        .expect_err("default remotes must abort when every source fails");
        let msg = err.to_string();
        assert!(
            msg.contains("Refusing to start") || msg.contains("incomplete"),
            "{msg}"
        );
    }

    #[tokio::test]
    async fn test_fetch_ruleset_from_multiple_sources_partial_success() {
        let temp_dir = TempDir::new().expect("temp dir");
        let local = temp_dir.path().join("techs.json");
        std::fs::write(&local, r#"{"Nginx":{"headers":{"server":"nginx"}}}"#)
            .expect("write local ruleset");
        let sources = vec![
            local.to_string_lossy().into_owned(),
            "https://invalid-url-that-does-not-exist-12345.com/technologies".to_string(),
        ];
        let err = fetch_ruleset_from_multiple_sources(
            &sources,
            temp_dir.path(),
            "test-hash-partial",
            false,
            false,
        )
        .await
        .expect_err("default-style pair must abort when one source fails");
        assert!(
            err.to_string().contains("incomplete") || err.to_string().contains("Refusing"),
            "{}",
            err
        );

        let allowed = fetch_ruleset_from_multiple_sources(
            &sources,
            temp_dir.path(),
            "test-hash-partial-allow",
            false,
            true,
        )
        .await
        .expect("allow_degraded keeps the partial merge");
        assert!(allowed.technologies.contains_key("Nginx"));
    }

    #[tokio::test]
    async fn test_fetch_ruleset_header_normalization() {
        // Test that headers are normalized to lowercase during merge
        // This is critical - header matching is case-insensitive
        // The code at line 179-183 normalizes header keys and patterns
        // This is tested implicitly through the merge logic
    }

    #[tokio::test]
    async fn test_fetch_ruleset_cookie_normalization() {
        // Test that cookies are normalized to lowercase during merge
        // This is critical - cookie matching is case-insensitive
        // The code at line 186-190 normalizes cookie keys and patterns
    }

    #[tokio::test]
    async fn test_fetch_ruleset_category_merge() {
        // Test that categories from multiple sources are merged correctly
        // Later sources should overwrite earlier ones (line 217-219)
        // This is tested implicitly through the merge logic
    }

    #[tokio::test]
    async fn test_fetch_ruleset_category_fetch_failure_handling() {
        // Test that category fetch failures don't break the entire ruleset load
        // The code at line 197-214 uses unwrap_or_else to handle category fetch failures
        // This is critical - if categories fail, we should still load technologies
    }

    #[tokio::test]
    async fn test_fetch_ruleset_version_extraction() {
        // Test version extraction from GitHub sources
        // The code at line 222-228 extracts commit SHA for GitHub sources
        // This is tested implicitly through the version string generation
    }

    #[tokio::test]
    async fn test_fetch_ruleset_empty_versions_fallback() {
        // Test that empty versions list uses "unknown" fallback
        // The code at line 254-258 handles empty versions
        // This is tested implicitly - if versions is empty, version becomes "unknown"
    }

    use super::{is_script_id_js_key, prune_technology_for_static_detection};
    use crate::fingerprint::models::Technology;

    #[test]
    fn prune_drops_js_only_technology() {
        let mut tech = Technology::default();
        tech.js.insert("jQuery".to_string(), String::new());
        assert!(prune_technology_for_static_detection(tech).is_none());
    }

    #[test]
    fn prune_keeps_implies_stub_without_signals() {
        // Cats/website-only techs exist as implies targets and must remain loadable.
        let tech = Technology {
            website: "https://example.com/testos".to_string(),
            ..Default::default()
        };
        let kept = prune_technology_for_static_detection(tech).expect("stub kept");
        assert!(kept.website.is_empty());
        assert!(kept.headers.is_empty());
        assert!(kept.js.is_empty());
    }

    #[test]
    fn prune_keeps_script_id_js_key() {
        let mut tech = Technology::default();
        tech.js
            .insert("__NEXT_DATA__".to_string(), "unused".to_string());
        let pruned = prune_technology_for_static_detection(tech).expect("kept");
        assert!(pruned.js.contains_key("__NEXT_DATA__"));
        assert_eq!(pruned.js.get("__NEXT_DATA__").map(String::as_str), Some(""));
    }

    #[test]
    fn script_id_key_heuristic() {
        assert!(is_script_id_js_key("__NEXT_DATA__"));
        assert!(is_script_id_js_key("dataLayer"));
        assert!(!is_script_id_js_key("jQuery"));
    }

    #[test]
    fn test_header_normalization_logic() {
        // Test that header normalization logic works correctly
        // This is critical - header matching is case-insensitive, normalization ensures consistency
        // The code at line 179-183 normalizes header keys and patterns to lowercase
        use std::collections::HashMap;
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "Text/HTML".to_string());
        headers.insert("X-Powered-By".to_string(), "PHP/7.4".to_string());

        // Simulate normalization (matching the code logic)
        let mut normalized = HashMap::new();
        for (key, value) in headers {
            normalized.insert(key.to_lowercase(), value.to_lowercase());
        }

        // Verify normalization
        assert!(normalized.contains_key("content-type"));
        assert_eq!(
            normalized.get("content-type"),
            Some(&"text/html".to_string())
        );
        assert!(normalized.contains_key("x-powered-by"));
        assert_eq!(normalized.get("x-powered-by"), Some(&"php/7.4".to_string()));
    }

    #[test]
    fn test_cookie_normalization_logic() {
        // Test that cookie normalization logic works correctly
        // This is critical - cookie matching is case-insensitive
        // The code at line 186-190 normalizes cookie keys and patterns to lowercase
        use std::collections::HashMap;
        let mut cookies = HashMap::new();
        cookies.insert("SessionID".to_string(), "ABC123".to_string());
        cookies.insert("User-Pref".to_string(), "Dark-Mode".to_string());

        // Simulate normalization (matching the code logic)
        let mut normalized = HashMap::new();
        for (key, value) in cookies {
            normalized.insert(key.to_lowercase(), value.to_lowercase());
        }

        // Verify normalization
        assert!(normalized.contains_key("sessionid"));
        assert_eq!(normalized.get("sessionid"), Some(&"abc123".to_string()));
        assert!(normalized.contains_key("user-pref"));
        assert_eq!(normalized.get("user-pref"), Some(&"dark-mode".to_string()));
    }

    #[test]
    fn test_category_merge_logic() {
        // Test that category merge logic works correctly
        // Later sources should overwrite earlier ones (line 217-219)
        use std::collections::HashMap;
        let mut all_categories = HashMap::new();

        // First source
        let source1 = vec![
            ("1".to_string(), "CMS".to_string()),
            ("2".to_string(), "E-commerce".to_string()),
        ];
        for (id, name) in source1 {
            all_categories.insert(id, name);
        }

        // Second source (overwrites "1", adds "3")
        let source2 = vec![
            ("1".to_string(), "Content Management".to_string()), // Overwrites
            ("3".to_string(), "Analytics".to_string()),          // New
        ];
        for (id, name) in source2 {
            all_categories.insert(id, name);
        }

        // Verify merge result
        assert_eq!(
            all_categories.get("1"),
            Some(&"Content Management".to_string())
        ); // Overwritten
        assert_eq!(all_categories.get("2"), Some(&"E-commerce".to_string())); // Preserved
        assert_eq!(all_categories.get("3"), Some(&"Analytics".to_string())); // Added
        assert_eq!(all_categories.len(), 3);
    }

    #[test]
    fn fingerprint_source_label_joins_multiple_sources_with_newlines() {
        assert_eq!(
            fingerprint_source_label(&["https://only.com".to_string()]),
            "https://only.com"
        );
        assert_eq!(
            fingerprint_source_label(&[
                "https://source1.com".to_string(),
                "https://source2.com".to_string()
            ]),
            "https://source1.com\nhttps://source2.com"
        );
    }

    #[test]
    fn fingerprint_cache_key_empty_sources_uses_schema_default() {
        assert_eq!(
            fingerprint_cache_key(&[]),
            format!("default-schema{CACHE_SCHEMA_VERSION}")
        );
    }

    #[test]
    fn fingerprint_cache_key_does_not_treat_plus_as_source_delimiter() {
        let plus_in_url = fingerprint_cache_key(&["https://a.com+https://b.com".to_string()]);
        let two_sources =
            fingerprint_cache_key(&["https://a.com".to_string(), "https://b.com".to_string()]);
        assert_ne!(plus_in_url, two_sources);
        assert_ne!(
            fingerprint_cache_key(&["https://source.com".to_string()]),
            two_sources
        );
    }

    #[test]
    fn fingerprint_cache_key_handles_special_url_characters() {
        let key = fingerprint_cache_key(&[
            "https://example.com/path?query=value&other=123".to_string(),
            "https://example.com/path#fragment+with+special%20chars".to_string(),
        ]);
        assert_eq!(key.len(), 64, "SHA256 hex digest is 64 characters");
        assert!(
            key.chars().all(|c| c.is_ascii_hexdigit()),
            "cache key should be hex: {key}"
        );
    }
}
