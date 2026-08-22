//! Technology detection with error handling.

use std::sync::Arc;

use crate::fetch::response::{HtmlData, ResponseData};
use crate::fingerprint::FingerprintRuleset;

/// Detects technologies with error handling and logging.
/// Runs CPU-bound regex matching on a blocking thread to avoid starving the async executor.
///
/// Returns a vector of detected technologies with name and optional version.
pub(crate) async fn detect_technologies_safely(
    html_data: &HtmlData,
    resp_data: &ResponseData,
    error_stats: &crate::error_handling::ProcessingStats,
    ruleset: &Arc<FingerprintRuleset>,
) -> Vec<crate::fingerprint::DetectedTechnology> {
    // Clone data for use inside spawn_blocking (closure must own values).
    // Body lowercasing (wappalyzergo-compatible) is CPU/alloc-heavy on large
    // HTML — keep it inside spawn_blocking with the regex work.
    let ruleset = Arc::clone(ruleset);
    let headers = resp_data.headers.clone();
    let meta_tags = html_data.meta_tags.clone();
    let script_sources = html_data.script_sources.clone();
    let url = resp_data.final_url.clone();
    let script_tag_ids = html_data.script_tag_ids.clone();
    let inline_script_text = html_data.inline_script_text.clone();
    let body = Arc::clone(&resp_data.body);

    // Run CPU-bound regex work on blocking thread pool to avoid executor starvation.
    let result = tokio::task::spawn_blocking(move || {
        let normalized_body = body.to_lowercase();
        crate::fingerprint::detect_technologies_blocking(
            &ruleset,
            &headers,
            &meta_tags,
            &script_sources,
            &normalized_body,
            &url,
            &script_tag_ids,
            &inline_script_text,
        )
    })
    .await
    // `JoinError` -> `FingerprintError::DetectionTaskJoin` via `#[from]`.
    .map_err(crate::error_handling::FingerprintError::from)
    .and_then(|r| r);

    match result {
        Ok(techs) => {
            if techs.is_empty() {
                log::debug!("No technologies detected for {}", resp_data.final_domain);
                Vec::new()
            } else {
                log::debug!(
                    "Detected {} technologies for {}",
                    techs.len(),
                    resp_data.final_domain
                );
                techs
            }
        }
        Err(e) => {
            match &e {
                crate::error_handling::FingerprintError::RulesetNotInitialized => {
                    log::warn!(
                        "Technology detection skipped for {}: {}",
                        resp_data.final_domain,
                        e
                    );
                }
                crate::error_handling::FingerprintError::DetectionTaskJoin(_) => {
                    log::warn!(
                        "Failed to detect technologies for {}: {}",
                        resp_data.final_domain,
                        e
                    );
                }
            }
            error_stats.increment_error(crate::error_handling::ErrorType::TechnologyDetectionError);
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ProcessingStats;
    use crate::fetch::response::{HtmlData, ResponseData};
    use crate::fingerprint::{FingerprintMetadata, FingerprintRuleset, Technology};
    use reqwest::header::{HeaderMap, HeaderValue};
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::time::SystemTime;

    fn create_test_response_data() -> ResponseData {
        ResponseData {
            initial_url: "https://example.com".to_string(),
            final_url: "https://example.com".to_string(),
            initial_domain: "example.com".to_string(),
            final_domain: "example.com".to_string(),
            host: "example.com".to_string(),
            status: 200,
            status_desc: "OK".to_string(),
            headers: HeaderMap::new(),
            security_headers: HashMap::new(),
            http_headers: HashMap::new(),
            body: std::sync::Arc::<str>::from("<html><head><title>Test</title></head></html>"),
            body_sha256: None,
            body_truncated: false,
            content_length: None,
            http_version: None,
            content_type: None,
        }
    }

    fn create_test_html_data() -> HtmlData {
        HtmlData {
            title: "Test".to_string(),
            description: None,
            structured_data: crate::parse::StructuredData::default(),
            social_media_links: vec![],
            contact_links: vec![],
            exposed_secrets: vec![],
            analytics_ids: vec![],
            meta_tags: HashMap::new(),
            script_sources: vec![],
            script_tag_ids: HashSet::new(),
            inline_script_text: String::new(),
            external_scripts_eligible: 0,
            external_scripts_scanned: 0,
            favicon_url: None,
            canonical_url: None,
            meta_refresh_url: None,
            meta_robots: None,
            resource_hints: Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_detect_technologies_safely_empty_ruleset() {
        let html_data = create_test_html_data();
        let resp_data = create_test_response_data();
        let error_stats = Arc::new(ProcessingStats::new());
        let ruleset = Arc::new(FingerprintRuleset::empty_for_tests());

        let result =
            detect_technologies_safely(&html_data, &resp_data, error_stats.as_ref(), &ruleset)
                .await;
        assert!(result.is_empty());
        assert_eq!(
            error_stats.get_error_count(crate::error_handling::ErrorType::TechnologyDetectionError),
            0,
            "empty ruleset is success with no detections, not an error"
        );
    }

    #[tokio::test]
    async fn test_detect_technologies_safely_fixture_ruleset_detects_header() {
        let html_data = create_test_html_data();
        let mut resp_data = create_test_response_data();
        resp_data
            .headers
            .insert("Server", HeaderValue::from_static("nginx/1.24.0"));

        let mut tech = Technology::default();
        // Ruleset header keys are lowercase (normalized on load).
        tech.headers.insert(
            "server".to_string(),
            "nginx(?:/([\\d.]+))?\\;version:\\1".to_string(),
        );
        let mut technologies = HashMap::new();
        technologies.insert("Nginx".to_string(), tech);
        let ruleset = Arc::new(FingerprintRuleset {
            technologies,
            categories: HashMap::new(),
            metadata: FingerprintMetadata {
                source: "test".into(),
                version: "0".into(),
                last_updated: SystemTime::now(),
            },
        });

        let error_stats = Arc::new(ProcessingStats::new());
        let result =
            detect_technologies_safely(&html_data, &resp_data, error_stats.as_ref(), &ruleset)
                .await;

        assert_eq!(result.len(), 1, "expected Nginx, got {result:?}");
        assert_eq!(result[0].name, "Nginx");
        assert_eq!(result[0].version.as_deref(), Some("1.24.0"));
        assert!(!result[0].is_implied);
    }
}
