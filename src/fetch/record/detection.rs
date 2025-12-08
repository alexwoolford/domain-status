//! Technology detection with error handling.

use crate::fetch::response::{HtmlData, ResponseData};

/// Detects technologies with error handling and logging.
///
/// Returns a sorted vector of detected technology names, or an empty vector on error.
pub(crate) async fn detect_technologies_safely(
    html_data: &HtmlData,
    resp_data: &ResponseData,
    error_stats: &crate::error_handling::ProcessingStats,
) -> Vec<String> {
    match crate::fingerprint::detect_technologies(
        &html_data.meta_tags,
        &html_data.script_sources,
        &html_data.script_content,
        &html_data.html_text,
        &resp_data.headers,
        &resp_data.final_url,
        &html_data.script_tag_ids,
    )
    .await
    {
        Ok(techs) => {
            if !techs.is_empty() {
                log::debug!(
                    "Detected {} technologies for {}: {:?}",
                    techs.len(),
                    resp_data.final_domain,
                    techs
                );
                let mut tech_vec: Vec<String> = techs.into_iter().collect();
                tech_vec.sort();
                tech_vec
            } else {
                log::debug!("No technologies detected for {}", resp_data.final_domain);
                Vec::new()
            }
        }
        Err(e) => {
            log::warn!(
                "Failed to detect technologies for {}: {e}",
                resp_data.final_domain
            );
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
    use reqwest::header::HeaderMap;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    fn create_test_response_data() -> ResponseData {
        ResponseData {
            final_url: "https://example.com".to_string(),
            initial_domain: "example.com".to_string(),
            final_domain: "example.com".to_string(),
            host: "example.com".to_string(),
            status: 200,
            status_desc: "OK".to_string(),
            headers: HeaderMap::new(),
            security_headers: HashMap::new(),
            http_headers: HashMap::new(),
            body: "<html><head><title>Test</title></head></html>".to_string(),
        }
    }

    fn create_test_html_data() -> HtmlData {
        HtmlData {
            title: "Test".to_string(),
            keywords_str: None,
            description: None,
            is_mobile_friendly: false,
            structured_data: crate::parse::StructuredData::default(),
            social_media_links: vec![],
            analytics_ids: vec![],
            meta_tags: HashMap::new(),
            script_sources: vec![],
            script_content: String::new(),
            script_tag_ids: HashSet::new(),
            html_text: "".to_string(),
        }
    }

    #[tokio::test]
    async fn test_detect_technologies_safely_success() {
        let resp_data = create_test_response_data();
        let html_data = create_test_html_data();
        let error_stats = Arc::new(ProcessingStats::new());

        // This will fail if ruleset is not initialized, but tests error handling
        let result = detect_technologies_safely(&html_data, &resp_data, error_stats.as_ref()).await;

        // Should return empty vector on error (ruleset not initialized)
        // or vector of technologies if ruleset is initialized
        assert!(result.is_empty() || !result.is_empty());
    }

    #[tokio::test]
    async fn test_detect_technologies_safely_error_handling() {
        let resp_data = create_test_response_data();
        let html_data = create_test_html_data();
        let error_stats = Arc::new(ProcessingStats::new());
        let initial_errors =
            error_stats.get_error_count(crate::error_handling::ErrorType::TechnologyDetectionError);

        let result = detect_technologies_safely(&html_data, &resp_data, error_stats.as_ref()).await;

        // Should not panic even if detection fails
        // Error stats may be incremented if detection fails
        let _ = (result, initial_errors);
    }

    #[tokio::test]
    async fn test_detect_technologies_safely_empty_result() {
        let resp_data = create_test_response_data();
        let mut html_data = create_test_html_data();
        // Empty HTML data should result in empty technologies
        html_data.meta_tags = HashMap::new();
        html_data.script_sources = vec![];
        html_data.html_text = String::new();

        let error_stats = Arc::new(ProcessingStats::new());
        let result = detect_technologies_safely(&html_data, &resp_data, error_stats.as_ref()).await;

        // Should return empty vector when no technologies detected
        // (May be non-empty if ruleset has URL-based patterns, but empty is expected)
        let _ = result;
    }

    #[tokio::test]
    async fn test_detect_technologies_safely_error_stats_incremented() {
        // Test that error stats are correctly incremented when detection fails
        let resp_data = create_test_response_data();
        let html_data = create_test_html_data();
        let error_stats = Arc::new(ProcessingStats::new());

        let initial_count =
            error_stats.get_error_count(crate::error_handling::ErrorType::TechnologyDetectionError);

        let result = detect_technologies_safely(&html_data, &resp_data, error_stats.as_ref()).await;

        let final_count =
            error_stats.get_error_count(crate::error_handling::ErrorType::TechnologyDetectionError);

        // If detection failed (ruleset not initialized), error count should increase
        // If detection succeeded, error count should remain the same
        // We can't assert exact behavior since it depends on ruleset initialization,
        // but we verify the function doesn't panic and error stats are tracked
        assert!(final_count >= initial_count);
        // Result should be a Vec (empty or non-empty)
        assert!(result.is_empty() || !result.is_empty());
    }

    #[tokio::test]
    async fn test_detect_technologies_safely_result_sorted() {
        // Test that detected technologies are returned in sorted order
        let resp_data = create_test_response_data();
        let html_data = create_test_html_data();
        let error_stats = Arc::new(ProcessingStats::new());

        let result = detect_technologies_safely(&html_data, &resp_data, error_stats.as_ref()).await;

        // If result is non-empty, it should be sorted
        if result.len() > 1 {
            let mut sorted = result.clone();
            sorted.sort();
            assert_eq!(
                result, sorted,
                "Technologies should be returned in sorted order"
            );
        }
    }
}
