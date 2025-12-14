//! Technology detection using community-maintained fingerprint rulesets.
//!
//! This module implements technology detection by fetching and applying
//! fingerprint rules from community sources like HTTP Archive or Enthec.
//! Rules are cached locally and can be updated periodically.
//!
//! # Pattern Matching
//!
//! Technology detection matches patterns against:
//! - HTTP headers (Server, X-Powered-By, etc.)
//! - Cookies
//! - Meta tags (name, property, http-equiv)
//! - Script source URLs (from HTML, not fetched)
//! - HTML text content
//! - URL patterns
//! - Script tag IDs (e.g., `__NEXT_DATA__` for Next.js)
//!
//! **Note:** We match WappalyzerGo's behavior - we do NOT execute JavaScript
//! or fetch external scripts. We only analyze the initial HTML response.

mod detection;
mod js_parsing;
mod models;
mod patterns;
mod ruleset;

// Re-export public API
#[allow(unused_imports)] // These are public API re-exports, even if not used in tests
pub use detection::{detect_technologies, get_technology_category, DetectedTechnology};
#[allow(unused_imports)] // These are public API re-exports, even if not used in tests
pub use models::{FingerprintMetadata, FingerprintRuleset, Technology};
#[allow(unused_imports)] // These are public API re-exports, even if not used in tests
pub use ruleset::{get_ruleset_metadata, init_ruleset};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::js_parsing::strip_js_comments_and_strings;
    use crate::fingerprint::patterns::matches_pattern;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    use std::collections::{HashMap, HashSet};

    #[allow(dead_code)]
    fn create_test_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("server"),
            HeaderValue::from_static("nginx/1.18.0"),
        );
        headers.insert(
            HeaderName::from_static("x-powered-by"),
            HeaderValue::from_static("PHP/7.4"),
        );
        headers
    }

    #[tokio::test]
    async fn test_pattern_matching() {
        assert!(matches_pattern("nginx", "nginx/1.18.0").matched);
        assert!(matches_pattern("", "anything").matched);
        assert!(!matches_pattern("apache", "nginx/1.18.0").matched);
    }

    #[test]
    fn test_strip_js_comments_and_strings() {
        // Test comment stripping
        let code = r#"var x = 1; // websiteMaximumSuggestFundiinWithPrediction
        var y = 2; /* lz_chat_execute */"#;
        let stripped = strip_js_comments_and_strings(code);
        assert!(!stripped.contains("websiteMaximumSuggestFundiinWithPrediction"));
        assert!(!stripped.contains("lz_chat_execute"));

        // Test string stripping
        let code2 = r#"var x = "websiteMaximumSuggestFundiinWithPrediction";
        var y = 'lz_chat_execute';"#;
        let stripped2 = strip_js_comments_and_strings(code2);
        assert!(!stripped2.contains("websiteMaximumSuggestFundiinWithPrediction"));
        assert!(!stripped2.contains("lz_chat_execute"));

        // Test that actual code is preserved
        let code3 = r#"window.websiteMaximumSuggestFundiinWithPrediction = true;
        var lz_chat_execute = function() {};"#;
        let stripped3 = strip_js_comments_and_strings(code3);
        assert!(stripped3.contains("websiteMaximumSuggestFundiinWithPrediction"));
        assert!(stripped3.contains("lz_chat_execute"));
    }

    #[tokio::test]
    async fn test_detect_technologies_empty() {
        // This test verifies behavior with empty input
        // In CI, the ruleset may be initialized by other tests
        let meta_tags = HashMap::new();
        let script_sources = Vec::new();
        let script_content = "";
        let html_text = "";
        let headers = HeaderMap::new();
        let url = "https://example.com";

        let script_tag_ids = HashSet::new();
        let normalized_body = html_text.to_lowercase(); // Normalize for HTML pattern matching
        let result = detect_technologies(
            &meta_tags,
            &script_sources,
            script_content,
            &normalized_body, // Use normalized body
            &headers,
            url,
            &script_tag_ids,
        )
        .await;

        // Ruleset may be initialized by other tests, so both success and error are valid
        match result {
            Ok(detected) => {
                // Ruleset is initialized - should return empty set for empty input
                assert!(
                    detected.is_empty(),
                    "Empty input should return empty detection"
                );
            }
            Err(_) => {
                // Ruleset not initialized - this is expected in unit test context
            }
        }
    }
}
