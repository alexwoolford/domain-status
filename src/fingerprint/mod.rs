//! Technology detection using community-maintained fingerprint rulesets.
//!
//! This module implements technology detection by fetching and applying
//! fingerprint rules from community sources like HTTP Archive or Enthec.
//! Rules are cached locally and can be updated periodically.
//!
//! # Pattern Matching
//!
//! Technology detection matches patterns against static evidence only
//! (no JavaScript execution — see ADR 0005):
//! - HTTP headers (Server, X-Powered-By, etc.)
//! - Cookies
//! - Meta tags (name, property, http-equiv)
//! - Script source URLs from the initial HTML (not fetched)
//! - Inline `<script>` text (`scripts` patterns)
//! - HTML text content
//! - URL patterns
//! - Script tag IDs (e.g., `__NEXT_DATA__` for Next.js)
//! - DNS records and TLS certificate issuer (after DNS/TLS enrichment)
//!
//! **`--scan-external-scripts` does not feed technology detection** — it only
//! scans first-party script bodies for exposed secrets.

mod detection;
#[cfg(test)]
mod js_parsing;
mod models;
mod patterns;
mod ruleset;

// Re-export public API
#[allow(unused_imports)] // These are public API re-exports, even if not used in tests
pub use detection::{get_technology_category, DetectedTechnology};
#[allow(unused_imports)] // These are public API re-exports, even if not used in tests
pub use models::{FingerprintMetadata, FingerprintRuleset, Technology};
#[allow(unused_imports)] // These are public API re-exports, even if not used in tests
pub use ruleset::init_ruleset;

// Blocking detection for the scan hot path (ruleset passed explicitly).
pub(crate) use detection::{
    detect_technologies_blocking, dns_records_haystack, supplement_technologies_with_dns_cert,
};
// Global getter retained for unit tests that call `init_ruleset` then exercise matchers.
#[cfg(test)]
pub(crate) use ruleset::get_ruleset;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::js_parsing::strip_js_comments_and_strings;
    use crate::fingerprint::patterns::matches_pattern;
    use reqwest::header::HeaderMap;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

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

    #[test]
    fn test_detect_technologies_empty() {
        let meta_tags = HashMap::new();
        let script_sources = Vec::new();
        let html_text = "";
        let headers = HeaderMap::new();
        let url = "https://example.com";
        let script_tag_ids = HashSet::new();
        let normalized_body = html_text.to_lowercase();
        let ruleset = Arc::new(FingerprintRuleset::empty_for_tests());

        let detected = detect_technologies_blocking(
            &ruleset,
            &headers,
            &meta_tags,
            &script_sources,
            &normalized_body,
            url,
            &script_tag_ids,
            "",
        )
        .expect("empty ruleset detection should succeed");

        assert!(
            detected.is_empty(),
            "Empty input should return empty detection"
        );
    }
}
