//! Analytics and tracking ID extraction.
//!
//! This module extracts analytics and tracking IDs from HTML content and JavaScript,
//! including Google Analytics, Facebook Pixel, Google Tag Manager, and Google AdSense.

use regex::Regex;
use std::sync::LazyLock;

/// Analytics provider name constants.
///
/// These are `&'static str` constants that:
/// - Live in the binary's data section (no heap allocation)
/// - Are shared across all uses (no memory overhead)
/// - Are compile-time checked (typos caught at compile time)
/// - Improve maintainability (single source of truth)
///
/// When we need an owned `String` (e.g., for `AnalyticsId.provider`), we convert
/// these constants using `.to_string()`, but the constant itself is never allocated.
const PROVIDER_GOOGLE_ANALYTICS: &str = "Google Analytics";
const PROVIDER_GOOGLE_ANALYTICS_4: &str = "Google Analytics 4";
const PROVIDER_FACEBOOK_PIXEL: &str = "Facebook Pixel";
const PROVIDER_GOOGLE_TAG_MANAGER: &str = "Google Tag Manager";
const PROVIDER_GOOGLE_ADSENSE: &str = "Google AdSense";

/// Analytics/Tracking ID extracted from HTML/JavaScript.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AnalyticsId {
    /// Analytics provider (e.g., "Google Analytics", "Facebook Pixel", "Google Tag Manager", "AdSense")
    pub provider: String,
    /// The tracking ID (e.g., "UA-123456-1", "G-XXXXXXXXXX", "1234567890", "GTM-XXXXX")
    pub id: String,
}

/// Minimum length for a valid GTM container ID.
/// Format: GTM- followed by at least 4 uppercase alphanumeric characters = 8 total.
const MIN_GTM_ID_LENGTH: usize = 8;

/// Validates that a string is a valid Google Tag Manager container ID.
///
/// Valid GTM IDs:
/// - Start with uppercase "GTM-"
/// - Followed by uppercase letters and numbers only
/// - Minimum length of 8 characters (GTM- + at least 4 chars)
///
/// This filters out false positives like:
/// - "gtm-company" (lowercase prefix)
/// - "gtm-industry" (lowercase prefix)
/// - "GTM-" (too short)
///
/// # Arguments
///
/// * `id` - The candidate GTM ID string
///
/// # Returns
///
/// `true` if the ID is a valid GTM container ID, `false` otherwise.
fn is_valid_gtm_id(id: &str) -> bool {
    id.starts_with("GTM-")
        && id.len() >= MIN_GTM_ID_LENGTH
        && id
            .chars()
            .skip(4)
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// Helper function to safely compile a regex pattern, panicking with a detailed error message
/// if compilation fails. Used for static regex patterns that are compile-time constants.
fn compile_regex_unsafe(pattern: &str, context: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|e| {
        panic!(
            "Failed to compile regex pattern '{}' in {}: {}. This is a programming error.",
            pattern, context, e
        )
    })
}

/// Extracts analytics and tracking IDs from HTML content and JavaScript.
///
/// Searches for:
/// - Google Analytics: `ga('create', 'UA-XXXXX-Y')`, `gtag('config', 'G-XXXXXXXXXX')`
/// - Facebook Pixel: `fbq('init', 'XXXXX')`
/// - Google Tag Manager: `GTM-XXXXX` in script src or dataLayer
/// - Google AdSense: Publisher IDs in script src or data attributes
///
/// # Arguments
///
/// * `html` - The raw HTML content (including script tags)
///
/// # Returns
///
/// A vector of `AnalyticsId` structs containing provider and ID pairs.
pub fn extract_analytics_ids(html: &str) -> Vec<AnalyticsId> {
    let mut analytics_ids = Vec::new();
    let mut seen_ids = std::collections::HashSet::<(String, String)>::new();

    // Google Analytics (Universal Analytics): ga('create', 'UA-XXXXX-Y')
    // Pattern: ga('create', 'UA-XXXXX-Y') or ga("create", "UA-XXXXX-Y")
    static GA_UA_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        compile_regex_unsafe(
            r#"(?i)ga\s*\(\s*['"]create['"]\s*,\s*['"](UA-\d+-\d+)['"]"#,
            "GA_UA_PATTERN",
        )
    });
    for cap in GA_UA_PATTERN.captures_iter(html) {
        if let Some(id) = cap.get(1) {
            let id_str = id.as_str().to_string();
            let key = (PROVIDER_GOOGLE_ANALYTICS.to_string(), id_str.clone());
            if seen_ids.insert(key) {
                analytics_ids.push(AnalyticsId {
                    provider: PROVIDER_GOOGLE_ANALYTICS.to_string(),
                    id: id_str,
                });
            }
        }
    }

    // Google Analytics 4 (GA4): gtag('config', 'G-XXXXXXXXXX')
    // Pattern: gtag('config', 'G-XXXXXXXXXX') or gtag("config", "G-XXXXXXXXXX")
    static GA4_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        compile_regex_unsafe(
            r#"(?i)gtag\s*\(\s*['"]config['"]\s*,\s*['"](G-[A-Z0-9]+)['"]"#,
            "GA4_PATTERN",
        )
    });
    for cap in GA4_PATTERN.captures_iter(html) {
        if let Some(id) = cap.get(1) {
            let id_str = id.as_str().to_string();
            let key = (PROVIDER_GOOGLE_ANALYTICS_4.to_string(), id_str.clone());
            if seen_ids.insert(key) {
                analytics_ids.push(AnalyticsId {
                    provider: PROVIDER_GOOGLE_ANALYTICS_4.to_string(),
                    id: id_str,
                });
            }
        }
    }

    // Facebook Pixel: fbq('init', 'XXXXX')
    // Pattern: fbq('init', 'XXXXX') or fbq("init", "XXXXX")
    static FB_PIXEL_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        compile_regex_unsafe(
            r#"(?i)fbq\s*\(\s*['"]init['"]\s*,\s*['"](\d+)['"]"#,
            "FB_PIXEL_PATTERN",
        )
    });
    for cap in FB_PIXEL_PATTERN.captures_iter(html) {
        if let Some(id) = cap.get(1) {
            let id_str = id.as_str().to_string();
            let key = (PROVIDER_FACEBOOK_PIXEL.to_string(), id_str.clone());
            if seen_ids.insert(key) {
                analytics_ids.push(AnalyticsId {
                    provider: PROVIDER_FACEBOOK_PIXEL.to_string(),
                    id: id_str,
                });
            }
        }
    }

    // Google Tag Manager: GTM-XXXXX in various formats
    // Patterns:
    //   - 'dataLayer','GTM-XXXXX' (function call parameter)
    //   - ns.html?id=GTM-XXXXX (iframe src)
    //   - gtm.js?id=GTM-XXXXX (script src)
    //   - "tagIds":["GTM-XXXXX"] (JSON)
    //   - gtag('config', 'GTM-XXXXX') (gtag call)
    // Valid GTM container IDs: GTM- followed by uppercase letters and numbers only (typically 6-7 chars)
    // We use case-sensitive matching to avoid false positives like "gtm-company", "gtm-industry"
    static GTM_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        compile_regex_unsafe(
            r#"(?i)(?:gtm|googletagmanager|dataLayer|tagIds|gtm\.js|ns\.html)[^'"">]*['"">]?\s*[:=,]\s*['"]?(GTM-[A-Z0-9]{4,})\b"#,
            "GTM_PATTERN",
        )
    });
    for cap in GTM_PATTERN.captures_iter(html) {
        if let Some(id) = cap.get(1) {
            let id_str = id.as_str().to_string();
            // Validate: must start with uppercase GTM- and contain only uppercase letters/numbers
            // Filter out common false positives like "gtm-company", "gtm-industry", etc.
            if is_valid_gtm_id(&id_str) {
                let key = (PROVIDER_GOOGLE_TAG_MANAGER.to_string(), id_str.clone());
                if seen_ids.insert(key) {
                    analytics_ids.push(AnalyticsId {
                        provider: PROVIDER_GOOGLE_TAG_MANAGER.to_string(),
                        id: id_str,
                    });
                }
            }
        }
    }

    // Also check for standalone GTM-XXXXX patterns (fallback for edge cases)
    // This catches GTM IDs that appear without the keywords above
    // Must be uppercase GTM- followed by uppercase letters/numbers only
    static GTM_STANDALONE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        compile_regex_unsafe(r#"\b(GTM-[A-Z0-9]{4,})\b"#, "GTM_STANDALONE_PATTERN")
    });
    for cap in GTM_STANDALONE_PATTERN.captures_iter(html) {
        if let Some(id) = cap.get(1) {
            let id_str = id.as_str().to_string();
            // Validate: must start with uppercase GTM- and contain only uppercase letters/numbers
            if is_valid_gtm_id(&id_str) {
                let key = (PROVIDER_GOOGLE_TAG_MANAGER.to_string(), id_str.clone());
                if seen_ids.insert(key) {
                    analytics_ids.push(AnalyticsId {
                        provider: PROVIDER_GOOGLE_TAG_MANAGER.to_string(),
                        id: id_str,
                    });
                }
            }
        }
    }

    // Google AdSense: Publisher ID in script src
    // Pattern: ca-pub-XXXXXXXXXX or pub-XXXXXXXXXX
    // AdSense publisher IDs are typically 16 digits (e.g., pub-1234567890123456)
    // We require at least 10 digits to avoid false positives like "pub-1"
    static ADSENSE_PATTERN: LazyLock<Regex> =
        LazyLock::new(|| compile_regex_unsafe(r#"(?i)(?:ca-)?pub-(\d{10,})"#, "ADSENSE_PATTERN"));
    for cap in ADSENSE_PATTERN.captures_iter(html) {
        if let Some(id) = cap.get(1) {
            let id_str = format!("pub-{}", id.as_str());
            let key = (PROVIDER_GOOGLE_ADSENSE.to_string(), id_str.clone());
            if seen_ids.insert(key) {
                analytics_ids.push(AnalyticsId {
                    provider: PROVIDER_GOOGLE_ADSENSE.to_string(),
                    id: id_str,
                });
            }
        }
    }

    analytics_ids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_analytics_ids_google_analytics_ua() {
        let html = r#"
            <script>
                ga('create', 'UA-123456-1', 'auto');
            </script>
        "#;
        let ids = extract_analytics_ids(html);
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].provider, "Google Analytics");
        assert_eq!(ids[0].id, "UA-123456-1");
    }

    #[test]
    fn test_extract_analytics_ids_google_analytics_ua_double_quotes() {
        let html = r#"
            <script>
                ga("create", "UA-654321-2", "auto");
            </script>
        "#;
        let ids = extract_analytics_ids(html);
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].provider, "Google Analytics");
        assert_eq!(ids[0].id, "UA-654321-2");
    }

    #[test]
    fn test_extract_analytics_ids_google_analytics_4() {
        let html = r#"
            <script>
                gtag('config', 'G-ABCDEFGHIJ');
            </script>
        "#;
        let ids = extract_analytics_ids(html);
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].provider, "Google Analytics 4");
        assert_eq!(ids[0].id, "G-ABCDEFGHIJ");
    }

    #[test]
    fn test_extract_analytics_ids_facebook_pixel() {
        let html = r#"
            <script>
                fbq('init', '1234567890');
            </script>
        "#;
        let ids = extract_analytics_ids(html);
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].provider, "Facebook Pixel");
        assert_eq!(ids[0].id, "1234567890");
    }

    #[test]
    fn test_extract_analytics_ids_google_tag_manager() {
        let html = r#"
            <script>
                dataLayer = [{'gtm.start': new Date().getTime(), event: 'gtm.js'}];
                (function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':
                new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],
                j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src=
                'https://www.googletagmanager.com/gtm.js?id=GTM-XXXXX'+i+dl;f.parentNode.insertBefore(j,f);
                })(window,document,'script','dataLayer','GTM-XXXXX');
            </script>
        "#;
        let ids = extract_analytics_ids(html);
        assert!(!ids.is_empty());
        assert!(ids
            .iter()
            .any(|id| id.provider == "Google Tag Manager" && id.id == "GTM-XXXXX"));
    }

    #[test]
    fn test_extract_analytics_ids_google_adsense() {
        let html = r#"
            <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-1234567890123456"></script>
        "#;
        let ids = extract_analytics_ids(html);
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].provider, "Google AdSense");
        assert_eq!(ids[0].id, "pub-1234567890123456");
    }

    #[test]
    fn test_extract_analytics_ids_multiple() {
        let html = r#"
            <script>
                ga('create', 'UA-123456-1', 'auto');
                gtag('config', 'G-ABCDEFGHIJ');
                fbq('init', '1234567890');
            </script>
        "#;
        let ids = extract_analytics_ids(html);
        assert_eq!(ids.len(), 3);
        assert!(ids.iter().any(|id| id.provider == "Google Analytics"));
        assert!(ids.iter().any(|id| id.provider == "Google Analytics 4"));
        assert!(ids.iter().any(|id| id.provider == "Facebook Pixel"));
    }

    #[test]
    fn test_extract_analytics_ids_duplicates() {
        let html = r#"
            <script>
                ga('create', 'UA-123456-1', 'auto');
                ga('create', 'UA-123456-1', 'auto');
            </script>
        "#;
        let ids = extract_analytics_ids(html);
        // Should only extract once
        assert_eq!(ids.len(), 1);
    }

    #[test]
    fn test_extract_analytics_ids_empty() {
        let html = "<html><body>No analytics</body></html>";
        let ids = extract_analytics_ids(html);
        assert_eq!(ids.len(), 0);
    }

    #[test]
    fn test_extract_analytics_ids_case_insensitive() {
        let html = r#"
            <script>
                GA('CREATE', 'UA-123456-1', 'auto');
            </script>
        "#;
        let ids = extract_analytics_ids(html);
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].id, "UA-123456-1");
    }
}
