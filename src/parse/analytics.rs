//! Analytics and tracking ID extraction.
//!
//! This module extracts analytics and tracking IDs from HTML content and JavaScript,
//! including Google Analytics, Facebook Pixel, Google Tag Manager, and Google AdSense.

use regex::Regex;
use std::sync::LazyLock;

/// Analytics/Tracking ID extracted from HTML/JavaScript.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AnalyticsId {
    /// Analytics provider (e.g., "Google Analytics", "Facebook Pixel", "Google Tag Manager", "AdSense")
    pub provider: String,
    /// The tracking ID (e.g., "UA-123456-1", "G-XXXXXXXXXX", "1234567890", "GTM-XXXXX")
    pub id: String,
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
            let key = ("Google Analytics".to_string(), id_str.clone());
            if seen_ids.insert(key) {
                analytics_ids.push(AnalyticsId {
                    provider: "Google Analytics".to_string(),
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
            let key = ("Google Analytics 4".to_string(), id_str.clone());
            if seen_ids.insert(key) {
                analytics_ids.push(AnalyticsId {
                    provider: "Google Analytics 4".to_string(),
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
            let key = ("Facebook Pixel".to_string(), id_str.clone());
            if seen_ids.insert(key) {
                analytics_ids.push(AnalyticsId {
                    provider: "Facebook Pixel".to_string(),
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
    // We match GTM- followed by alphanumeric, appearing after common GTM-related keywords or in URL parameters
    static GTM_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        compile_regex_unsafe(
            r#"(?i)(?:gtm|googletagmanager|dataLayer|tagIds|gtm\.js|ns\.html)[^'"">]*['"">]?\s*[:=,]\s*['"]?(GTM-[A-Z0-9]+)"#,
            "GTM_PATTERN",
        )
    });
    for cap in GTM_PATTERN.captures_iter(html) {
        if let Some(id) = cap.get(1) {
            let id_str = id.as_str().to_string();
            let key = ("Google Tag Manager".to_string(), id_str.clone());
            if seen_ids.insert(key) {
                analytics_ids.push(AnalyticsId {
                    provider: "Google Tag Manager".to_string(),
                    id: id_str,
                });
            }
        }
    }

    // Also check for standalone GTM-XXXXX patterns (fallback for edge cases)
    // This catches GTM IDs that appear without the keywords above
    static GTM_STANDALONE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        compile_regex_unsafe(r#"(?i)\b(GTM-[A-Z0-9]{6,})\b"#, "GTM_STANDALONE_PATTERN")
    });
    for cap in GTM_STANDALONE_PATTERN.captures_iter(html) {
        if let Some(id) = cap.get(1) {
            let id_str = id.as_str().to_string();
            let key = ("Google Tag Manager".to_string(), id_str.clone());
            if seen_ids.insert(key) {
                analytics_ids.push(AnalyticsId {
                    provider: "Google Tag Manager".to_string(),
                    id: id_str,
                });
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
            let key = ("Google AdSense".to_string(), id_str.clone());
            if seen_ids.insert(key) {
                analytics_ids.push(AnalyticsId {
                    provider: "Google AdSense".to_string(),
                    id: id_str,
                });
            }
        }
    }

    analytics_ids
}

