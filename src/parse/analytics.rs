//! Analytics and tracking ID extraction.
//!
//! This module extracts analytics and tracking IDs from HTML content and JavaScript,
//! including Google Analytics, Facebook Pixel, Google Tag Manager, and Google `AdSense`.

use regex::Regex;
use std::collections::HashSet;
use std::fmt;
use std::sync::LazyLock;

/// Supported analytics/tracking providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnalyticsProvider {
    GoogleAnalytics,
    GoogleAnalytics4,
    FacebookPixel,
    GoogleTagManager,
    GoogleAdSense,
}

impl AnalyticsProvider {
    /// Returns the provider name as a string slice.
    pub fn as_str(self) -> &'static str {
        match self {
            AnalyticsProvider::GoogleAnalytics => "Google Analytics",
            AnalyticsProvider::GoogleAnalytics4 => "Google Analytics 4",
            AnalyticsProvider::FacebookPixel => "Facebook Pixel",
            AnalyticsProvider::GoogleTagManager => "Google Tag Manager",
            AnalyticsProvider::GoogleAdSense => "Google AdSense",
        }
    }
}

impl fmt::Display for AnalyticsProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Analytics/Tracking ID extracted from HTML/JavaScript.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AnalyticsId {
    /// Analytics provider
    pub provider: AnalyticsProvider,
    /// The tracking ID (e.g., "UA-123456-1", "G-XXXXXXXXXX", "1234567890", "GTM-XXXXX")
    pub id: String,
}

/// Minimum length for a valid GTM container ID (`GTM-` + at least 4 chars).
const MIN_GTM_ID_LENGTH: usize = 8;

fn compile_re(pattern: &'static str) -> Regex {
    Regex::new(pattern).expect("hardcoded analytics regex is valid; this is a compile-time bug")
}

fn id_as_is(captured: &str) -> String {
    captured.to_string()
}

fn id_adsense_pub(captured: &str) -> String {
    format!("pub-{captured}")
}

fn accept_all(_: &str) -> bool {
    true
}

/// Valid GTM IDs start with uppercase `GTM-` and then only A–Z / 0–9.
fn is_valid_gtm_id(id: &str) -> bool {
    id.starts_with("GTM-")
        && id.len() >= MIN_GTM_ID_LENGTH
        && id
            .chars()
            .skip(4)
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

static GA_UA_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| compile_re(r#"(?i)ga\s*\(\s*['"]create['"]\s*,\s*['"](UA-\d+-\d+)['"]"#));
static GA4_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| compile_re(r#"(?i)gtag\s*\(\s*['"]config['"]\s*,\s*['"](G-[A-Z0-9]+)['"]"#));
static FB_PIXEL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| compile_re(r#"(?i)fbq\s*\(\s*['"]init['"]\s*,\s*['"](\d+)['"]"#));
static GTM_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    compile_re(
        r#"(?i)(?:gtm|googletagmanager|dataLayer|tagIds|gtm\.js|ns\.html)[^'"">]*['"">]?\s*[:=,]\s*['"]?(GTM-[A-Z0-9]{4,})\b"#,
    )
});
static GTM_STANDALONE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| compile_re(r"\b(GTM-[A-Z0-9]{4,})\b"));
static ADSENSE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| compile_re(r"(?i)(?:ca-)?pub-(\d{10,})"));

struct AnalyticsRule {
    regex: &'static LazyLock<Regex>,
    provider: AnalyticsProvider,
    map_id: fn(&str) -> String,
    accept: fn(&str) -> bool,
}

static ANALYTICS_RULES: &[AnalyticsRule] = &[
    AnalyticsRule {
        regex: &GA_UA_PATTERN,
        provider: AnalyticsProvider::GoogleAnalytics,
        map_id: id_as_is,
        accept: accept_all,
    },
    AnalyticsRule {
        regex: &GA4_PATTERN,
        provider: AnalyticsProvider::GoogleAnalytics4,
        map_id: id_as_is,
        accept: accept_all,
    },
    AnalyticsRule {
        regex: &FB_PIXEL_PATTERN,
        provider: AnalyticsProvider::FacebookPixel,
        map_id: id_as_is,
        accept: accept_all,
    },
    AnalyticsRule {
        regex: &GTM_PATTERN,
        provider: AnalyticsProvider::GoogleTagManager,
        map_id: id_as_is,
        accept: is_valid_gtm_id,
    },
    AnalyticsRule {
        regex: &GTM_STANDALONE_PATTERN,
        provider: AnalyticsProvider::GoogleTagManager,
        map_id: id_as_is,
        accept: is_valid_gtm_id,
    },
    AnalyticsRule {
        regex: &ADSENSE_PATTERN,
        provider: AnalyticsProvider::GoogleAdSense,
        map_id: id_adsense_pub,
        accept: accept_all,
    },
];

/// Extracts analytics and tracking IDs from HTML content and JavaScript.
///
/// Searches for Google Analytics (`UA-` / `G-`), Facebook Pixel, Google Tag
/// Manager (`GTM-XXXX`), and Google `AdSense` publisher IDs.
pub fn extract_analytics_ids(html: &str) -> Vec<AnalyticsId> {
    let mut analytics_ids = Vec::new();
    let mut seen_ids = HashSet::<(AnalyticsProvider, String)>::new();

    for rule in ANALYTICS_RULES {
        for cap in rule.regex.captures_iter(html) {
            let Some(id) = cap.get(1) else {
                continue;
            };
            let id_str = (rule.map_id)(id.as_str());
            if !(rule.accept)(&id_str) {
                continue;
            }
            if seen_ids.insert((rule.provider, id_str.clone())) {
                analytics_ids.push(AnalyticsId {
                    provider: rule.provider,
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
    fn test_extract_analytics_ids_table() {
        let cases: &[(&str, AnalyticsProvider, &str)] = &[
            (
                r#"<script>ga('create', 'UA-123456-1', 'auto');</script>"#,
                AnalyticsProvider::GoogleAnalytics,
                "UA-123456-1",
            ),
            (
                r#"<script>ga("create", "UA-654321-2", "auto");</script>"#,
                AnalyticsProvider::GoogleAnalytics,
                "UA-654321-2",
            ),
            (
                r#"<script>gtag('config', 'G-ABCDEFGHIJ');</script>"#,
                AnalyticsProvider::GoogleAnalytics4,
                "G-ABCDEFGHIJ",
            ),
            (
                r#"<script>fbq('init', '1234567890');</script>"#,
                AnalyticsProvider::FacebookPixel,
                "1234567890",
            ),
            (
                r#"<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-1234567890123456"></script>"#,
                AnalyticsProvider::GoogleAdSense,
                "pub-1234567890123456",
            ),
            (
                r#"<script>GA('CREATE', 'UA-123456-1', 'auto');</script>"#,
                AnalyticsProvider::GoogleAnalytics,
                "UA-123456-1",
            ),
            (
                r#"<script>dataLayer.push('GTM-MMCQ2RJB');</script>"#,
                AnalyticsProvider::GoogleTagManager,
                "GTM-MMCQ2RJB",
            ),
        ];
        for &(html, provider, id) in cases {
            let ids = extract_analytics_ids(html);
            assert!(
                ids.iter()
                    .any(|item| item.provider == provider && item.id == id),
                "expected {provider:?} {id} in {ids:?} from {html}"
            );
        }
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
        assert!(ids
            .iter()
            .any(|id| id.provider == AnalyticsProvider::GoogleAnalytics && id.id == "UA-123456-1"));
        assert!(ids.iter().any(|id| {
            id.provider == AnalyticsProvider::GoogleAnalytics4 && id.id == "G-ABCDEFGHIJ"
        }));
        assert!(ids
            .iter()
            .any(|id| id.provider == AnalyticsProvider::FacebookPixel && id.id == "1234567890"));
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
        assert_eq!(ids.len(), 1);
    }

    #[test]
    fn test_extract_analytics_ids_empty() {
        let html = "<html><body>No analytics</body></html>";
        let ids = extract_analytics_ids(html);
        assert_eq!(ids.len(), 0);
    }
}
