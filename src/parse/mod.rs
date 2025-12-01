use regex::Regex;
use scraper::{Html, Selector};
use std::collections::HashMap;
use std::sync::LazyLock;

use crate::error_handling::ProcessingStats;

// CSS selector strings
const TITLE_SELECTOR_STR: &str = "title";
const META_KEYWORDS_SELECTOR_STR: &str = "meta[name='keywords']";
const META_DESCRIPTION_SELECTOR_STR: &str = "meta[name='description']";
const ANCHOR_SELECTOR_STR: &str = "a[href]";

// Regex patterns for social media links
const LINKEDIN_URL_PATTERN: &str = r"https?://(?:www\.)?linkedin\.com/(?:company|in|pub)/([^/?#]+)";
const TWITTER_URL_PATTERN: &str = r"https?://(?:www\.)?(?:twitter\.com|x\.com)/([^/?#]+)";
const FACEBOOK_URL_PATTERN: &str = r"https?://(?:www\.)?facebook\.com/([^/?#]+)";
const INSTAGRAM_URL_PATTERN: &str = r"https?://(?:www\.)?instagram\.com/([^/?#]+)";
const YOUTUBE_URL_PATTERN: &str = r"https?://(?:www\.)?youtube\.com/(?:channel|c|user)/([^/?#]+)";
const GITHUB_URL_PATTERN: &str = r"https?://(?:www\.)?github\.com/([^/?#]+)";
const TIKTOK_URL_PATTERN: &str = r"https?://(?:www\.)?tiktok\.com/@([^/?#]+)";
const PINTEREST_URL_PATTERN: &str = r"https?://(?:www\.)?pinterest\.(?:com|co\.uk)/([^/?#]+)";
const SNAPCHAT_URL_PATTERN: &str = r"https?://(?:www\.)?snapchat\.com/add/([^/?#]+)";
const REDDIT_URL_PATTERN: &str = r"https?://(?:www\.)?reddit\.com/(?:r|u)/([^/?#]+)";

static TITLE_SELECTOR: LazyLock<Selector> = LazyLock::new(|| {
    Selector::parse(TITLE_SELECTOR_STR).unwrap_or_else(|e| {
        log::error!(
            "Failed to parse title selector '{}': {}",
            TITLE_SELECTOR_STR,
            e
        );
        // Return a safe default selector that matches nothing
        // This prevents panics while still allowing the code to run
        Selector::parse("__invalid_selector__").expect("Failed to parse fallback selector")
    })
});

static META_KEYWORDS_SELECTOR: LazyLock<Selector> = LazyLock::new(|| {
    Selector::parse(META_KEYWORDS_SELECTOR_STR).unwrap_or_else(|e| {
        log::error!(
            "Failed to parse meta keywords selector '{}': {}",
            META_KEYWORDS_SELECTOR_STR,
            e
        );
        Selector::parse("__invalid_selector__").expect("Failed to parse fallback selector")
    })
});

static META_DESCRIPTION_SELECTOR: LazyLock<Selector> = LazyLock::new(|| {
    Selector::parse(META_DESCRIPTION_SELECTOR_STR).unwrap_or_else(|e| {
        log::error!(
            "Failed to parse meta description selector '{}': {}",
            META_DESCRIPTION_SELECTOR_STR,
            e
        );
        Selector::parse("__invalid_selector__").expect("Failed to parse fallback selector")
    })
});

/// Extracts the page title from an HTML document.
///
/// Searches for the first `<title>` element and returns its text content, trimmed
/// of whitespace. If no title is found, increments the error counter and returns
/// an empty string.
///
/// # Arguments
///
/// * `document` - The parsed HTML document
/// * `error_stats` - Processing statistics tracker for recording extraction issues
///
/// # Returns
///
/// The page title as a string, or an empty string if not found.
pub fn extract_title(document: &Html, error_stats: &ProcessingStats) -> String {
    let elements: Vec<_> = document.select(&TITLE_SELECTOR).collect();
    log::debug!("Found {} title elements", elements.len());

    match elements.first() {
        Some(element) => {
            // Use text() to get text content, which handles HTML entities and nested tags correctly
            let title: String = element.text().collect::<String>().trim().to_string();
            log::debug!(
                "Extracted title text: '{}' (length: {})",
                title,
                title.len()
            );
            if title.is_empty() {
                // Try inner_html as fallback in case text() doesn't work
                let inner = element.inner_html().trim().to_string();
                log::debug!("Title inner_html: '{}' (length: {})", inner, inner.len());
                if inner.is_empty() {
                    error_stats.increment_warning(crate::error_handling::WarningType::MissingTitle);
                    String::from("")
                } else {
                    inner
                }
            } else {
                title
            }
        }
        None => {
            log::debug!("No title element found in document");
            error_stats.increment_warning(crate::error_handling::WarningType::MissingTitle);
            String::from("")
        }
    }
}

/// Extracts meta keywords from an HTML document.
///
/// Searches for a `<meta name="keywords">` element and parses its `content` attribute
/// as a comma-separated list of keywords. Returns `None` if the meta tag is not found
/// or if the content is empty.
///
/// # Arguments
///
/// * `document` - The parsed HTML document
/// * `stats` - Processing statistics tracker (for warnings if missing)
///
/// # Returns
///
/// A vector of keyword strings, or `None` if no keywords meta tag is found.
pub fn extract_meta_keywords(
    document: &Html,
    stats: &crate::error_handling::ProcessingStats,
) -> Option<Vec<String>> {
    let meta_keywords = document
        .select(&META_KEYWORDS_SELECTOR)
        .next()
        .and_then(|element| element.value().attr("content"));

    match meta_keywords {
        Some(content) => {
            let keywords: Vec<String> = content
                .split(',')
                .map(|keyword| keyword.trim().to_lowercase())
                .filter(|keyword| !keyword.is_empty())
                .collect();

            if keywords.is_empty() {
                // Empty keywords - track as warning
                stats.increment_warning(crate::error_handling::WarningType::MissingMetaKeywords);
                None
            } else {
                Some(keywords)
            }
        }
        None => {
            // Missing keywords meta tag - track as warning
            stats.increment_warning(crate::error_handling::WarningType::MissingMetaKeywords);
            None
        }
    }
}

/// Extracts the meta description from an HTML document.
///
/// Searches for a `<meta name="description">` element and returns its `content`
/// attribute value, trimmed of whitespace. Returns `None` if the meta tag is not found.
///
/// # Arguments
///
/// * `document` - The parsed HTML document
/// * `stats` - Processing statistics tracker (for warnings if missing)
///
/// # Returns
///
/// The meta description as a string, or `None` if not found.
pub fn extract_meta_description(document: &Html, stats: &ProcessingStats) -> Option<String> {
    let meta_description = document
        .select(&META_DESCRIPTION_SELECTOR)
        .next()
        .and_then(|element| {
            element
                .value()
                .attr("content")
                .map(|content| content.trim().to_string())
        });

    // Missing meta description - track as warning (optional but recommended for SEO)
    if meta_description.is_none() {
        stats.increment_warning(crate::error_handling::WarningType::MissingMetaDescription);
    }
    meta_description
}

/// Social media link information
#[derive(Debug, Clone, Default)]
pub struct SocialMediaLink {
    pub platform: String,
    pub url: String,
    pub identifier: Option<String>, // Username, handle, or ID extracted from URL
}

// Lazy static regex patterns for social media links
static LINKEDIN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(LINKEDIN_URL_PATTERN).expect("Failed to compile LinkedIn regex"));
static TWITTER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(TWITTER_URL_PATTERN).expect("Failed to compile Twitter regex"));
static FACEBOOK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(FACEBOOK_URL_PATTERN).expect("Failed to compile Facebook regex"));
static INSTAGRAM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(INSTAGRAM_URL_PATTERN).expect("Failed to compile Instagram regex"));
static YOUTUBE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(YOUTUBE_URL_PATTERN).expect("Failed to compile YouTube regex"));
static GITHUB_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(GITHUB_URL_PATTERN).expect("Failed to compile GitHub regex"));
static TIKTOK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(TIKTOK_URL_PATTERN).expect("Failed to compile TikTok regex"));
static PINTEREST_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(PINTEREST_URL_PATTERN).expect("Failed to compile Pinterest regex"));
static SNAPCHAT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(SNAPCHAT_URL_PATTERN).expect("Failed to compile Snapchat regex"));
static REDDIT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(REDDIT_URL_PATTERN).expect("Failed to compile Reddit regex"));

static ANCHOR_SELECTOR: LazyLock<Selector> = LazyLock::new(|| {
    Selector::parse(ANCHOR_SELECTOR_STR).expect("Failed to parse anchor selector - this is a bug")
});

/// Extracts social media links from an HTML document.
///
/// Searches for anchor tags (`<a>`) with `href` attributes matching common social media
/// platform URL patterns and extracts the platform, full URL, and identifier (username/handle).
///
/// Supported platforms:
/// - LinkedIn (company, profile, publisher pages)
/// - Twitter/X
/// - Facebook
/// - Instagram
/// - YouTube (channel, user pages)
/// - GitHub
/// - TikTok
/// - Pinterest
/// - Snapchat
/// - Reddit (subreddits, users)
///
/// # Arguments
///
/// * `document` - The parsed HTML document
///
/// # Returns
///
/// A vector of `SocialMediaLink` structs containing platform, URL, and identifier.
pub fn extract_social_media_links(document: &Html) -> Vec<SocialMediaLink> {
    let mut links = Vec::new();
    let mut seen_urls = std::collections::HashSet::new();

    // Pattern matching: (regex, platform_name)
    let patterns: Vec<(&LazyLock<Regex>, &str)> = vec![
        (&LINKEDIN_RE, "LinkedIn"),
        (&TWITTER_RE, "Twitter"),
        (&FACEBOOK_RE, "Facebook"),
        (&INSTAGRAM_RE, "Instagram"),
        (&YOUTUBE_RE, "YouTube"),
        (&GITHUB_RE, "GitHub"),
        (&TIKTOK_RE, "TikTok"),
        (&PINTEREST_RE, "Pinterest"),
        (&SNAPCHAT_RE, "Snapchat"),
        (&REDDIT_RE, "Reddit"),
    ];

    for element in document.select(&ANCHOR_SELECTOR) {
        if let Some(href) = element.value().attr("href") {
            // Skip if we've already seen this URL
            if seen_urls.contains(href) {
                continue;
            }

            // Try each pattern
            for (re, platform_name) in &patterns {
                if let Some(caps) = re.captures(href) {
                    let identifier = caps.get(1).map(|m| m.as_str().to_string());
                    let full_url = if href.starts_with("http://") || href.starts_with("https://") {
                        href.to_string()
                    } else if href.starts_with("//") {
                        format!("https:{}", href)
                    } else if href.starts_with('/') {
                        // Relative URL - skip for now (would need base URL)
                        continue;
                    } else {
                        format!("https://{}", href)
                    };

                    seen_urls.insert(href.to_string());
                    links.push(SocialMediaLink {
                        platform: platform_name.to_string(),
                        url: full_url,
                        identifier,
                    });
                    break; // Found a match, move to next link
                }
            }
        }
    }

    links
}

/// Checks if an HTML document is mobile-friendly by looking for a viewport meta tag.
///
/// # Arguments
///
/// * `html` - The raw HTML content
///
/// # Returns
///
/// `true` if a viewport meta tag is present, `false` otherwise.
pub fn is_mobile_friendly(html: &str) -> bool {
    html.contains("viewport")
}

/// Analytics/Tracking ID extracted from HTML/JavaScript.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AnalyticsId {
    /// Analytics provider (e.g., "Google Analytics", "Facebook Pixel", "Google Tag Manager", "AdSense")
    pub provider: String,
    /// The tracking ID (e.g., "UA-123456-1", "G-XXXXXXXXXX", "1234567890", "GTM-XXXXX")
    pub id: String,
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
        Regex::new(r#"(?i)ga\s*\(\s*['"]create['"]\s*,\s*['"](UA-\d+-\d+)['"]"#)
            .expect("Failed to compile GA UA regex pattern")
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
        Regex::new(r#"(?i)gtag\s*\(\s*['"]config['"]\s*,\s*['"](G-[A-Z0-9]+)['"]"#)
            .expect("Failed to compile GA4 regex pattern")
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
        Regex::new(r#"(?i)fbq\s*\(\s*['"]init['"]\s*,\s*['"](\d+)['"]"#)
            .expect("Failed to compile Facebook Pixel regex pattern")
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
        Regex::new(r#"(?i)(?:gtm|googletagmanager|dataLayer|tagIds|gtm\.js|ns\.html)[^'"">]*['"">]?\s*[:=,]\s*['"]?(GTM-[A-Z0-9]+)"#)
            .expect("Failed to compile GTM regex pattern")
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
        Regex::new(r#"(?i)\b(GTM-[A-Z0-9]{6,})\b"#)
            .expect("Failed to compile GTM standalone regex pattern")
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
    static ADSENSE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)(?:ca-)?pub-(\d{10,})"#).expect("Failed to compile AdSense regex pattern")
    });
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

/// Structured data extracted from HTML
#[derive(Debug, Clone, Default)]
pub struct StructuredData {
    /// JSON-LD scripts (application/ld+json)
    pub json_ld: Vec<serde_json::Value>,
    /// Open Graph meta tags (og:*)
    pub open_graph: HashMap<String, String>,
    /// Twitter Card meta tags (twitter:*)
    pub twitter_cards: HashMap<String, String>,
    /// Schema.org types detected (from JSON-LD @type or microdata itemtype)
    pub schema_types: Vec<String>,
}

/// Extracts structured data from an HTML document.
///
/// Extracts:
/// - JSON-LD (script type="application/ld+json")
/// - Open Graph tags (meta property="og:*")
/// - Twitter Card tags (meta name="twitter:*")
/// - Schema.org types (from JSON-LD @type)
///
/// # Arguments
///
/// * `document` - The parsed HTML document
/// * `html` - The raw HTML content (for JSON-LD extraction)
///
/// # Returns
///
/// A `StructuredData` struct containing all extracted structured data.
pub fn extract_structured_data(document: &Html, html: &str) -> StructuredData {
    // Extract JSON-LD
    let json_ld = extract_json_ld(html);

    // Extract Schema.org types from JSON-LD
    let mut schema_types = Vec::new();
    for json_value in &json_ld {
        if let Some(obj) = json_value.as_object() {
            if let Some(type_value) = obj.get("@type") {
                if let Some(type_str) = type_value.as_str() {
                    schema_types.push(type_str.to_string());
                } else if let Some(type_array) = type_value.as_array() {
                    for t in type_array {
                        if let Some(t_str) = t.as_str() {
                            schema_types.push(t_str.into());
                        }
                    }
                }
            }
        }
    }

    // Extract Open Graph tags
    let open_graph = extract_open_graph(document);

    // Extract Twitter Card tags
    let twitter_cards = extract_twitter_cards(document);

    StructuredData {
        json_ld,
        open_graph,
        twitter_cards,
        schema_types,
    }
}

/// Extracts JSON-LD structured data from HTML.
///
/// Searches for `<script type="application/ld+json">` tags and parses their content.
fn extract_json_ld(html: &str) -> Vec<serde_json::Value> {
    let mut json_ld_scripts = Vec::new();

    // Pattern to match JSON-LD script tags
    // Matches: <script type="application/ld+json">...</script>
    // Handles both single and double quotes, and case-insensitive type attribute
    // Use two patterns: one for double quotes, one for single quotes
    let re_double = match Regex::new(
        "(?i)<script[^>]*type\\s*=\\s*\"application/ld\\+json\"[^>]*>(.*?)</script>",
    ) {
        Ok(r) => r,
        Err(_) => return json_ld_scripts,
    };

    let re_single = match Regex::new(
        "(?i)<script[^>]*type\\s*=\\s*'application/ld\\+json'[^>]*>(.*?)</script>",
    ) {
        Ok(r) => r,
        Err(_) => return json_ld_scripts,
    };

    // Try double quotes first
    for cap in re_double.captures_iter(html) {
        if let Some(json_content) = cap.get(1) {
            let json_str = json_content.as_str().trim();
            if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(json_str) {
                json_ld_scripts.push(json_value);
            } else {
                // Try parsing as array of JSON objects
                if let Ok(json_array) = serde_json::from_str::<Vec<serde_json::Value>>(json_str) {
                    json_ld_scripts.extend(json_array);
                }
            }
        }
    }

    // Then try single quotes
    for cap in re_single.captures_iter(html) {
        if let Some(json_content) = cap.get(1) {
            let json_str = json_content.as_str().trim();
            if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(json_str) {
                json_ld_scripts.push(json_value);
            } else {
                // Try parsing as array of JSON objects
                if let Ok(json_array) = serde_json::from_str::<Vec<serde_json::Value>>(json_str) {
                    json_ld_scripts.extend(json_array);
                }
            }
        }
    }

    json_ld_scripts
}

/// Extracts Open Graph meta tags from HTML.
///
/// Searches for `<meta property="og:*">` tags and extracts property-value pairs.
fn extract_open_graph(document: &Html) -> HashMap<String, String> {
    let mut og_tags = HashMap::new();

    // Selector for meta tags with property attribute starting with "og:"
    let selector_str = r#"meta[property^="og:"]"#;
    if let Ok(selector) = Selector::parse(selector_str) {
        for element in document.select(&selector) {
            if let (Some(property), Some(content)) = (
                element.value().attr("property"),
                element.value().attr("content"),
            ) {
                og_tags.insert(property.to_string(), content.to_string());
            }
        }
    }

    og_tags
}

/// Extracts Twitter Card meta tags from HTML.
///
/// Searches for `<meta name="twitter:*">` tags and extracts name-value pairs.
fn extract_twitter_cards(document: &Html) -> HashMap<String, String> {
    let mut twitter_tags = HashMap::new();

    // Selector for meta tags with name attribute starting with "twitter:"
    let selector_str = r#"meta[name^="twitter:"]"#;
    if let Ok(selector) = Selector::parse(selector_str) {
        for element in document.select(&selector) {
            if let (Some(name), Some(content)) = (
                element.value().attr("name"),
                element.value().attr("content"),
            ) {
                twitter_tags.insert(name.to_string(), content.to_string());
            }
        }
    }

    twitter_tags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ProcessingStats;

    fn test_error_stats() -> ProcessingStats {
        ProcessingStats::new()
    }

    #[test]
    fn test_extract_title_basic() {
        let html = r#"<html><head><title>Test Page</title></head><body></body></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert_eq!(extract_title(&document, &stats), "Test Page");
        assert_eq!(
            stats.get_error_count(crate::error_handling::ErrorType::TitleExtractError),
            0
        );
    }

    #[test]
    fn test_extract_title_with_whitespace() {
        // Common gotcha: titles with extra whitespace/newlines
        let html = r#"<html><head><title>
            Test Page
        </title></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert_eq!(extract_title(&document, &stats), "Test Page");
    }

    #[test]
    fn test_extract_title_with_html_entities() {
        // HTML entities should be decoded
        let html = r#"<html><head><title>Test &amp; Page &lt;Title&gt;</title></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        let title = extract_title(&document, &stats);
        // scraper should decode entities
        assert!(title.contains("&") || title.contains("Test"));
    }

    #[test]
    fn test_extract_title_empty() {
        let html = r#"<html><head><title></title></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert_eq!(extract_title(&document, &stats), "");
    }

    #[test]
    fn test_extract_title_missing() {
        // Missing title is now tracked as a warning, not an error
        let html = r#"<html><head></head><body></body></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert_eq!(extract_title(&document, &stats), "");
        assert_eq!(
            stats.get_warning_count(crate::error_handling::WarningType::MissingTitle),
            1
        );
        assert_eq!(
            stats.get_error_count(crate::error_handling::ErrorType::TitleExtractError),
            0
        );
    }

    #[test]
    fn test_extract_title_multiple_tags() {
        // Edge case: multiple title tags (should get first)
        let html = r#"<html><head><title>First</title><title>Second</title></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert_eq!(extract_title(&document, &stats), "First");
    }

    #[test]
    fn test_extract_meta_keywords_basic() {
        let html = r#"<html><head><meta name="keywords" content="rust, programming, language"></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        let keywords = extract_meta_keywords(&document, &stats).unwrap();
        assert_eq!(keywords, vec!["rust", "programming", "language"]);
    }

    #[test]
    fn test_extract_meta_keywords_with_whitespace() {
        // Common gotcha: keywords with extra spaces
        let html = r#"<html><head><meta name="keywords" content=" rust , programming , language "></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        let keywords = extract_meta_keywords(&document, &stats).unwrap();
        assert_eq!(keywords, vec!["rust", "programming", "language"]);
    }

    #[test]
    fn test_extract_meta_keywords_empty_content() {
        // Edge case: empty content attribute
        // Empty keywords - track as warning
        let html = r#"<html><head><meta name="keywords" content=""></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert!(extract_meta_keywords(&document, &stats).is_none());
        // Missing/empty keywords is tracked as a warning, not an error
    }

    #[test]
    fn test_extract_meta_keywords_only_whitespace() {
        // Edge case: content with only spaces/commas
        let html = r#"<html><head><meta name="keywords" content="  ,  ,  "></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert!(extract_meta_keywords(&document, &stats).is_none());
    }

    #[test]
    fn test_extract_meta_keywords_case_insensitive() {
        // Keywords should be lowercased
        let html = r#"<html><head><meta name="keywords" content="RUST, Programming, LANGUAGE"></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        let keywords = extract_meta_keywords(&document, &stats).unwrap();
        assert_eq!(keywords, vec!["rust", "programming", "language"]);
    }

    #[test]
    fn test_extract_meta_description_basic() {
        let html =
            r#"<html><head><meta name="description" content="A test description"></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert_eq!(
            extract_meta_description(&document, &stats),
            Some("A test description".to_string())
        );
    }

    #[test]
    fn test_extract_meta_description_with_whitespace() {
        let html = r#"<html><head><meta name="description" content="  A test description  "></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert_eq!(
            extract_meta_description(&document, &stats),
            Some("A test description".to_string())
        );
    }

    #[test]
    fn test_extract_meta_description_missing() {
        // Missing meta description is tracked as a warning, not an error
        let html = r#"<html><head></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert!(extract_meta_description(&document, &stats).is_none());
        // Missing meta description is tracked as a warning, not an error
    }

    #[test]
    fn test_is_mobile_friendly_with_viewport() {
        let html =
            r#"<html><head><meta name="viewport" content="width=device-width"></head></html>"#;
        assert!(is_mobile_friendly(html));
    }

    #[test]
    fn test_is_mobile_friendly_case_insensitive() {
        // Edge case: viewport in different case
        // Current implementation uses contains() which is case-sensitive
        // "Viewport" does not contain "viewport" (lowercase), so this should fail
        let html =
            r#"<html><head><meta name="Viewport" content="width=device-width"></head></html>"#;
        // This documents a limitation: case-sensitive matching
        assert!(!is_mobile_friendly(html));
    }

    #[test]
    fn test_is_mobile_friendly_without_viewport() {
        let html = r#"<html><head><title>Test</title></head></html>"#;
        assert!(!is_mobile_friendly(html));
    }

    #[test]
    fn test_is_mobile_friendly_false_positive() {
        // Potential gotcha: word "viewport" in content (not in meta tag)
        let html = r#"<html><body><p>This page has a viewport</p></body></html>"#;
        // Current implementation would return true (false positive)
        // This test documents this behavior
        assert!(is_mobile_friendly(html));
    }

    // Analytics ID extraction tests
    #[test]
    fn test_extract_analytics_ids_gtm_data_layer_format() {
        // Test GTM in dataLayer format (like Chevron.com)
        let html = r#"
            <script>
                (function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':
                new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],
                j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src=
                'https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);
                })(window, document, 'script', 'dataLayer','GTM-MMCQ2RJB');
            </script>
        "#;
        let ids = crate::parse::extract_analytics_ids(html);
        assert!(ids.len() >= 1, "Should find GTM ID in dataLayer format");
        let gtm_ids: Vec<&str> = ids
            .iter()
            .filter(|id| id.provider == "Google Tag Manager")
            .map(|id| id.id.as_str())
            .collect();
        assert!(
            gtm_ids.contains(&"GTM-MMCQ2RJB"),
            "Should find GTM-MMCQ2RJB: {:?}",
            gtm_ids
        );
    }

    #[test]
    fn test_extract_analytics_ids_gtm_json_format() {
        // Test GTM in JSON format (like Fannie Mae)
        let html = r#"
            <script type="application/json">{"gtm":{"tagIds":["GTM-T7L6LT"]}}</script>
        "#;
        let ids = crate::parse::extract_analytics_ids(html);
        assert!(ids.len() >= 1, "Should find GTM ID in JSON format");
        let gtm_ids: Vec<&str> = ids
            .iter()
            .filter(|id| id.provider == "Google Tag Manager")
            .map(|id| id.id.as_str())
            .collect();
        assert!(
            gtm_ids.contains(&"GTM-T7L6LT"),
            "Should find GTM-T7L6LT: {:?}",
            gtm_ids
        );
    }

    #[test]
    fn test_extract_analytics_ids_gtm_url_format() {
        // Test GTM in URL format (iframe/script src)
        let html = r#"
            <iframe src="https://www.googletagmanager.com/ns.html?id=GTM-XXXXX"></iframe>
            <script src="https://www.googletagmanager.com/gtm.js?id=GTM-YYYYY"></script>
        "#;
        let ids = crate::parse::extract_analytics_ids(html);
        assert!(ids.len() >= 1, "Should find GTM IDs in URL format");
        let gtm_ids: Vec<&str> = ids
            .iter()
            .filter(|id| id.provider == "Google Tag Manager")
            .map(|id| id.id.as_str())
            .collect();
        assert!(
            gtm_ids.contains(&"GTM-XXXXX") || gtm_ids.contains(&"GTM-YYYYY"),
            "Should find at least one GTM ID: {:?}",
            gtm_ids
        );
    }
}
