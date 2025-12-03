//! Social media link extraction.
//!
//! This module extracts social media links from HTML documents, identifying
//! platform, URL, and identifier (username/handle) for each link.

use regex::Regex;
use scraper::{Html, Selector};
use std::sync::LazyLock;

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

const ANCHOR_SELECTOR_STR: &str = "a[href]";

/// Social media link information
#[derive(Debug, Clone, Default)]
pub struct SocialMediaLink {
    pub platform: String,
    pub url: String,
    pub identifier: Option<String>, // Username, handle, or ID extracted from URL
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

// Lazy static regex patterns for social media links
static LINKEDIN_RE: LazyLock<Regex> =
    LazyLock::new(|| compile_regex_unsafe(LINKEDIN_URL_PATTERN, "LINKEDIN_RE"));
static TWITTER_RE: LazyLock<Regex> =
    LazyLock::new(|| compile_regex_unsafe(TWITTER_URL_PATTERN, "TWITTER_RE"));
static FACEBOOK_RE: LazyLock<Regex> =
    LazyLock::new(|| compile_regex_unsafe(FACEBOOK_URL_PATTERN, "FACEBOOK_RE"));
static INSTAGRAM_RE: LazyLock<Regex> =
    LazyLock::new(|| compile_regex_unsafe(INSTAGRAM_URL_PATTERN, "INSTAGRAM_RE"));
static YOUTUBE_RE: LazyLock<Regex> =
    LazyLock::new(|| compile_regex_unsafe(YOUTUBE_URL_PATTERN, "YOUTUBE_RE"));
static GITHUB_RE: LazyLock<Regex> =
    LazyLock::new(|| compile_regex_unsafe(GITHUB_URL_PATTERN, "GITHUB_RE"));
static TIKTOK_RE: LazyLock<Regex> =
    LazyLock::new(|| compile_regex_unsafe(TIKTOK_URL_PATTERN, "TIKTOK_RE"));
static PINTEREST_RE: LazyLock<Regex> =
    LazyLock::new(|| compile_regex_unsafe(PINTEREST_URL_PATTERN, "PINTEREST_RE"));
static SNAPCHAT_RE: LazyLock<Regex> =
    LazyLock::new(|| compile_regex_unsafe(SNAPCHAT_URL_PATTERN, "SNAPCHAT_RE"));
static REDDIT_RE: LazyLock<Regex> =
    LazyLock::new(|| compile_regex_unsafe(REDDIT_URL_PATTERN, "REDDIT_RE"));

static ANCHOR_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| crate::utils::parse_selector_unsafe(ANCHOR_SELECTOR_STR, "ANCHOR_SELECTOR"));

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
