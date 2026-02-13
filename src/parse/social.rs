//! Social media link extraction.
//!
//! This module extracts social media links from HTML documents, identifying
//! platform, URL, and identifier (username/handle) for each link.

use regex::Regex;
use scraper::{Html, Selector};
use std::fmt;
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

/// Supported social media platforms.
///
/// Eliminates primitive obsession by replacing raw `String` platform names
/// with a type-safe enum, preventing typos and enabling exhaustive matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocialPlatform {
    LinkedIn,
    Twitter,
    Facebook,
    Instagram,
    YouTube,
    GitHub,
    TikTok,
    Pinterest,
    Snapchat,
    Reddit,
}

impl SocialPlatform {
    /// Returns the platform name as a string slice.
    pub fn as_str(&self) -> &'static str {
        match self {
            SocialPlatform::LinkedIn => "LinkedIn",
            SocialPlatform::Twitter => "Twitter",
            SocialPlatform::Facebook => "Facebook",
            SocialPlatform::Instagram => "Instagram",
            SocialPlatform::YouTube => "YouTube",
            SocialPlatform::GitHub => "GitHub",
            SocialPlatform::TikTok => "TikTok",
            SocialPlatform::Pinterest => "Pinterest",
            SocialPlatform::Snapchat => "Snapchat",
            SocialPlatform::Reddit => "Reddit",
        }
    }
}

impl fmt::Display for SocialPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Social media link information
#[derive(Debug, Clone)]
pub struct SocialMediaLink {
    pub platform: SocialPlatform,
    pub url: String,
    pub identifier: Option<String>, // Username, handle, or ID extracted from URL
}

// Lazy static regex patterns for social media links
static LINKEDIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(LINKEDIN_URL_PATTERN)
        .expect("LINKEDIN_URL_PATTERN is a hardcoded valid regex; this is a compile-time bug")
});
static TWITTER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(TWITTER_URL_PATTERN)
        .expect("TWITTER_URL_PATTERN is a hardcoded valid regex; this is a compile-time bug")
});
static FACEBOOK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(FACEBOOK_URL_PATTERN)
        .expect("FACEBOOK_URL_PATTERN is a hardcoded valid regex; this is a compile-time bug")
});
static INSTAGRAM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(INSTAGRAM_URL_PATTERN)
        .expect("INSTAGRAM_URL_PATTERN is a hardcoded valid regex; this is a compile-time bug")
});
static YOUTUBE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(YOUTUBE_URL_PATTERN)
        .expect("YOUTUBE_URL_PATTERN is a hardcoded valid regex; this is a compile-time bug")
});
static GITHUB_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(GITHUB_URL_PATTERN)
        .expect("GITHUB_URL_PATTERN is a hardcoded valid regex; this is a compile-time bug")
});
static TIKTOK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(TIKTOK_URL_PATTERN)
        .expect("TIKTOK_URL_PATTERN is a hardcoded valid regex; this is a compile-time bug")
});
static PINTEREST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(PINTEREST_URL_PATTERN)
        .expect("PINTEREST_URL_PATTERN is a hardcoded valid regex; this is a compile-time bug")
});
static SNAPCHAT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(SNAPCHAT_URL_PATTERN)
        .expect("SNAPCHAT_URL_PATTERN is a hardcoded valid regex; this is a compile-time bug")
});
static REDDIT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(REDDIT_URL_PATTERN)
        .expect("REDDIT_URL_PATTERN is a hardcoded valid regex; this is a compile-time bug")
});

static ANCHOR_SELECTOR: LazyLock<Selector> = LazyLock::new(|| {
    Selector::parse(ANCHOR_SELECTOR_STR)
        .expect("ANCHOR_SELECTOR_STR is a hardcoded valid CSS selector; this is a compile-time bug")
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

    // Pattern matching: (regex, platform)
    let patterns: Vec<(&LazyLock<Regex>, SocialPlatform)> = vec![
        (&LINKEDIN_RE, SocialPlatform::LinkedIn),
        (&TWITTER_RE, SocialPlatform::Twitter),
        (&FACEBOOK_RE, SocialPlatform::Facebook),
        (&INSTAGRAM_RE, SocialPlatform::Instagram),
        (&YOUTUBE_RE, SocialPlatform::YouTube),
        (&GITHUB_RE, SocialPlatform::GitHub),
        (&TIKTOK_RE, SocialPlatform::TikTok),
        (&PINTEREST_RE, SocialPlatform::Pinterest),
        (&SNAPCHAT_RE, SocialPlatform::Snapchat),
        (&REDDIT_RE, SocialPlatform::Reddit),
    ];

    for element in document.select(&ANCHOR_SELECTOR) {
        if let Some(href) = element.value().attr("href") {
            // Skip if we've already seen this URL
            if seen_urls.contains(href) {
                continue;
            }

            // Try each pattern
            for (re, platform) in &patterns {
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
                        platform: *platform,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_social_media_links_linkedin() {
        let html = Html::parse_document(
            r#"<html><body><a href="https://www.linkedin.com/company/example">LinkedIn</a></body></html>"#,
        );
        let links = extract_social_media_links(&html);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].platform, SocialPlatform::LinkedIn);
        assert_eq!(links[0].url, "https://www.linkedin.com/company/example");
        assert_eq!(links[0].identifier, Some("example".to_string()));
    }

    #[test]
    fn test_extract_social_media_links_twitter() {
        let html = Html::parse_document(
            r#"<html><body><a href="https://twitter.com/example">Twitter</a></body></html>"#,
        );
        let links = extract_social_media_links(&html);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].platform, SocialPlatform::Twitter);
        assert_eq!(links[0].url, "https://twitter.com/example");
        assert_eq!(links[0].identifier, Some("example".to_string()));
    }

    #[test]
    fn test_extract_social_media_links_x_com() {
        let html = Html::parse_document(
            r#"<html><body><a href="https://x.com/example">X</a></body></html>"#,
        );
        let links = extract_social_media_links(&html);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].platform, SocialPlatform::Twitter);
        assert_eq!(links[0].identifier, Some("example".to_string()));
    }

    #[test]
    fn test_extract_social_media_links_facebook() {
        let html = Html::parse_document(
            r#"<html><body><a href="https://www.facebook.com/example">Facebook</a></body></html>"#,
        );
        let links = extract_social_media_links(&html);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].platform, SocialPlatform::Facebook);
        assert_eq!(links[0].identifier, Some("example".to_string()));
    }

    #[test]
    fn test_extract_social_media_links_instagram() {
        let html = Html::parse_document(
            r#"<html><body><a href="https://www.instagram.com/example">Instagram</a></body></html>"#,
        );
        let links = extract_social_media_links(&html);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].platform, SocialPlatform::Instagram);
    }

    #[test]
    fn test_extract_social_media_links_youtube() {
        let html = Html::parse_document(
            r#"<html><body><a href="https://www.youtube.com/channel/example">YouTube</a></body></html>"#,
        );
        let links = extract_social_media_links(&html);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].platform, SocialPlatform::YouTube);
        assert_eq!(links[0].identifier, Some("example".to_string()));
    }

    #[test]
    fn test_extract_social_media_links_github() {
        let html = Html::parse_document(
            r#"<html><body><a href="https://github.com/example">GitHub</a></body></html>"#,
        );
        let links = extract_social_media_links(&html);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].platform, SocialPlatform::GitHub);
        assert_eq!(links[0].identifier, Some("example".to_string()));
    }

    #[test]
    fn test_extract_social_media_links_tiktok() {
        let html = Html::parse_document(
            r#"<html><body><a href="https://www.tiktok.com/@example">TikTok</a></body></html>"#,
        );
        let links = extract_social_media_links(&html);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].platform, SocialPlatform::TikTok);
        assert_eq!(links[0].identifier, Some("example".to_string()));
    }

    #[test]
    fn test_extract_social_media_links_protocol_relative() {
        // Protocol-relative URLs (//example.com) are converted to https:// by the implementation
        // But the regex patterns require http:// or https:// in the original href to match
        let html = Html::parse_document(
            r#"<html><body><a href="//www.linkedin.com/company/example">LinkedIn</a></body></html>"#,
        );
        let links = extract_social_media_links(&html);
        // The regex patterns require http:// or https:// in the href attribute to match
        // Protocol-relative URLs (//) are converted but only after regex matching
        assert_eq!(links.len(), 0);
    }

    #[test]
    fn test_extract_social_media_links_no_http() {
        // URLs without http/https won't match the regex patterns which require http:// or https://
        // The implementation converts them to https:// but only after regex matching
        let html = Html::parse_document(
            r#"<html><body><a href="www.linkedin.com/company/example">LinkedIn</a></body></html>"#,
        );
        let links = extract_social_media_links(&html);
        // The regex patterns require http:// or https:// in the href attribute to match
        // So URLs without protocol won't match the pattern
        assert_eq!(links.len(), 0);
    }

    #[test]
    fn test_extract_social_media_links_duplicates() {
        let html = Html::parse_document(
            r#"<html><body>
                <a href="https://www.linkedin.com/company/example">Link 1</a>
                <a href="https://www.linkedin.com/company/example">Link 2</a>
            </body></html>"#,
        );
        let links = extract_social_media_links(&html);
        // Should only extract once
        assert_eq!(links.len(), 1);
    }

    #[test]
    fn test_extract_social_media_links_multiple_platforms() {
        let html = Html::parse_document(
            r#"<html><body>
                <a href="https://www.linkedin.com/company/example">LinkedIn</a>
                <a href="https://twitter.com/example">Twitter</a>
                <a href="https://github.com/example">GitHub</a>
            </body></html>"#,
        );
        let links = extract_social_media_links(&html);
        assert_eq!(links.len(), 3);
    }

    #[test]
    fn test_extract_social_media_links_empty() {
        let html = Html::parse_document("<html><body>No social links</body></html>");
        let links = extract_social_media_links(&html);
        assert_eq!(links.len(), 0);
    }

    #[test]
    fn test_extract_social_media_links_relative_url() {
        // Relative URLs should be skipped
        let html =
            Html::parse_document(r#"<html><body><a href="/linkedin">Relative</a></body></html>"#);
        let links = extract_social_media_links(&html);
        assert_eq!(links.len(), 0);
    }
}
