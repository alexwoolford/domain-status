//! Response data structures.

use std::collections::{HashMap, HashSet};

/// Extracted response data from HTTP response.
#[derive(Debug)]
pub(crate) struct ResponseData {
    pub(crate) final_url: String,
    pub(crate) initial_domain: String,
    pub(crate) final_domain: String,
    pub(crate) host: String,
    pub(crate) status: u16,
    pub(crate) status_desc: String,
    pub(crate) headers: reqwest::header::HeaderMap,
    pub(crate) security_headers: HashMap<String, String>,
    pub(crate) http_headers: HashMap<String, String>,
    pub(crate) body: String,
    pub(crate) body_sha256: Option<String>,
    pub(crate) content_length: Option<i64>,
    pub(crate) http_version: Option<String>,
    pub(crate) body_word_count: Option<i64>,
    pub(crate) body_line_count: Option<i64>,
    pub(crate) content_type: Option<String>,
}

/// Extracted HTML data from parsed document.
#[derive(Debug)]
pub(crate) struct HtmlData {
    pub(crate) title: String,
    pub(crate) keywords_str: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) is_mobile_friendly: bool,
    pub(crate) structured_data: crate::parse::StructuredData,
    pub(crate) social_media_links: Vec<crate::parse::SocialMediaLink>,
    pub(crate) contact_links: Vec<crate::parse::ContactLink>,
    pub(crate) exposed_secrets: Vec<crate::parse::ExposedSecret>,
    pub(crate) analytics_ids: Vec<crate::parse::AnalyticsId>, // Analytics/tracking IDs (GA, Facebook Pixel, GTM, AdSense)
    pub(crate) meta_tags: HashMap<String, Vec<String>>, // Vec to handle multiple meta tags with same name (e.g., multiple generator tags)
    pub(crate) script_sources: Vec<String>,
    pub(crate) script_content: String, // Inline script content for js field detection
    pub(crate) script_tag_ids: HashSet<String>, // Script tag IDs (for __NEXT_DATA__ etc.)
    #[allow(dead_code)]
    // Kept for potential future use, but currently using html_body in detection
    pub(crate) html_text: String,
    pub(crate) favicon_url: Option<String>, // Favicon URL extracted from <link rel="icon"> tags
    pub(crate) canonical_url: Option<String>, // Canonical URL from <link rel="canonical">
    pub(crate) meta_refresh_url: Option<String>, // Meta refresh redirect URL
    pub(crate) resource_hints: Vec<(String, String)>, // (hint_type, href) for preconnect/dns-prefetch
    pub(crate) body_domains: Vec<(String, Option<String>)>, // (fqdn, registrable_domain) from href/src attrs
}
