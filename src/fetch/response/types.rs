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
    pub(crate) analytics_ids: Vec<crate::parse::AnalyticsId>, // Analytics/tracking IDs (GA, Facebook Pixel, GTM, AdSense)
    pub(crate) meta_tags: HashMap<String, String>,
    pub(crate) script_sources: Vec<String>,
    pub(crate) script_content: String, // Inline script content for js field detection
    pub(crate) script_tag_ids: HashSet<String>, // Script tag IDs (for __NEXT_DATA__ etc.)
    #[allow(dead_code)]
    // Kept for potential future use, but currently using html_body in detection
    pub(crate) html_text: String,
}
