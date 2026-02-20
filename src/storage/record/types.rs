//! Complete record data structure.
//!
//! This module defines the BatchRecord type, which contains all data
//! needed to insert a complete URL record and its enrichment data.
//!
//! **Note:** Despite the name "BatchRecord", records are NOT batched.
//! They are written directly to the database immediately. The name is
//! historical - it represents a "batch" of related data (URL + enrichment)
//! that gets inserted together, not a batching optimization.

use std::collections::HashMap;
use std::collections::HashSet;

use crate::geoip::GeoIpResult;
use crate::parse::{AnalyticsId, SocialMediaLink, StructuredData};
use crate::security::SecurityWarning;
use crate::whois::WhoisResult;

use crate::storage::models::{UrlPartialFailureRecord, UrlRecord};

/// A complete record ready for database insertion.
///
/// This struct contains all data needed to insert a URL record and
/// all its associated enrichment data (GeoIP, WHOIS, structured data, etc.).
pub struct BatchRecord {
    pub url_record: UrlRecord,
    pub security_headers: HashMap<String, String>,
    pub http_headers: HashMap<String, String>,
    pub oids: HashSet<String>,
    pub redirect_chain: Vec<String>,
    pub technologies: Vec<crate::fingerprint::DetectedTechnology>,
    pub subject_alternative_names: Vec<String>, // Certificate SANs (for linking domains sharing certificates)
    pub analytics_ids: Vec<AnalyticsId>, // Analytics/tracking IDs (GA, Facebook Pixel, GTM, AdSense)
    pub geoip: Option<(String, GeoIpResult)>, // (ip_address, geoip_result)
    pub structured_data: Option<StructuredData>,
    pub social_media_links: Vec<SocialMediaLink>,
    pub security_warnings: Vec<SecurityWarning>,
    pub whois: Option<WhoisResult>,
    pub partial_failures: Vec<UrlPartialFailureRecord>, // DNS/TLS errors that didn't prevent processing
    pub favicon: Option<crate::fetch::favicon::FaviconData>, // Favicon hash + base64 for Shodan-compatible threat intel
}
