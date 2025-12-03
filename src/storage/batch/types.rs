//! Batch record data structure.
//!
//! This module defines the BatchRecord type, which contains all data
//! needed to insert a complete URL record and its enrichment data.

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
    pub technologies: Vec<String>,
    pub subject_alternative_names: Vec<String>, // Certificate SANs (for linking domains sharing certificates)
    pub analytics_ids: Vec<AnalyticsId>, // Analytics/tracking IDs (GA, Facebook Pixel, GTM, AdSense)
    pub geoip: Option<(String, GeoIpResult)>, // (ip_address, geoip_result)
    pub structured_data: Option<StructuredData>,
    pub social_media_links: Vec<SocialMediaLink>,
    pub security_warnings: Vec<SecurityWarning>,
    pub whois: Option<WhoisResult>,
    pub partial_failures: Vec<UrlPartialFailureRecord>, // DNS/TLS errors that didn't prevent processing
}
