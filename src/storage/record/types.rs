//! Complete record data structure.
//!
//! This module defines the `PersistedUrlRecord` type, which contains all data
//! needed to insert a complete URL record and its enrichment data.
//!
//! Records are written directly to the database immediately; the aggregate
//! groups one URL row with all related enrichment data.

use std::collections::HashMap;
use std::collections::HashSet;

use crate::geoip::GeoIpResult;
use crate::parse::{AnalyticsId, ContactLink, ExposedSecret, SocialMediaLink, StructuredData};
use crate::whois::WhoisResult;

use crate::storage::models::{UrlPartialFailureRecord, UrlRecord};

/// A complete record ready for database insertion.
///
/// This struct contains all data needed to insert a URL record and
/// all its associated enrichment data (`GeoIP`, WHOIS, structured data, etc.).
pub struct PersistedUrlRecord {
    pub url_record: UrlRecord,
    pub security_headers: HashMap<String, String>,
    pub http_headers: HashMap<String, String>,
    pub oids: HashSet<String>,
    pub redirect_chain: Vec<(String, u16)>, // (url, http_status) per redirect hop
    pub technologies: Vec<crate::fingerprint::DetectedTechnology>,
    pub subject_alternative_names: Vec<String>, // Certificate SANs (for linking domains sharing certificates)
    pub analytics_ids: Vec<AnalyticsId>, // Analytics/tracking IDs (GA, Facebook Pixel, GTM, AdSense)
    pub geoip: Option<(String, GeoIpResult)>, // (ip_address, geoip_result)
    pub structured_data: Option<StructuredData>,
    pub social_media_links: Vec<SocialMediaLink>,
    pub contact_links: Vec<ContactLink>,
    pub exposed_secrets: Vec<ExposedSecret>,
    pub whois: Option<WhoisResult>,
    pub partial_failures: Vec<UrlPartialFailureRecord>, // DNS/TLS errors that didn't prevent processing
    pub favicon: Option<crate::fetch::favicon::FaviconData>, // Shodan-compatible favicon hash + URL
    pub cname_records: Option<String>,                  // CNAME records JSON (satellite table)
    pub aaaa_records: Option<String>,                   // IPv6 addresses JSON (satellite table)
    pub caa_records: Option<String>,                    // CAA records JSON (satellite table)
    pub csp_domains: Vec<(String, String, Option<String>)>, // (directive, fqdn, registrable_domain)
    pub cookies: Vec<CookieInfo>,
    pub resource_hints: Vec<(String, String)>, // (hint_type, href); hint_type: preconnect/dns-prefetch/preload/prefetch/modulepreload
    /// Unique hosts from `<script src>` (resolved against final URL)
    pub script_hosts: Vec<ScriptHostInfo>,
    pub security_txt: Option<crate::fetch::well_known::SecurityTxtData>,
    pub robots_txt: Option<crate::fetch::well_known::RobotsTxtData>,
}

/// Parsed cookie security attributes.
#[derive(Debug)]
pub struct CookieInfo {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
    pub domain: Option<String>,
    pub path: Option<String>,
}

/// Host inventory entry from a page's `<script src>` attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptHostInfo {
    pub host: String,
    pub registrable_domain: Option<String>,
    pub is_first_party: bool,
}
