//! Shared export row building logic.
//!
//! This module provides a unified way to fetch all data for a single export row,
//! eliminating duplication between CSV and JSONL exporters.

use anyhow::Result;
use sqlx::Row;
use std::collections::HashMap;

use crate::storage::DbPool;

use super::queries::{
    fetch_count_query, fetch_filtered_http_headers, fetch_key_value_list, fetch_string_list,
};

/// Main row data from the url_status table.
#[derive(Debug)]
pub struct MainRowData {
    pub id: i64,
    pub initial_domain: String,
    pub final_domain: String,
    pub ip_address: String,
    pub reverse_dns: Option<String>,
    pub status: u16,
    pub status_desc: String,
    pub response_time: f64,
    pub title: String,
    pub keywords: Option<String>,
    pub description: Option<String>,
    pub is_mobile_friendly: bool,
    pub tls_version: Option<String>,
    pub ssl_cert_subject: Option<String>,
    pub ssl_cert_issuer: Option<String>,
    pub ssl_cert_valid_to_ms: Option<i64>,
    pub cipher_suite: Option<String>,
    pub key_algorithm: Option<String>,
    pub spf_record: Option<String>,
    pub dmarc_record: Option<String>,
    pub timestamp: i64,
    pub run_id: Option<String>,
}

/// A single redirect entry.
#[derive(Debug)]
pub struct RedirectEntry {
    pub redirect_url: String,
    pub sequence_order: i64,
}

/// GeoIP data for an export row.
#[derive(Debug, Default)]
pub struct GeoIpData {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub asn: Option<i64>,
    pub asn_org: Option<String>,
}

/// WHOIS data for an export row.
#[derive(Debug, Default)]
pub struct WhoisData {
    pub registrar: Option<String>,
    pub creation_date_ms: Option<i64>,
    pub expiration_date_ms: Option<i64>,
    pub registrant_country: Option<String>,
}

/// All data for a single export row.
///
/// This struct consolidates all satellite data fetched from various tables
/// for a single URL record, providing a unified view for exporters.
#[derive(Debug)]
pub struct ExportRow {
    /// Main row data from url_status table
    pub main: MainRowData,

    /// Redirect chain
    pub redirects: Vec<RedirectEntry>,
    pub redirect_count: usize,
    pub final_redirect_url: String,

    /// Technologies (as "name:version" strings)
    pub technologies_str: String,
    pub technology_count: usize,

    /// Certificate SANs
    pub certificate_sans_str: String,
    pub certificate_san_count: usize,

    /// Certificate OIDs
    pub oids_str: String,
    pub oid_count: usize,

    /// DNS counts
    pub nameserver_count: usize,
    pub txt_count: usize,
    pub mx_count: usize,

    /// Analytics IDs (as "provider:tracking_id" strings)
    pub analytics_ids_str: String,
    pub analytics_count: usize,

    /// Social media links (as "platform:url" strings)
    pub social_media_links_str: String,
    pub social_media_count: usize,

    /// Security warnings
    pub security_warnings_str: String,
    pub security_warning_count: usize,

    /// Structured data
    pub structured_data_types_str: String,
    pub structured_data_count: usize,

    /// HTTP headers (key headers only)
    pub http_headers_str: String,
    pub http_header_count: usize,

    /// Security headers (key headers only)
    pub security_headers_str: String,
    pub security_header_count: usize,

    /// GeoIP data
    pub geoip: GeoIpData,

    /// WHOIS data
    pub whois: WhoisData,
}

/// Key HTTP headers to include in exports.
const HTTP_KEY_HEADERS: &[&str] = &[
    "Content-Type",
    "Server",
    "X-Powered-By",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy",
];

/// Key security headers to include in exports.
const SECURITY_KEY_HEADERS: &[&str] = &[
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
];

/// Extract main row data from a database row.
pub fn extract_main_row_data(row: &sqlx::sqlite::SqliteRow) -> MainRowData {
    MainRowData {
        id: row.get("id"),
        initial_domain: row.get("initial_domain"),
        final_domain: row.get("final_domain"),
        ip_address: row.get("ip_address"),
        reverse_dns: row.get("reverse_dns_name"),
        status: row.get("http_status"),
        status_desc: row.get("http_status_text"),
        response_time: row.get("response_time_seconds"),
        title: row.get("title"),
        keywords: row.get("keywords"),
        description: row.get("description"),
        is_mobile_friendly: row.get("is_mobile_friendly"),
        tls_version: row.get("tls_version"),
        ssl_cert_subject: row.get("ssl_cert_subject"),
        ssl_cert_issuer: row.get("ssl_cert_issuer"),
        ssl_cert_valid_to_ms: row.get("ssl_cert_valid_to_ms"),
        cipher_suite: row.get("cipher_suite"),
        key_algorithm: row.get("key_algorithm"),
        spf_record: row.get("spf_record"),
        dmarc_record: row.get("dmarc_record"),
        timestamp: row.get("observed_at_ms"),
        run_id: row.get("run_id"),
    }
}

/// Build a complete export row by fetching all satellite data.
///
/// This function takes the main row data and fetches all related data
/// from satellite tables, constructing a complete `ExportRow`.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `main` - Main row data extracted from the url_status table
///
/// # Returns
///
/// A complete `ExportRow` with all satellite data populated.
#[allow(clippy::too_many_lines)]
pub async fn build_export_row(pool: &DbPool, main: MainRowData) -> Result<ExportRow> {
    let url_status_id = main.id;

    // Fetch redirect chain
    let redirect_rows = sqlx::query(
        "SELECT redirect_url, sequence_order FROM url_redirect_chain
         WHERE url_status_id = ? ORDER BY sequence_order",
    )
    .bind(url_status_id)
    .fetch_all(pool.as_ref())
    .await?;

    let redirects: Vec<RedirectEntry> = redirect_rows
        .iter()
        .map(|r| RedirectEntry {
            redirect_url: r.get("redirect_url"),
            sequence_order: r.get("sequence_order"),
        })
        .collect();

    let redirect_count = redirects.len();
    let final_redirect_url = redirects
        .last()
        .map(|r| r.redirect_url.clone())
        .unwrap_or_default();

    // Fetch technologies
    let (technologies_str, technology_count) = fetch_key_value_list(
        pool,
        "SELECT technology_name, technology_version FROM url_technologies WHERE url_status_id = ? ORDER BY technology_name",
        "technology_name",
        "technology_version",
        url_status_id,
    )
    .await?;

    // Fetch certificate SANs
    let (certificate_sans_str, certificate_san_count) = fetch_string_list(
        pool,
        "SELECT san_value FROM url_certificate_sans WHERE url_status_id = ? ORDER BY san_value",
        url_status_id,
    )
    .await?;

    // Fetch OIDs
    let (oids_str, oid_count) = fetch_string_list(
        pool,
        "SELECT oid FROM url_certificate_oids WHERE url_status_id = ? ORDER BY oid",
        url_status_id,
    )
    .await?;

    // Fetch DNS counts
    let nameserver_count = fetch_count_query(
        pool,
        "SELECT COUNT(*) FROM url_nameservers WHERE url_status_id = ?",
        url_status_id,
    )
    .await?;

    let txt_count = fetch_count_query(
        pool,
        "SELECT COUNT(*) FROM url_txt_records WHERE url_status_id = ?",
        url_status_id,
    )
    .await?;

    let mx_count = fetch_count_query(
        pool,
        "SELECT COUNT(*) FROM url_mx_records WHERE url_status_id = ?",
        url_status_id,
    )
    .await?;

    // Fetch analytics IDs
    let (analytics_ids_str, analytics_count) = fetch_key_value_list(
        pool,
        "SELECT provider, tracking_id FROM url_analytics_ids WHERE url_status_id = ? ORDER BY provider, tracking_id",
        "provider",
        "tracking_id",
        url_status_id,
    )
    .await?;

    // Fetch social media links
    let (social_media_links_str, social_media_count) = fetch_key_value_list(
        pool,
        "SELECT platform, profile_url FROM url_social_media_links WHERE url_status_id = ? ORDER BY platform, profile_url",
        "platform",
        "profile_url",
        url_status_id,
    )
    .await?;

    // Fetch security warnings
    let (security_warnings_str, security_warning_count) = fetch_string_list(
        pool,
        "SELECT warning_code FROM url_security_warnings WHERE url_status_id = ? ORDER BY warning_code",
        url_status_id,
    )
    .await?;

    // Fetch structured data types
    let (structured_data_types_str, _) = fetch_string_list(
        pool,
        "SELECT DISTINCT data_type FROM url_structured_data WHERE url_status_id = ? ORDER BY data_type",
        url_status_id,
    )
    .await?;

    let structured_data_count = fetch_count_query(
        pool,
        "SELECT COUNT(*) FROM url_structured_data WHERE url_status_id = ?",
        url_status_id,
    )
    .await?;

    // Fetch HTTP headers
    let (http_headers_str, http_header_count) =
        fetch_filtered_http_headers(pool, "url_http_headers", url_status_id, HTTP_KEY_HEADERS)
            .await?;

    // Fetch security headers
    let (security_headers_str, security_header_count) = fetch_filtered_http_headers(
        pool,
        "url_security_headers",
        url_status_id,
        SECURITY_KEY_HEADERS,
    )
    .await?;

    // Fetch GeoIP data
    let geoip_row = sqlx::query(
        "SELECT country_code, country_name, region, city, latitude, longitude, asn, asn_org
         FROM url_geoip WHERE url_status_id = ?",
    )
    .bind(url_status_id)
    .fetch_optional(pool.as_ref())
    .await?;

    let geoip = if let Some(row) = geoip_row {
        GeoIpData {
            country_code: row.get("country_code"),
            country_name: row.get("country_name"),
            region: row.get("region"),
            city: row.get("city"),
            latitude: row.get("latitude"),
            longitude: row.get("longitude"),
            asn: row.get("asn"),
            asn_org: row.get("asn_org"),
        }
    } else {
        GeoIpData::default()
    };

    // Fetch WHOIS data
    let whois_row = sqlx::query(
        "SELECT registrar, creation_date_ms, expiration_date_ms, registrant_country
         FROM url_whois WHERE url_status_id = ?",
    )
    .bind(url_status_id)
    .fetch_optional(pool.as_ref())
    .await?;

    let whois = if let Some(row) = whois_row {
        WhoisData {
            registrar: row.get("registrar"),
            creation_date_ms: row.get("creation_date_ms"),
            expiration_date_ms: row.get("expiration_date_ms"),
            registrant_country: row.get("registrant_country"),
        }
    } else {
        WhoisData::default()
    };

    // SAFETY: All count values are non-negative database counts that fit in usize.
    // These casts are safe because:
    // 1. SQL COUNT(*) always returns non-negative values
    // 2. Realistic table sizes are well within usize range
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    Ok(ExportRow {
        main,
        redirects,
        redirect_count,
        final_redirect_url,
        technologies_str,
        technology_count,
        certificate_sans_str,
        certificate_san_count,
        oids_str,
        oid_count,
        nameserver_count: nameserver_count as usize,
        txt_count: txt_count as usize,
        mx_count: mx_count as usize,
        analytics_ids_str,
        analytics_count,
        social_media_links_str,
        social_media_count,
        security_warnings_str,
        security_warning_count,
        structured_data_types_str,
        structured_data_count: structured_data_count as usize,
        http_headers_str,
        http_header_count: http_header_count as usize,
        security_headers_str,
        security_header_count: security_header_count as usize,
        geoip,
        whois,
    })
}

/// Parse technologies string into a list of (name, version) tuples.
///
/// The input string is in format "name1:version1,name2:version2,..."
pub fn parse_technologies(technologies_str: &str) -> Vec<(String, Option<String>)> {
    if technologies_str.is_empty() {
        return vec![];
    }

    technologies_str
        .split(',')
        .filter_map(|s| {
            let parts: Vec<&str> = s.split(':').collect();
            if !parts.is_empty() && !parts[0].is_empty() {
                let name = parts[0].to_string();
                let version = if parts.len() >= 2 && !parts[1].is_empty() {
                    Some(parts[1].to_string())
                } else {
                    None
                };
                Some((name, version))
            } else {
                None
            }
        })
        .collect()
}

/// Parse key-value string into a list of (key, value) tuples.
///
/// The input string is in format "key1:value1,key2:value2,..."
pub fn parse_key_value_pairs(kv_str: &str) -> Vec<(String, String)> {
    if kv_str.is_empty() {
        return vec![];
    }

    kv_str
        .split(',')
        .filter_map(|s| {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() >= 2 {
                Some((parts[0].to_string(), parts[1].to_string()))
            } else {
                None
            }
        })
        .collect()
}

/// Parse headers string into a HashMap.
///
/// The input string is in format "header1:value1;header2:value2;..."
/// Note: values may contain colons, so we only split on the first colon.
pub fn parse_headers(headers_str: &str) -> HashMap<String, String> {
    if headers_str.is_empty() {
        return HashMap::new();
    }

    headers_str
        .split(';')
        .filter_map(|s| {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() >= 2 {
                Some((parts[0].to_string(), parts[1..].join(":")))
            } else {
                None
            }
        })
        .collect()
}

/// Parse a comma-separated string into a Vec of strings.
pub fn parse_string_list(list_str: &str) -> Vec<String> {
    if list_str.is_empty() {
        return vec![];
    }

    list_str.split(',').map(|s| s.to_string()).collect()
}

/// Build the URL from final_domain.
pub fn build_url(final_domain: &str) -> String {
    if final_domain.starts_with("http://") || final_domain.starts_with("https://") {
        final_domain.to_string()
    } else {
        format!("https://{}", final_domain)
    }
}
