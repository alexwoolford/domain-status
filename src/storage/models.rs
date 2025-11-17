// storage/models.rs
// Database models and types

use chrono::NaiveDateTime;

/// Represents a complete URL status record for database insertion.
///
/// Contains all data extracted from a URL check including HTTP response details,
/// HTML metadata, DNS information, TLS certificate data, and security headers.
///
/// # Database Schema
///
/// This struct maps directly to the `url_status` table. The `timestamp` field
/// is stored as milliseconds since Unix epoch. All string fields that can be
/// empty are stored as `TEXT NOT NULL` with empty strings as fallback.
pub struct UrlRecord {
    pub initial_domain: String,
    pub final_domain: String,
    pub ip_address: String,
    pub reverse_dns_name: Option<String>,
    pub status: u16,
    pub status_desc: String,
    pub response_time: f64,
    pub title: String,
    pub keywords: Option<String>,
    pub description: Option<String>,
    pub tls_version: Option<String>,
    pub ssl_cert_subject: Option<String>,
    pub ssl_cert_issuer: Option<String>,
    pub ssl_cert_valid_from: Option<NaiveDateTime>,
    pub ssl_cert_valid_to: Option<NaiveDateTime>,
    pub is_mobile_friendly: bool,
    pub timestamp: i64,
    pub technologies: Option<String>,
    // Removed: fingerprints_source and fingerprints_version (now stored in runs table)
    pub nameservers: Option<String>,
    pub txt_records: Option<String>,
    pub mx_records: Option<String>,
    pub spf_record: Option<String>,
    pub dmarc_record: Option<String>,
    pub cipher_suite: Option<String>,
    pub key_algorithm: Option<String>,
    pub run_id: Option<String>,
}
