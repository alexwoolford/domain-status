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
    // Removed: technologies (now passed directly to insert_url_record, not stored in url_status table)
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

/// Represents a failed URL processing attempt for database insertion.
///
/// Contains information about why a URL processing failed, including error type,
/// error message, and any context that was available before the failure
/// (e.g., redirect chain, response headers).
///
/// # Database Schema
///
/// This struct maps to the `url_failures` table. The `timestamp` field
/// is stored as milliseconds since Unix epoch.
pub struct UrlFailureRecord {
    pub url: String,
    pub final_url: Option<String>,    // URL after redirects (if any)
    pub domain: String,               // Initial domain extracted from original URL
    pub final_domain: Option<String>, // Final domain after redirects (if any)
    pub error_type: String,           // ErrorType enum value as string
    pub error_message: String,        // Full error message
    pub http_status: Option<u16>,     // HTTP status code if available (e.g., 403, 500)
    pub retry_count: u32,             // Number of retry attempts made
    pub elapsed_time_seconds: Option<f64>, // Time spent before failure
    pub timestamp: i64,               // When the failure occurred
    pub run_id: Option<String>,       // Foreign key to runs.run_id
    pub redirect_chain: Vec<String>,  // Redirect chain before failure (if any)
    pub response_headers: Vec<(String, String)>, // Response headers received (if any)
    pub request_headers: Vec<(String, String)>, // Request headers sent (for debugging)
}

/// Represents a partial failure (DNS/TLS error that didn't prevent URL processing).
///
/// These are errors that occurred during supplementary data collection (DNS, TLS)
/// but didn't prevent the URL from being successfully processed. The URL was
/// processed, but some optional data is missing.
///
/// # Database Schema
///
/// This struct maps to the `url_partial_failures` table. The `timestamp` field
/// is stored as milliseconds since Unix epoch.
pub struct UrlPartialFailureRecord {
    pub url_status_id: i64,     // Foreign key to url_status.id
    pub error_type: String,     // ErrorType enum value (DNS/TLS errors)
    pub error_message: String,  // Full error message
    pub timestamp: i64,         // When the failure occurred
    pub run_id: Option<String>, // Foreign key to runs.run_id
}
