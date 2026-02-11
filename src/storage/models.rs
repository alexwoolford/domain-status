//! Database models and types.
//!
//! This module defines the data structures used for database operations:
//! - `UrlRecord` - Main URL status record
//! - `BatchRecord` - Complete record with all satellite data (despite the name, records are NOT batched - they're written immediately)
//!
//! All models use `Option<T>` for nullable fields to match SQLite's type system.

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
    /// The original domain/URL before any redirects
    pub initial_domain: String,
    /// The final domain/URL after following redirects
    pub final_domain: String,
    /// The resolved IP address of the final domain
    pub ip_address: String,
    /// Reverse DNS lookup result for the IP address
    pub reverse_dns_name: Option<String>,
    /// HTTP status code (e.g., 200, 404, 500)
    pub status: u16,
    /// Human-readable status description
    pub status_desc: String,
    /// Response time in seconds
    pub response_time: f64,
    /// HTML page title
    pub title: String,
    /// HTML meta keywords
    pub keywords: Option<String>,
    /// HTML meta description
    pub description: Option<String>,
    /// TLS version (e.g., "TLSv1.3")
    pub tls_version: Option<String>,
    /// SSL certificate subject (e.g., "CN=example.com")
    pub ssl_cert_subject: Option<String>,
    /// SSL certificate issuer
    pub ssl_cert_issuer: Option<String>,
    /// SSL certificate valid from date
    pub ssl_cert_valid_from: Option<NaiveDateTime>,
    /// SSL certificate valid to date
    pub ssl_cert_valid_to: Option<NaiveDateTime>,
    /// Whether the page is mobile-friendly
    pub is_mobile_friendly: bool,
    /// Timestamp of the check (milliseconds since Unix epoch)
    pub timestamp: i64,
    /// JSON array of DNS nameservers
    pub nameservers: Option<String>,
    /// JSON array of TXT DNS records
    pub txt_records: Option<String>,
    /// JSON array of MX DNS records
    pub mx_records: Option<String>,
    /// SPF record content
    pub spf_record: Option<String>,
    /// DMARC record content
    pub dmarc_record: Option<String>,
    /// TLS cipher suite used
    pub cipher_suite: Option<String>,
    /// TLS key exchange algorithm
    pub key_algorithm: Option<String>,
    /// ID of the scan run this record belongs to
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
