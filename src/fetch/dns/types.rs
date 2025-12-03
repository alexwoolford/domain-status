//! DNS and TLS data structures.
//!
//! This module defines the data structures used for TLS certificate information
//! and DNS record data.

/// TLS and DNS resolution results.
#[derive(Debug)]
pub(crate) struct TlsDnsData {
    pub(crate) tls_version: Option<String>,
    pub(crate) subject: Option<String>,
    pub(crate) issuer: Option<String>,
    pub(crate) valid_from: Option<chrono::NaiveDateTime>,
    pub(crate) valid_to: Option<chrono::NaiveDateTime>,
    pub(crate) oids: Option<std::collections::HashSet<String>>,
    pub(crate) cipher_suite: Option<String>,
    pub(crate) key_algorithm: Option<String>,
    pub(crate) subject_alternative_names: Option<Vec<String>>,
    pub(crate) ip_address: String,
    pub(crate) reverse_dns_name: Option<String>,
}

/// Result of fetching TLS and DNS data, including any partial failures.
pub struct TlsDnsResult {
    pub data: TlsDnsData,
    pub partial_failures: Vec<(crate::error_handling::ErrorType, String)>, // (error_type, error_message)
}

/// Additional DNS records (NS, TXT, MX).
#[derive(Debug)]
pub(crate) struct AdditionalDnsData {
    pub(crate) nameservers: Option<String>,
    pub(crate) txt_records: Option<String>,
    pub(crate) mx_records: Option<String>,
    pub(crate) spf_record: Option<String>,
    pub(crate) dmarc_record: Option<String>,
}

/// Result of fetching additional DNS records, including any partial failures.
#[derive(Debug)]
pub struct AdditionalDnsResult {
    pub data: AdditionalDnsData,
    pub partial_failures: Vec<(crate::error_handling::ErrorType, String)>, // (error_type, error_message)
}
