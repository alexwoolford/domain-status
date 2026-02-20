//! Record building utilities.
//!
//! These functions are optimized to minimize clones in the hot path:
//! - `build_url_record` clones ~15 small strings (unavoidable for UrlRecord fields)
//! - `build_batch_record` takes ownership and **moves** large collections (HashMaps, Vecs)
//!   instead of cloning them, saving ~5-10KB of allocations per URL

use crate::database::UrlRecord;
use crate::fetch::dns::{AdditionalDnsData, TlsDnsData};
use crate::fetch::response::{HtmlData, ResponseData};
use crate::storage::BatchRecord;

/// Builds a UrlRecord from extracted response data.
///
/// This function clones string fields from the input data. While this involves
/// ~15 small string allocations, these are necessary to create an independent
/// UrlRecord. The expensive HashMap/Vec data is handled by `build_batch_record`
/// which takes ownership to avoid cloning.
pub(crate) fn build_url_record(
    resp_data: &ResponseData,
    html_data: &HtmlData,
    tls_dns_data: &TlsDnsData,
    additional_dns: &AdditionalDnsData,
    elapsed: f64,
    timestamp: i64,
    run_id: &Option<String>,
) -> UrlRecord {
    UrlRecord {
        initial_domain: resp_data.initial_domain.clone(),
        final_domain: resp_data.final_domain.clone(),
        ip_address: tls_dns_data.ip_address.clone(),
        reverse_dns_name: tls_dns_data.reverse_dns_name.clone(),
        status: resp_data.status,
        status_desc: resp_data.status_desc.clone(),
        response_time: elapsed,
        title: html_data.title.clone(),
        // Normalize empty strings to None for consistency with database queries
        // Use filter_map to avoid unnecessary clone when string is empty
        keywords: html_data
            .keywords_str
            .as_ref()
            .filter(|k| !k.is_empty())
            .cloned(),
        // Normalize empty strings to None for consistency with database queries
        description: html_data
            .description
            .as_ref()
            .filter(|d| !d.is_empty())
            .cloned(),
        tls_version: tls_dns_data.tls_version,
        ssl_cert_subject: tls_dns_data.subject.clone(),
        ssl_cert_issuer: tls_dns_data.issuer.clone(),
        ssl_cert_valid_from: tls_dns_data.valid_from,
        ssl_cert_valid_to: tls_dns_data.valid_to,
        is_mobile_friendly: html_data.is_mobile_friendly,
        timestamp,
        nameservers: additional_dns.nameservers.clone(),
        txt_records: additional_dns.txt_records.clone(),
        mx_records: additional_dns.mx_records.clone(),
        spf_record: additional_dns.spf_record.clone(),
        dmarc_record: additional_dns.dmarc_record.clone(),
        cipher_suite: tls_dns_data.cipher_suite.clone(),
        key_algorithm: tls_dns_data.key_algorithm.clone(),
        run_id: run_id.clone(),
    }
}

/// Parameters for building a BatchRecord.
///
/// This struct **owns** the response, HTML, and TLS/DNS data to enable moving
/// large collections (HashMaps, Vecs) into the BatchRecord instead of cloning.
/// This eliminates ~5-10KB of heap allocations per URL in the hot path.
pub struct BatchRecordParams {
    /// The URL record to include in the batch
    pub record: UrlRecord,
    /// Response data (headers, status, etc.) - owned to move HashMaps
    pub resp_data: ResponseData,
    /// HTML parsing results - owned to move Vecs
    pub html_data: HtmlData,
    /// TLS and DNS data - owned to move HashSet and Vec
    pub tls_dns_data: TlsDnsData,
    /// Detected technologies
    pub technologies_vec: Vec<crate::fingerprint::DetectedTechnology>,
    /// Redirect chain URLs
    pub redirect_chain: Vec<String>,
    /// Partial failures (DNS/TLS errors that didn't prevent processing)
    pub partial_failures: Vec<(crate::error_handling::ErrorType, String)>,
    /// GeoIP lookup result (IP address and data)
    pub geoip_data: Option<(String, crate::geoip::GeoIpResult)>,
    /// Security warnings
    pub security_warnings: Vec<crate::security::SecurityWarning>,
    /// WHOIS lookup result
    pub whois_data: Option<crate::whois::WhoisResult>,
    /// Timestamp for the record
    pub timestamp: i64,
    /// Run identifier
    pub run_id: Option<String>,
    /// Favicon data (hash + base64)
    pub favicon: Option<crate::fetch::favicon::FaviconData>,
}

/// Builds a BatchRecord from all extracted data.
///
/// Takes ownership of params to **move** large collections instead of cloning:
/// - `security_headers` and `http_headers` HashMaps from ResponseData
/// - `oids` HashSet and `subject_alternative_names` Vec from TlsDnsData
/// - `analytics_ids`, `structured_data`, `social_media_links` from HtmlData
///
/// This saves ~5-10KB of heap allocations per URL compared to cloning.
///
/// # Arguments
///
/// * `params` - Parameters for building the batch record (ownership transferred)
pub(crate) fn build_batch_record(mut params: BatchRecordParams) -> BatchRecord {
    // Move OIDs HashSet instead of cloning (avoids HashSet allocation)
    let oids_set: std::collections::HashSet<String> =
        params.tls_dns_data.oids.take().unwrap_or_default();

    let partial_failure_records: Vec<crate::storage::models::UrlPartialFailureRecord> = params
        .partial_failures
        .into_iter()
        .map(|(error_type, error_message)| {
            crate::storage::models::UrlPartialFailureRecord {
                url_status_id: 0, // Will be set when record is inserted
                error_type,
                error_message,
                timestamp: params.timestamp,
                run_id: params.run_id.clone(),
            }
        })
        .collect();

    // Move SANs Vec instead of cloning (avoids Vec allocation)
    let sans_vec: Vec<String> = params
        .tls_dns_data
        .subject_alternative_names
        .take()
        .unwrap_or_default();

    // Move analytics_ids, structured_data, social_media_links instead of cloning
    let analytics_ids = std::mem::take(&mut params.html_data.analytics_ids);
    let structured_data = std::mem::take(&mut params.html_data.structured_data);
    let social_media_links = std::mem::take(&mut params.html_data.social_media_links);

    // Move security_headers and http_headers HashMaps instead of cloning
    // These are the most expensive clones (~2-5KB each for typical responses)
    let security_headers = std::mem::take(&mut params.resp_data.security_headers);
    let http_headers = std::mem::take(&mut params.resp_data.http_headers);

    BatchRecord {
        url_record: params.record,
        security_headers,
        http_headers,
        oids: oids_set,
        redirect_chain: params.redirect_chain,
        technologies: params.technologies_vec,
        subject_alternative_names: sans_vec,
        analytics_ids,
        geoip: params.geoip_data,
        structured_data: Some(structured_data),
        social_media_links,
        security_warnings: params.security_warnings,
        whois: params.whois_data,
        partial_failures: partial_failure_records,
        favicon: params.favicon,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ErrorType;
    use crate::fetch::dns::{AdditionalDnsData, TlsDnsData};
    use crate::fetch::response::{HtmlData, ResponseData};
    use crate::geoip::GeoIpResult;
    use crate::parse::StructuredData;
    use crate::security::SecurityWarning;
    use crate::whois::WhoisResult;
    use chrono::NaiveDateTime;
    use reqwest::header::HeaderMap;
    use std::collections::{HashMap, HashSet};

    fn create_test_response_data() -> ResponseData {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_SECURITY_POLICY,
            "default-src 'self'".parse().unwrap(),
        );
        ResponseData {
            final_url: "https://example.com".to_string(),
            initial_domain: "example.com".to_string(),
            final_domain: "example.com".to_string(),
            host: "example.com".to_string(),
            status: 200,
            status_desc: "OK".to_string(),
            headers,
            security_headers: HashMap::new(),
            http_headers: HashMap::new(),
            body: "<html><head><title>Test</title></head></html>".to_string(),
        }
    }

    fn create_test_html_data() -> HtmlData {
        HtmlData {
            title: "Test Page".to_string(),
            keywords_str: Some("test, keywords".to_string()),
            description: Some("Test description".to_string()),
            is_mobile_friendly: true,
            structured_data: StructuredData::default(),
            social_media_links: vec![],
            analytics_ids: vec![],
            meta_tags: HashMap::new(),
            script_sources: vec![],
            script_content: String::new(),
            script_tag_ids: HashSet::new(),
            html_text: "Test content".to_string(),
            favicon_url: None,
        }
    }

    fn create_test_tls_dns_data() -> TlsDnsData {
        TlsDnsData {
            tls_version: Some(crate::models::TlsVersion::Tls13),
            subject: Some("CN=example.com".to_string()),
            issuer: Some("CN=Let's Encrypt".to_string()),
            valid_from: Some(
                NaiveDateTime::parse_from_str("2024-01-01 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap(),
            ),
            valid_to: Some(
                NaiveDateTime::parse_from_str("2024-12-31 23:59:59", "%Y-%m-%d %H:%M:%S").unwrap(),
            ),
            oids: Some(HashSet::new()),
            cipher_suite: Some("TLS_AES_256_GCM_SHA384".to_string()),
            key_algorithm: Some(crate::models::KeyAlgorithm::RSA),
            subject_alternative_names: Some(vec!["example.com".to_string()]),
            ip_address: "192.0.2.1".to_string(),
            reverse_dns_name: Some("example.com".to_string()),
        }
    }

    fn create_test_additional_dns_data() -> AdditionalDnsData {
        AdditionalDnsData {
            nameservers: Some("ns1.example.com,ns2.example.com".to_string()),
            txt_records: Some("v=spf1 include:_spf.google.com ~all".to_string()),
            mx_records: Some("10 mail.example.com".to_string()),
            spf_record: Some("v=spf1 include:_spf.google.com ~all".to_string()),
            dmarc_record: Some("v=DMARC1; p=none".to_string()),
        }
    }

    #[test]
    fn test_build_url_record_basic() {
        let resp_data = create_test_response_data();
        let html_data = create_test_html_data();
        let tls_dns_data = create_test_tls_dns_data();
        let additional_dns = create_test_additional_dns_data();
        let run_id = Some("test-run-123".to_string());

        let record = build_url_record(
            &resp_data,
            &html_data,
            &tls_dns_data,
            &additional_dns,
            1.5,
            1234567890,
            &run_id,
        );

        assert_eq!(record.initial_domain, "example.com");
        assert_eq!(record.final_domain, "example.com");
        assert_eq!(record.ip_address, "192.0.2.1");
        assert_eq!(record.status, 200);
        assert_eq!(record.title, "Test Page");
        assert_eq!(record.keywords, Some("test, keywords".to_string()));
        assert_eq!(record.description, Some("Test description".to_string()));
        assert_eq!(record.tls_version, Some(crate::models::TlsVersion::Tls13));
        assert_eq!(record.run_id, run_id);
    }

    #[test]
    fn test_build_url_record_empty_strings_normalized() {
        let resp_data = create_test_response_data();
        let mut html_data = create_test_html_data();
        html_data.keywords_str = Some("".to_string());
        html_data.description = Some("".to_string());
        let tls_dns_data = create_test_tls_dns_data();
        let additional_dns = create_test_additional_dns_data();

        let record = build_url_record(
            &resp_data,
            &html_data,
            &tls_dns_data,
            &additional_dns,
            1.5,
            1234567890,
            &None,
        );

        // Empty strings should be normalized to None
        assert_eq!(record.keywords, None);
        assert_eq!(record.description, None);
    }

    #[test]
    fn test_build_url_record_none_fields() {
        let resp_data = create_test_response_data();
        let mut html_data = create_test_html_data();
        html_data.keywords_str = None;
        html_data.description = None;
        let tls_dns_data = create_test_tls_dns_data();
        let additional_dns = create_test_additional_dns_data();

        let record = build_url_record(
            &resp_data,
            &html_data,
            &tls_dns_data,
            &additional_dns,
            1.5,
            1234567890,
            &None,
        );

        assert_eq!(record.keywords, None);
        assert_eq!(record.description, None);
    }

    #[test]
    fn test_build_batch_record_basic() {
        let resp_data = create_test_response_data();
        let html_data = create_test_html_data();
        let tls_dns_data = create_test_tls_dns_data();
        let additional_dns = create_test_additional_dns_data();
        let run_id = Some("test-run-123".to_string());

        let url_record = build_url_record(
            &resp_data,
            &html_data,
            &tls_dns_data,
            &additional_dns,
            1.5,
            1234567890,
            &run_id,
        );

        let technologies = vec![
            crate::fingerprint::DetectedTechnology {
                name: "WordPress".to_string(),
                version: None,
            },
            crate::fingerprint::DetectedTechnology {
                name: "PHP".to_string(),
                version: None,
            },
        ];
        let redirect_chain = vec!["https://example.com".to_string()];
        let partial_failures = vec![(ErrorType::DnsNsLookupError, "DNS lookup failed".to_string())];
        let geoip_data = Some((
            "192.0.2.1".to_string(),
            GeoIpResult {
                country_code: Some("US".to_string()),
                country_name: Some("United States".to_string()),
                ..Default::default()
            },
        ));
        let security_warnings = vec![SecurityWarning::NoHttps];
        let whois_data = Some(WhoisResult {
            registrar: Some("Example Registrar".to_string()),
            ..Default::default()
        });

        let batch_record = build_batch_record(BatchRecordParams {
            record: url_record,
            resp_data,
            html_data,
            tls_dns_data,
            technologies_vec: technologies.clone(),
            redirect_chain,
            partial_failures,
            geoip_data,
            security_warnings,
            whois_data,
            timestamp: 1234567890,
            run_id,
            favicon: None,
        });

        assert_eq!(batch_record.url_record.final_domain, "example.com");
        assert_eq!(batch_record.technologies.len(), 2);
        assert!(batch_record.technologies.iter().any(|t| t.name == "PHP"));
        assert_eq!(batch_record.redirect_chain.len(), 1);
        assert_eq!(batch_record.partial_failures.len(), 1);
        assert!(batch_record.geoip.is_some());
        assert_eq!(batch_record.security_warnings.len(), 1);
        assert!(batch_record.whois.is_some());
    }

    #[test]
    fn test_build_batch_record_empty_oids() {
        let resp_data = create_test_response_data();
        let html_data = create_test_html_data();
        let mut tls_dns_data = create_test_tls_dns_data();
        tls_dns_data.oids = None; // Test None OIDs
        let additional_dns = create_test_additional_dns_data();

        let url_record = build_url_record(
            &resp_data,
            &html_data,
            &tls_dns_data,
            &additional_dns,
            1.5,
            1234567890,
            &None,
        );

        let batch_record = build_batch_record(BatchRecordParams {
            record: url_record,
            resp_data,
            html_data,
            tls_dns_data,
            technologies_vec: vec![],
            redirect_chain: vec![],
            partial_failures: vec![],
            geoip_data: None,
            security_warnings: vec![],
            whois_data: None,
            timestamp: 1234567890,
            run_id: None,
            favicon: None,
        });

        assert!(batch_record.oids.is_empty());
    }

    #[test]
    fn test_build_batch_record_empty_sans() {
        let resp_data = create_test_response_data();
        let html_data = create_test_html_data();
        let mut tls_dns_data = create_test_tls_dns_data();
        tls_dns_data.subject_alternative_names = None; // Test None SANs
        let additional_dns = create_test_additional_dns_data();

        let url_record = build_url_record(
            &resp_data,
            &html_data,
            &tls_dns_data,
            &additional_dns,
            1.5,
            1234567890,
            &None,
        );

        let batch_record = build_batch_record(BatchRecordParams {
            record: url_record,
            resp_data,
            html_data,
            tls_dns_data,
            technologies_vec: vec![],
            redirect_chain: vec![],
            partial_failures: vec![],
            geoip_data: None,
            security_warnings: vec![],
            whois_data: None,
            timestamp: 1234567890,
            run_id: None,
            favicon: None,
        });

        assert!(batch_record.subject_alternative_names.is_empty());
    }

    #[test]
    fn test_build_batch_record_partial_failures() {
        let resp_data = create_test_response_data();
        let html_data = create_test_html_data();
        let tls_dns_data = create_test_tls_dns_data();
        let additional_dns = create_test_additional_dns_data();

        let url_record = build_url_record(
            &resp_data,
            &html_data,
            &tls_dns_data,
            &additional_dns,
            1.5,
            1234567890,
            &None,
        );

        let partial_failures = vec![
            (ErrorType::DnsNsLookupError, "NS lookup failed".to_string()),
            (
                ErrorType::DnsTxtLookupError,
                "TXT lookup failed".to_string(),
            ),
        ];

        let batch_record = build_batch_record(BatchRecordParams {
            record: url_record,
            resp_data,
            html_data,
            tls_dns_data,
            technologies_vec: vec![],
            redirect_chain: vec![],
            partial_failures,
            geoip_data: None,
            security_warnings: vec![],
            whois_data: None,
            timestamp: 1234567890,
            run_id: None,
            favicon: None,
        });

        assert_eq!(batch_record.partial_failures.len(), 2);
        assert_eq!(
            batch_record.partial_failures[0].error_type,
            ErrorType::DnsNsLookupError
        );
        assert_eq!(
            batch_record.partial_failures[1].error_type,
            ErrorType::DnsTxtLookupError
        );
    }

    #[test]
    fn test_build_url_record_whitespace_only_strings() {
        // Test that whitespace-only strings are NOT normalized to None
        // Only empty strings are normalized - whitespace is preserved
        let resp_data = create_test_response_data();
        let mut html_data = create_test_html_data();
        html_data.keywords_str = Some("   ".to_string()); // Whitespace only
        html_data.description = Some("\t\n".to_string()); // Whitespace only
        let tls_dns_data = create_test_tls_dns_data();
        let additional_dns = create_test_additional_dns_data();

        let record = build_url_record(
            &resp_data,
            &html_data,
            &tls_dns_data,
            &additional_dns,
            1.5,
            1234567890,
            &None,
        );

        // Whitespace-only strings should be preserved (not normalized to None)
        // This is intentional - only truly empty strings are normalized
        assert_eq!(record.keywords, Some("   ".to_string()));
        assert_eq!(record.description, Some("\t\n".to_string()));
    }

    #[test]
    fn test_build_batch_record_duplicate_oids() {
        // Test that duplicate OIDs are deduplicated (HashSet behavior)
        let resp_data = create_test_response_data();
        let html_data = create_test_html_data();
        let mut tls_dns_data = create_test_tls_dns_data();
        let mut oids = HashSet::new();
        oids.insert("1.2.3.4".to_string());
        oids.insert("1.2.3.4".to_string()); // Duplicate
        oids.insert("5.6.7.8".to_string());
        tls_dns_data.oids = Some(oids);
        let additional_dns = create_test_additional_dns_data();

        let url_record = build_url_record(
            &resp_data,
            &html_data,
            &tls_dns_data,
            &additional_dns,
            1.5,
            1234567890,
            &None,
        );

        let batch_record = build_batch_record(BatchRecordParams {
            record: url_record,
            resp_data,
            html_data,
            tls_dns_data,
            technologies_vec: vec![],
            redirect_chain: vec![],
            partial_failures: vec![],
            geoip_data: None,
            security_warnings: vec![],
            whois_data: None,
            timestamp: 1234567890,
            run_id: None,
            favicon: None,
        });

        // Duplicate OIDs should be deduplicated by HashSet
        assert_eq!(batch_record.oids.len(), 2); // Only 2 unique OIDs
        assert!(batch_record.oids.contains("1.2.3.4"));
        assert!(batch_record.oids.contains("5.6.7.8"));
    }

    #[test]
    fn test_build_batch_record_duplicate_sans() {
        // Test that duplicate SANs are preserved (Vec, not HashSet)
        let resp_data = create_test_response_data();
        let html_data = create_test_html_data();
        let mut tls_dns_data = create_test_tls_dns_data();
        tls_dns_data.subject_alternative_names = Some(vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
            "example.com".to_string(), // Duplicate
        ]);
        let additional_dns = create_test_additional_dns_data();

        let url_record = build_url_record(
            &resp_data,
            &html_data,
            &tls_dns_data,
            &additional_dns,
            1.5,
            1234567890,
            &None,
        );

        let batch_record = build_batch_record(BatchRecordParams {
            record: url_record,
            resp_data,
            html_data,
            tls_dns_data,
            technologies_vec: vec![],
            redirect_chain: vec![],
            partial_failures: vec![],
            geoip_data: None,
            security_warnings: vec![],
            whois_data: None,
            timestamp: 1234567890,
            run_id: None,
            favicon: None,
        });

        // SANs are Vec, so duplicates are preserved (this is intentional - matches cert data)
        assert_eq!(batch_record.subject_alternative_names.len(), 3);
        assert_eq!(batch_record.subject_alternative_names[0], "example.com");
        assert_eq!(batch_record.subject_alternative_names[2], "example.com");
    }

    #[test]
    fn test_build_batch_record_large_redirect_chain() {
        // Test that large redirect chains are handled correctly
        let resp_data = create_test_response_data();
        let html_data = create_test_html_data();
        let tls_dns_data = create_test_tls_dns_data();
        let additional_dns = create_test_additional_dns_data();

        let url_record = build_url_record(
            &resp_data,
            &html_data,
            &tls_dns_data,
            &additional_dns,
            1.5,
            1234567890,
            &None,
        );

        // Create a large redirect chain (100 URLs)
        let redirect_chain: Vec<String> = (0..100)
            .map(|i| format!("https://example.com/redirect{}", i))
            .collect();

        let batch_record = build_batch_record(BatchRecordParams {
            record: url_record,
            resp_data,
            html_data,
            tls_dns_data,
            technologies_vec: vec![],
            redirect_chain,
            partial_failures: vec![],
            geoip_data: None,
            security_warnings: vec![],
            whois_data: None,
            timestamp: 1234567890,
            run_id: None,
            favicon: None,
        });

        // Large redirect chain should be preserved
        assert_eq!(batch_record.redirect_chain.len(), 100);
        assert_eq!(
            batch_record.redirect_chain[0],
            "https://example.com/redirect0"
        );
        assert_eq!(
            batch_record.redirect_chain[99],
            "https://example.com/redirect99"
        );
    }

    #[test]
    fn test_build_batch_record_run_id_propagation() {
        // Test that run_id is correctly propagated to partial failure records
        let resp_data = create_test_response_data();
        let html_data = create_test_html_data();
        let tls_dns_data = create_test_tls_dns_data();
        let additional_dns = create_test_additional_dns_data();

        let url_record = build_url_record(
            &resp_data,
            &html_data,
            &tls_dns_data,
            &additional_dns,
            1.5,
            1234567890,
            &None,
        );

        let run_id = Some("test-run-456".to_string());
        let partial_failures = vec![(ErrorType::DnsNsLookupError, "Test error".to_string())];

        let batch_record = build_batch_record(BatchRecordParams {
            record: url_record,
            resp_data,
            html_data,
            tls_dns_data,
            technologies_vec: vec![],
            redirect_chain: vec![],
            partial_failures,
            geoip_data: None,
            security_warnings: vec![],
            whois_data: None,
            timestamp: 1234567890,
            run_id: run_id.clone(),
            favicon: None,
        });

        // Run ID should be propagated to partial failure records
        assert_eq!(batch_record.partial_failures.len(), 1);
        assert_eq!(batch_record.partial_failures[0].run_id, run_id);
    }
}
