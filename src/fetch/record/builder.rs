//! Record building utilities.

use crate::database::UrlRecord;
use crate::fetch::dns::{AdditionalDnsData, TlsDnsData};
use crate::fetch::response::{HtmlData, ResponseData};
use crate::storage::BatchRecord;

/// Builds a UrlRecord from extracted response data.
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
        tls_version: tls_dns_data.tls_version.clone(),
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
/// This struct groups all parameters needed to build a batch record, reducing
/// function argument count and improving maintainability.
pub struct BatchRecordParams<'a> {
    /// The URL record to include in the batch
    pub record: UrlRecord,
    /// Response data (headers, status, etc.)
    pub resp_data: &'a ResponseData,
    /// HTML parsing results
    pub html_data: &'a HtmlData,
    /// TLS and DNS data
    pub tls_dns_data: &'a TlsDnsData,
    /// Detected technologies
    pub technologies_vec: Vec<String>,
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
    pub run_id: &'a Option<String>,
}

/// Builds a BatchRecord from all extracted data.
///
/// # Arguments
///
/// * `params` - Parameters for building the batch record
pub(crate) fn build_batch_record(params: BatchRecordParams<'_>) -> BatchRecord {
    let oids_set: std::collections::HashSet<String> =
        params.tls_dns_data.oids.clone().unwrap_or_default();

    let partial_failure_records: Vec<crate::storage::models::UrlPartialFailureRecord> = params
        .partial_failures
        .into_iter()
        .map(|(error_type, error_message)| {
            crate::storage::models::UrlPartialFailureRecord {
                url_status_id: 0, // Will be set when record is inserted
                error_type: error_type.as_str().to_string(),
                error_message,
                timestamp: params.timestamp,
                run_id: params.run_id.clone(),
            }
        })
        .collect();

    let sans_vec: Vec<String> = params
        .tls_dns_data
        .subject_alternative_names
        .clone()
        .unwrap_or_default();

    BatchRecord {
        url_record: params.record,
        security_headers: params.resp_data.security_headers.clone(),
        http_headers: params.resp_data.http_headers.clone(),
        oids: oids_set,
        redirect_chain: params.redirect_chain,
        technologies: params.technologies_vec,
        subject_alternative_names: sans_vec,
        analytics_ids: params.html_data.analytics_ids.clone(),
        geoip: params.geoip_data,
        structured_data: Some(params.html_data.structured_data.clone()),
        social_media_links: params.html_data.social_media_links.clone(),
        security_warnings: params.security_warnings,
        whois: params.whois_data,
        partial_failures: partial_failure_records,
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
        }
    }

    fn create_test_tls_dns_data() -> TlsDnsData {
        TlsDnsData {
            tls_version: Some("TLSv1.3".to_string()),
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
            key_algorithm: Some("RSA".to_string()),
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
        assert_eq!(record.tls_version, Some("TLSv1.3".to_string()));
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

        let technologies = vec!["WordPress".to_string(), "PHP".to_string()];
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
            resp_data: &resp_data,
            html_data: &html_data,
            tls_dns_data: &tls_dns_data,
            technologies_vec: technologies,
            redirect_chain,
            partial_failures,
            geoip_data,
            security_warnings,
            whois_data,
            timestamp: 1234567890,
            run_id: &run_id,
        });

        assert_eq!(batch_record.url_record.final_domain, "example.com");
        assert_eq!(batch_record.technologies.len(), 2);
        assert!(batch_record.technologies.contains(&"PHP".to_string()));
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
            resp_data: &resp_data,
            html_data: &html_data,
            tls_dns_data: &tls_dns_data,
            technologies_vec: vec![],
            redirect_chain: vec![],
            partial_failures: vec![],
            geoip_data: None,
            security_warnings: vec![],
            whois_data: None,
            timestamp: 1234567890,
            run_id: &None,
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
            resp_data: &resp_data,
            html_data: &html_data,
            tls_dns_data: &tls_dns_data,
            technologies_vec: vec![],
            redirect_chain: vec![],
            partial_failures: vec![],
            geoip_data: None,
            security_warnings: vec![],
            whois_data: None,
            timestamp: 1234567890,
            run_id: &None,
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
            resp_data: &resp_data,
            html_data: &html_data,
            tls_dns_data: &tls_dns_data,
            technologies_vec: vec![],
            redirect_chain: vec![],
            partial_failures,
            geoip_data: None,
            security_warnings: vec![],
            whois_data: None,
            timestamp: 1234567890,
            run_id: &None,
        });

        assert_eq!(batch_record.partial_failures.len(), 2);
        assert_eq!(
            batch_record.partial_failures[0].error_type,
            ErrorType::DnsNsLookupError.as_str()
        );
        assert_eq!(
            batch_record.partial_failures[1].error_type,
            ErrorType::DnsTxtLookupError.as_str()
        );
    }
}
