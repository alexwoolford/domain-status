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
        keywords: html_data.keywords_str.as_ref().and_then(|k| {
            if k.is_empty() {
                None
            } else {
                Some(k.clone())
            }
        }),
        // Normalize empty strings to None for consistency with database queries
        description: html_data.description.as_ref().and_then(|d| {
            if d.is_empty() {
                None
            } else {
                Some(d.clone())
            }
        }),
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

/// Builds a BatchRecord from all extracted data.
#[allow(clippy::too_many_arguments)] // Batch record requires many data sources
pub(crate) fn build_batch_record(
    record: UrlRecord,
    resp_data: &ResponseData,
    html_data: &HtmlData,
    tls_dns_data: &TlsDnsData,
    technologies_vec: Vec<String>,
    redirect_chain: Vec<String>,
    partial_failures: Vec<(crate::error_handling::ErrorType, String)>,
    geoip_data: Option<(String, crate::geoip::GeoIpResult)>,
    security_warnings: Vec<crate::security::SecurityWarning>,
    whois_data: Option<crate::whois::WhoisResult>,
    timestamp: i64,
    run_id: &Option<String>,
) -> BatchRecord {
    let oids_set: std::collections::HashSet<String> = tls_dns_data.oids.clone().unwrap_or_default();

    let partial_failure_records: Vec<crate::storage::models::UrlPartialFailureRecord> =
        partial_failures
            .into_iter()
            .map(|(error_type, error_message)| {
                crate::storage::models::UrlPartialFailureRecord {
                    url_status_id: 0, // Will be set when record is inserted
                    error_type: error_type.as_str().to_string(),
                    error_message,
                    timestamp,
                    run_id: run_id.clone(),
                }
            })
            .collect();

    let sans_vec: Vec<String> = tls_dns_data
        .subject_alternative_names
        .clone()
        .unwrap_or_default();

    BatchRecord {
        url_record: record,
        security_headers: resp_data.security_headers.clone(),
        http_headers: resp_data.http_headers.clone(),
        oids: oids_set,
        redirect_chain,
        technologies: technologies_vec,
        subject_alternative_names: sans_vec,
        analytics_ids: html_data.analytics_ids.clone(),
        geoip: geoip_data,
        structured_data: Some(html_data.structured_data.clone()),
        social_media_links: html_data.social_media_links.clone(),
        security_warnings,
        whois: whois_data,
        partial_failures: partial_failure_records,
    }
}
