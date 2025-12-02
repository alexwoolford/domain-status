//! Record preparation orchestration.

use crate::fetch::dns::{AdditionalDnsData, TlsDnsData};
use crate::fetch::enrichment::perform_enrichment_lookups;
use crate::fetch::response::{HtmlData, ResponseData};
use crate::storage::BatchRecord;

use super::builder::{build_batch_record, build_url_record};
use super::detection::detect_technologies_safely;

/// Prepares a complete record for database insertion.
///
/// Orchestrates technology detection, enrichment lookups, and batch record building.
#[allow(clippy::too_many_arguments)] // All arguments are necessary for record preparation
pub async fn prepare_record_for_insertion(
    resp_data: &ResponseData,
    html_data: &HtmlData,
    tls_dns_data: &TlsDnsData,
    additional_dns: &AdditionalDnsData,
    partial_failures: Vec<(crate::error_handling::ErrorType, String)>,
    redirect_chain: Vec<String>,
    elapsed: f64,
    timestamp: i64,
    ctx: &crate::fetch::ProcessingContext,
) -> BatchRecord {
    // Detect technologies
    let technologies_vec = detect_technologies_safely(html_data, resp_data, &ctx.error_stats).await;

    // Build URL record
    let record = build_url_record(
        resp_data,
        html_data,
        tls_dns_data,
        additional_dns,
        elapsed,
        timestamp,
        &ctx.run_id,
    );

    // Perform enrichment lookups (GeoIP, WHOIS, security analysis)
    let (geoip_data, security_warnings, whois_data) = perform_enrichment_lookups(
        &tls_dns_data.ip_address,
        &resp_data.final_url,
        &resp_data.final_domain,
        &tls_dns_data.tls_version,
        &resp_data.security_headers,
        ctx.enable_whois,
    )
    .await;

    // Build batch record
    build_batch_record(
        record,
        resp_data,
        html_data,
        tls_dns_data,
        technologies_vec,
        redirect_chain,
        partial_failures,
        geoip_data,
        security_warnings,
        whois_data,
        timestamp,
        &ctx.run_id,
    )
}

