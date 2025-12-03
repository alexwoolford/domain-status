//! Record preparation orchestration.

use crate::fetch::dns::{AdditionalDnsData, TlsDnsData};
use crate::fetch::response::{HtmlData, ResponseData};
use crate::storage::BatchRecord;

use super::builder::{build_batch_record, build_url_record};
use super::detection::detect_technologies_safely;

/// Prepares a complete record for database insertion.
///
/// Orchestrates technology detection, enrichment lookups, and batch record building.
/// Returns the batch record and timing metrics: (tech_detection_ms, geoip_lookup_ms, whois_lookup_ms, security_analysis_ms)
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
) -> (BatchRecord, (u64, u64, u64, u64)) {
    use crate::utils::duration_to_ms;
    use std::time::Instant;

    // Detect technologies
    let tech_start = Instant::now();
    let technologies_vec = detect_technologies_safely(html_data, resp_data, &ctx.error_stats).await;
    let tech_detection_ms = duration_to_ms(tech_start.elapsed());

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
    // Note: GeoIP and security analysis are synchronous, WHOIS is async
    let geoip_start = Instant::now();
    let geoip_data = crate::geoip::lookup_ip(&tls_dns_data.ip_address)
        .map(|result| (tls_dns_data.ip_address.clone(), result));
    let geoip_lookup_ms = duration_to_ms(geoip_start.elapsed());

    let security_start = Instant::now();
    let security_warnings = crate::security::analyze_security(
        &resp_data.final_url,
        &tls_dns_data.tls_version,
        &resp_data.security_headers,
    );
    let security_analysis_ms = duration_to_ms(security_start.elapsed());

    let whois_start = Instant::now();
    let whois_data = if ctx.enable_whois {
        log::info!(
            "Performing WHOIS lookup for domain: {}",
            resp_data.final_domain
        );
        match crate::whois::lookup_whois(&resp_data.final_domain, None).await {
            Ok(Some(whois_result)) => {
                log::info!(
                    "WHOIS lookup successful for {}: registrar={:?}, creation={:?}, expiration={:?}",
                    resp_data.final_domain,
                    whois_result.registrar,
                    whois_result.creation_date,
                    whois_result.expiration_date
                );
                Some(whois_result)
            }
            Ok(None) => {
                log::info!(
                    "WHOIS lookup returned no data for {}",
                    resp_data.final_domain
                );
                None
            }
            Err(e) => {
                log::warn!("WHOIS lookup failed for {}: {}", resp_data.final_domain, e);
                None
            }
        }
    } else {
        None
    };
    let whois_lookup_ms = if ctx.enable_whois {
        duration_to_ms(whois_start.elapsed())
    } else {
        0
    };

    // Build batch record
    let batch_record = build_batch_record(
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
    );

    (
        batch_record,
        (
            tech_detection_ms,
            geoip_lookup_ms,
            whois_lookup_ms,
            security_analysis_ms,
        ),
    )
}
