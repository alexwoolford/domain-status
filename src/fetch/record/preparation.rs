//! Record preparation orchestration.

use crate::fetch::dns::{AdditionalDnsData, TlsDnsData};
use crate::fetch::response::{HtmlData, ResponseData};
use crate::storage::BatchRecord;

use super::builder::{build_batch_record, build_url_record};

/// Prepares a complete record for database insertion.
///
/// Orchestrates enrichment lookups and batch record building.
/// Technology detection is now done in parallel with DNS/TLS fetching.
/// Returns the batch record and timing metrics: (geoip_lookup_ms, whois_lookup_ms, security_analysis_ms)
#[allow(clippy::too_many_arguments)] // All arguments are necessary for record preparation
pub async fn prepare_record_for_insertion(
    resp_data: &ResponseData,
    html_data: &HtmlData,
    tls_dns_data: &TlsDnsData,
    additional_dns: &AdditionalDnsData,
    technologies_vec: Vec<String>,
    partial_failures: Vec<(crate::error_handling::ErrorType, String)>,
    redirect_chain: Vec<String>,
    elapsed: f64,
    timestamp: i64,
    ctx: &crate::fetch::ProcessingContext,
) -> (BatchRecord, (u64, u64, u64)) {
    use crate::utils::duration_to_ms;
    use std::time::Instant;

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

    // Perform enrichment lookups in parallel where possible
    // GeoIP and security analysis are synchronous and fast, WHOIS is async
    // All can run in parallel since they're independent
    let (geoip_data, security_warnings, whois_data) = tokio::join!(
        // GeoIP lookup (synchronous, very fast)
        async {
            let geoip_start = Instant::now();
            let ip_addr = std::hint::black_box(&tls_dns_data.ip_address);
            let geoip_result = crate::geoip::lookup_ip(ip_addr);
            let geoip_data = geoip_result.map(|result| (tls_dns_data.ip_address.clone(), result));
            let geoip_elapsed = geoip_start.elapsed();
            let geoip_lookup_ms = duration_to_ms(geoip_elapsed);
            // Debug: Log if GeoIP lookup is suspiciously fast (might indicate measurement issue)
            if geoip_lookup_ms == 0 && geoip_data.is_some() {
                log::debug!(
                    "GeoIP lookup returned data but timing is 0ms (elapsed: {:?}, micros: {}, nanos: {})",
                    geoip_elapsed,
                    geoip_elapsed.as_micros(),
                    geoip_elapsed.as_nanos()
                );
            }
            (geoip_data, geoip_lookup_ms)
        },
        // Security analysis (synchronous, very fast)
        async {
            let security_start = Instant::now();
            let security_warnings = crate::security::analyze_security(
                &resp_data.final_url,
                &tls_dns_data.tls_version,
                &resp_data.security_headers,
            );
            let security_analysis_ms = duration_to_ms(security_start.elapsed());
            (security_warnings, security_analysis_ms)
        },
        // WHOIS lookup (async, can be slow)
        async {
            if ctx.enable_whois {
                let whois_start = Instant::now();
                log::info!(
                    "Performing WHOIS lookup for domain: {}",
                    resp_data.final_domain
                );
                let result = match crate::whois::lookup_whois(&resp_data.final_domain, None).await {
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
                };
                let whois_lookup_ms = duration_to_ms(whois_start.elapsed());
                (result, whois_lookup_ms)
            } else {
                (None, 0)
            }
        }
    );

    let (geoip_data, geoip_lookup_ms) = geoip_data;
    let (security_warnings, security_analysis_ms) = security_warnings;
    let (whois_data, whois_lookup_ms) = whois_data;

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
        (geoip_lookup_ms, whois_lookup_ms, security_analysis_ms),
    )
}
