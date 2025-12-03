//! HTTP response handling.

use anyhow::{Error, Result};
use log::debug;

use crate::fetch::dns::fetch_all_dns_data;
use crate::fetch::record::{prepare_record_for_insertion, queue_batch_record};
use crate::fetch::response::{extract_response_data, parse_html_content};
use crate::fetch::ProcessingContext;
use crate::utils::{UrlTimingMetrics, duration_to_ms};
use std::time::Instant;

/// Handles an HTTP response, extracting all relevant data and storing it in the database.
///
/// This function orchestrates domain extraction, TLS certificate retrieval, DNS lookups,
/// HTML parsing, and database insertion.
///
/// # Arguments
///
/// * `response` - The HTTP response
/// * `original_url` - The original URL before redirects
/// * `final_url_str` - The final URL after redirects
/// * `ctx` - Processing context containing all shared resources
/// * `elapsed` - Response time in seconds
/// * `redirect_chain` - Vector of redirect chain URLs (will be inserted into url_redirect_chain table)
///
/// # Errors
///
/// Returns an error if domain extraction, DNS resolution, or database insertion fails.
pub async fn handle_response(
    response: reqwest::Response,
    original_url: &str,
    final_url_str: &str,
    ctx: &ProcessingContext,
    elapsed: f64,
    redirect_chain: Option<Vec<String>>,
) -> Result<(), Error> {
    let total_start = Instant::now();
    debug!("Started processing response for {final_url_str}");

    let mut metrics = UrlTimingMetrics::default();
    metrics.http_request_ms = (elapsed * 1000.0) as u64;

    // Extract and validate response data
    let html_parse_start = Instant::now();
    let Some(resp_data) =
        extract_response_data(response, original_url, final_url_str, &ctx.extractor).await?
    else {
        // Non-HTML or empty response, skip silently
        // This is logged at debug level in extract_response_data
        debug!(
            "Skipping URL {} (non-HTML content-type, empty body, or body too large)",
            final_url_str
        );
        return Ok(());
    };

    // Parse HTML content
    let html_data = parse_html_content(&resp_data.body, &resp_data.final_domain, &ctx.error_stats);
    metrics.html_parsing_ms = duration_to_ms(html_parse_start.elapsed());

    // Fetch all DNS-related data (TLS, DNS resolution, additional DNS records)
    let (tls_dns_data, additional_dns, partial_failures, (dns_forward_ms, dns_reverse_ms, dns_additional_ms, tls_handshake_ms)) = fetch_all_dns_data(
        &resp_data,
        &ctx.resolver,
        &ctx.error_stats,
        ctx.run_id.as_deref(),
    )
    .await?;
    
    metrics.dns_forward_ms = dns_forward_ms;
    metrics.dns_reverse_ms = dns_reverse_ms;
    metrics.dns_additional_ms = dns_additional_ms;
    metrics.tls_handshake_ms = tls_handshake_ms;

    // Prepare record for insertion (technology detection, enrichment, batch record building)
    let timestamp = chrono::Utc::now().timestamp_millis();
    let redirect_chain_vec = redirect_chain.unwrap_or_default();

    debug!(
        "Preparing to insert record for URL: {}",
        resp_data.final_url
    );
    log::info!(
        "Attempting to insert record into database for domain: {}",
        resp_data.initial_domain
    );

    let (batch_record, (tech_detection_ms, geoip_lookup_ms, whois_lookup_ms, security_analysis_ms)) = prepare_record_for_insertion(
        &resp_data,
        &html_data,
        &tls_dns_data,
        &additional_dns,
        partial_failures,
        redirect_chain_vec,
        elapsed,
        timestamp,
        ctx,
    )
    .await;
    
    metrics.tech_detection_ms = tech_detection_ms;
    metrics.geoip_lookup_ms = geoip_lookup_ms;
    metrics.whois_lookup_ms = whois_lookup_ms;
    metrics.security_analysis_ms = security_analysis_ms;

    // Queue for batch insertion
    queue_batch_record(batch_record, &ctx.batch_sender, &resp_data.final_url).await;

    metrics.total_ms = duration_to_ms(total_start.elapsed());
    
    // Record metrics (DNS and enrichment times are set inside their respective functions)
    ctx.timing_stats.record(&metrics);

    Ok(())
}
