//! HTTP response handling.

use anyhow::{Error, Result};
use log::debug;

use crate::fetch::dns::fetch_all_dns_data;
use crate::fetch::record::prepare_record_for_insertion;
use crate::fetch::response::{extract_response_data, parse_html_content};
use crate::fetch::ProcessingContext;
use crate::storage::insert::insert_batch_record;
use crate::utils::{duration_to_ms, UrlTimingMetrics};
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
/// * `elapsed` - Response time in seconds (includes redirect resolution + HTTP request)
/// * `redirect_chain` - Vector of redirect chain URLs (will be inserted into url_redirect_chain table)
/// * `start_time` - Original start time from process_url (for accurate total_ms calculation)
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
    start_time: std::time::Instant,
) -> Result<(), Error> {
    // Use start_time for total_ms calculation to ensure accurate percentages
    // This ensures http_request_ms (which includes redirect resolution) is <= total_ms
    // since both are measured from the same start point
    debug!("Started processing response for {final_url_str}");

    let mut metrics = UrlTimingMetrics {
        // elapsed is in seconds, convert to microseconds for internal storage
        // Note: This includes redirect resolution time + HTTP request time
        http_request_ms: (elapsed * 1_000_000.0) as u64,
        ..Default::default()
    };

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

    // Run tech detection and DNS/TLS in parallel (they're independent)
    // Tech detection only needs HTML data and headers, DNS/TLS only needs domain
    let timestamp = chrono::Utc::now().timestamp_millis();
    let redirect_chain_vec = redirect_chain.unwrap_or_default();

    let (tech_result, dns_result) = tokio::join!(
        // Technology detection (only needs HTML data and headers)
        async {
            use crate::fetch::record::detect_technologies_safely;
            use crate::utils::duration_to_ms;
            use std::time::Instant;

            let tech_start = Instant::now();
            let technologies =
                detect_technologies_safely(&html_data, &resp_data, &ctx.error_stats).await;
            let tech_detection_ms = duration_to_ms(tech_start.elapsed());
            (technologies, tech_detection_ms)
        },
        // DNS/TLS fetching (only needs domain/hostname)
        async {
            fetch_all_dns_data(
                &resp_data,
                &ctx.resolver,
                &ctx.error_stats,
                ctx.run_id.as_deref(),
            )
            .await
        }
    );

    let (technologies_vec, tech_detection_ms) = tech_result;
    let (
        tls_dns_data,
        additional_dns,
        partial_failures,
        (dns_forward_ms, dns_reverse_ms, dns_additional_ms, tls_handshake_ms),
    ) = dns_result?;

    metrics.dns_forward_ms = dns_forward_ms;
    metrics.dns_reverse_ms = dns_reverse_ms;
    metrics.dns_additional_ms = dns_additional_ms;
    metrics.tls_handshake_ms = tls_handshake_ms;
    metrics.tech_detection_ms = tech_detection_ms;

    debug!(
        "Preparing to insert record for URL: {}",
        resp_data.final_url
    );
    log::info!(
        "Attempting to insert record into database for domain: {}",
        resp_data.initial_domain
    );

    // Prepare record for insertion (enrichment lookups and batch record building)
    let (batch_record, (geoip_lookup_ms, whois_lookup_ms, security_analysis_ms)) =
        prepare_record_for_insertion(
            &resp_data,
            &html_data,
            &tls_dns_data,
            &additional_dns,
            technologies_vec,
            partial_failures,
            redirect_chain_vec,
            elapsed,
            timestamp,
            ctx,
        )
        .await;

    metrics.geoip_lookup_ms = geoip_lookup_ms;
    metrics.whois_lookup_ms = whois_lookup_ms;
    metrics.security_analysis_ms = security_analysis_ms;

    // Insert record directly into database
    // If write fails, return error so URL is not counted as successful
    // Database errors are non-retriable, so this won't trigger retries
    insert_batch_record(&ctx.pool, batch_record)
        .await
        .map_err(|e| {
            log::error!(
                "Failed to insert record for URL {}: {}",
                resp_data.final_url,
                e
            );
            anyhow::anyhow!("Database write failed: {}", e)
        })?;

    // Calculate total_ms from start_time (same baseline as http_request_ms)
    // This ensures percentages are accurate (http_request_ms <= total_ms)
    metrics.total_ms = duration_to_ms(start_time.elapsed());

    // Record metrics (DNS and enrichment times are set inside their respective functions)
    ctx.timing_stats.record(&metrics);

    Ok(())
}
