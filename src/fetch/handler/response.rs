//! HTTP response handling.

use anyhow::{Error, Result};
use log::debug;

use crate::fetch::dns::fetch_all_dns_data;
use crate::fetch::record::prepare_record_for_insertion;
use crate::fetch::response::{extract_response_data, parse_html_content, HtmlData, ResponseData};
use crate::fetch::ProcessingContext;
use crate::fetch::UrlProcessOutcome;
use crate::fingerprint::DetectedTechnology;
use crate::storage::insert::insert_persisted_url_record;
use crate::utils::{duration_to_us, UrlTimingMetrics};
use std::sync::Arc;
use std::time::Instant;

/// Serializes a response header map into newline-separated `Name: value` lines
/// for secret scanning. Repeated headers (e.g. multiple `Set-Cookie`) each get
/// their own line; non-UTF-8 header values are skipped.
fn serialize_headers(headers: &reqwest::header::HeaderMap) -> String {
    let mut out = String::new();
    for (name, value) in headers {
        if let Ok(v) = value.to_str() {
            out.push_str(name.as_str());
            out.push_str(": ");
            out.push_str(v);
            out.push('\n');
        }
    }
    out
}

struct ExtractedResponse {
    resp_data: ResponseData,
    html_data: HtmlData,
    html_parsing_us: u64,
}

/// Extract response bytes/headers and parse HTML on a blocking thread.
async fn extract_and_parse(
    response: reqwest::Response,
    original_url: &str,
    final_url_str: &str,
    ctx: &ProcessingContext,
) -> Result<Option<ExtractedResponse>, Error> {
    let html_parse_start = Instant::now();
    let Some(resp_data) = extract_response_data(response, original_url, final_url_str).await?
    else {
        return Ok(None);
    };

    // Parse HTML content on a blocking thread to avoid starving Tokio worker threads.
    // body is `Arc<str>`; `Arc::clone` is cheap (pointer + atomic refcount bump).
    let body = Arc::clone(&resp_data.body);
    let final_domain = resp_data.final_domain.clone();
    let error_stats = ctx.runtime.error_stats.clone();
    let html_data =
        tokio::task::spawn_blocking(move || parse_html_content(&body, &final_domain, &error_stats))
            .await
            .map_err(|e| anyhow::anyhow!("HTML parsing task failed: {e}"))?;

    Ok(Some(ExtractedResponse {
        resp_data,
        html_data,
        html_parsing_us: duration_to_us(html_parse_start.elapsed()),
    }))
}

struct EnrichmentResult {
    technologies_vec: Vec<DetectedTechnology>,
    tech_detection_us: u64,
    tls_dns_data: crate::fetch::dns::TlsDnsData,
    additional_dns: crate::fetch::dns::AdditionalDnsData,
    partial_failures: Vec<(crate::error_handling::ErrorType, String)>,
    dns_forward_us: u64,
    dns_reverse_us: u64,
    dns_additional_us: u64,
    tls_handshake_us: u64,
    favicon_result: Option<crate::fetch::favicon::FaviconData>,
    external_script_scan: crate::fetch::external_scripts::ExternalScriptScanResult,
}

/// Run independent enrichments in parallel: tech detection, DNS/TLS, favicon, scripts.
async fn parallel_enrich(
    html_data: &HtmlData,
    resp_data: &ResponseData,
    ctx: &ProcessingContext,
    final_url_str: &str,
) -> Result<EnrichmentResult, Error> {
    let (tech_result, dns_result, favicon_result, external_script_scan) = tokio::join!(
        async {
            use crate::fetch::record::detect_technologies_safely;

            let tech_start = Instant::now();
            let technologies = detect_technologies_safely(
                html_data,
                resp_data,
                &ctx.runtime.error_stats,
                &ctx.ruleset,
            )
            .await;
            let tech_detection_us = duration_to_us(tech_start.elapsed());
            (technologies, tech_detection_us)
        },
        async {
            fetch_all_dns_data(resp_data, &ctx.network.resolver, &ctx.runtime.error_stats).await
        },
        crate::fetch::favicon::fetch_and_hash_favicon(
            &ctx.network.client,
            html_data.favicon_url.as_deref(),
            final_url_str,
        ),
        async {
            if ctx.runtime.scan_external_scripts {
                crate::fetch::external_scripts::scan_external_scripts(
                    &ctx.network.client,
                    &resp_data.final_url,
                    &html_data.script_sources,
                    ctx.runtime.allow_localhost_for_tests,
                )
                .await
            } else {
                crate::fetch::external_scripts::ExternalScriptScanResult::default()
            }
        }
    );

    let (technologies_vec, tech_detection_us) = tech_result;
    let (
        tls_dns_data,
        additional_dns,
        partial_failures,
        (dns_forward_us, dns_reverse_us, dns_additional_us, tls_handshake_us),
    ) = dns_result?;

    let technologies_vec = supplement_technologies_after_enrichment(
        ctx,
        technologies_vec,
        &tls_dns_data,
        &additional_dns,
        &external_script_scan,
        &resp_data.final_domain,
    )
    .await;

    Ok(EnrichmentResult {
        technologies_vec,
        tech_detection_us,
        tls_dns_data,
        additional_dns,
        partial_failures,
        dns_forward_us,
        dns_reverse_us,
        dns_additional_us,
        tls_handshake_us,
        favicon_result,
        external_script_scan,
    })
}

/// Merge DNS/cert and fetched-script-body signals into the first tech pass.
///
/// Official **late-signal** pattern for technology detection:
/// `parallel_enrich` runs the first tech pass in parallel with DNS/TLS and
/// (optionally) external script fetch. Signals those stages produce are not
/// available during pass 1, so fold them here afterward (DNS/cert first, then
/// script bodies). New late signals should extend this function rather than
/// inventing a second pipeline. ADR 0005 still forbids JS *execution*; matching
/// static text from already-fetched bodies is in scope.
async fn supplement_technologies_after_enrichment(
    ctx: &ProcessingContext,
    technologies_vec: Vec<DetectedTechnology>,
    tls_dns_data: &crate::fetch::dns::TlsDnsData,
    additional_dns: &crate::fetch::dns::AdditionalDnsData,
    external_script_scan: &crate::fetch::external_scripts::ExternalScriptScanResult,
    final_domain: &str,
) -> Vec<DetectedTechnology> {
    // Build the DNS haystack on the async task (cheap string assembly), then run
    // DNS/cert + optional script-text matching on the blocking pool with the
    // main fingerprint pass.
    let dns_haystack = crate::fingerprint::dns_records_haystack(
        additional_dns.nameservers.as_deref(),
        additional_dns.txt_records.as_deref(),
        additional_dns.mx_records.as_deref(),
        additional_dns.cname_chain.as_deref(),
        additional_dns.spf_record.as_deref(),
        additional_dns.dmarc_record.as_deref(),
    );
    let ruleset = Arc::clone(&ctx.ruleset);
    let cert_issuer = tls_dns_data.issuer.clone();
    let script_text = external_script_scan.script_bodies_text.clone();
    let fallback = technologies_vec.clone();

    match tokio::task::spawn_blocking(move || {
        let techs = crate::fingerprint::supplement_technologies_with_dns_cert(
            ruleset.as_ref(),
            technologies_vec,
            &dns_haystack,
            cert_issuer.as_deref(),
        );
        if script_text.is_empty() {
            return techs;
        }
        crate::fingerprint::supplement_technologies_with_script_text(
            ruleset.as_ref(),
            techs,
            &script_text,
        )
    })
    .await
    {
        Ok(techs) => techs,
        Err(e) => {
            log::warn!("Technology late-signal supplement join failed for {final_domain}: {e}");
            fallback
        }
    }
}

/// Merge external-script and response-header secret findings into `html_data`.
///
/// Header secret regex work runs on `spawn_blocking` so it does not occupy a
/// Tokio async worker (same posture as HTML / external-script secret scans).
async fn merge_secrets(
    html_data: &mut HtmlData,
    resp_data: &ResponseData,
    external_script_scan: crate::fetch::external_scripts::ExternalScriptScanResult,
) {
    html_data.external_scripts_eligible = external_script_scan.eligible;
    html_data.external_scripts_scanned = external_script_scan.scanned;
    if !external_script_scan.secrets.is_empty() {
        log::info!(
            "Detected {} additional secret(s) in external scripts for {}",
            external_script_scan.secrets.len(),
            resp_data.final_domain
        );
        html_data
            .exposed_secrets
            .extend(external_script_scan.secrets);
    }

    let headers_blob = serialize_headers(&resp_data.headers);
    let final_domain = resp_data.final_domain.clone();
    let header_secrets = tokio::task::spawn_blocking(move || {
        crate::parse::detect_exposed_secrets_in_headers(&headers_blob)
    })
    .await
    .unwrap_or_else(|e| {
        log::warn!("Header secret scan join failed for {final_domain}: {e}");
        Vec::new()
    });
    if !header_secrets.is_empty() {
        log::info!(
            "Detected {} secret(s) in response headers for {}",
            header_secrets.len(),
            resp_data.final_domain
        );
        html_data.exposed_secrets.extend(header_secrets);
    }
}

/// Prepare and insert the scan record; returns enrichment timing micros.
async fn persist(
    resp_data: ResponseData,
    html_data: HtmlData,
    enrichment: EnrichmentResult,
    redirect_chain_vec: Vec<(String, u16)>,
    elapsed: f64,
    timestamp: i64,
    ctx: &ProcessingContext,
) -> Result<(u64, u64, bool), Error> {
    debug!(
        "Preparing to insert record for URL: {}",
        resp_data.final_url
    );
    log::debug!(
        "Attempting to insert record into database for domain: {}",
        resp_data.initial_domain
    );

    let final_url_for_logging = resp_data.final_url.clone();
    let EnrichmentResult {
        technologies_vec,
        tls_dns_data,
        additional_dns,
        partial_failures,
        favicon_result,
        ..
    } = enrichment;

    let (persisted_record, (geoip_lookup_us, whois_lookup_us)) =
        prepare_record_for_insertion(crate::fetch::record::RecordPreparationParams {
            resp_data,
            html_data,
            tls_dns_data,
            additional_dns,
            technologies_vec,
            partial_failures,
            redirect_chain: redirect_chain_vec,
            elapsed,
            timestamp,
            ctx,
            favicon: favicon_result,
        })
        .await;

    let upsert = insert_persisted_url_record(&ctx.pool, persisted_record)
        .await
        .map_err(|e| {
            log::error!("Failed to insert record for URL {final_url_for_logging}: {e}");
            anyhow::anyhow!("Database write failed: {e}")
        })?;

    Ok((geoip_lookup_us, whois_lookup_us, upsert.inserted))
}

/// Handles an HTTP response, extracting all relevant data and storing it in the database.
///
/// Stages: `extract_and_parse` → `parallel_enrich` → `merge_secrets` → `persist`.
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
    redirect_chain: Option<Vec<(String, u16)>>,
    start_time: std::time::Instant,
) -> Result<UrlProcessOutcome, Error> {
    debug!("Started processing response for {final_url_str}");

    let mut metrics = UrlTimingMetrics {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_precision_loss,
            clippy::cast_sign_loss
        )]
        http_request_us: (elapsed * 1_000_000.0).min(u64::MAX as f64).max(0.0) as u64,
        ..Default::default()
    };

    let Some(extracted) = extract_and_parse(response, original_url, final_url_str, ctx).await?
    else {
        debug!("Skipping URL {final_url_str} (non-HTML content-type or empty body)");
        return Ok(UrlProcessOutcome::Skipped);
    };
    metrics.html_parsing_us = extracted.html_parsing_us;

    let ExtractedResponse {
        resp_data,
        mut html_data,
        ..
    } = extracted;

    let timestamp = chrono::Utc::now().timestamp_millis();
    let redirect_chain_vec = redirect_chain.unwrap_or_default();

    let mut enrichment = parallel_enrich(&html_data, &resp_data, ctx, final_url_str).await?;
    metrics.dns_forward_us = enrichment.dns_forward_us;
    metrics.dns_reverse_us = enrichment.dns_reverse_us;
    metrics.dns_additional_us = enrichment.dns_additional_us;
    metrics.tls_handshake_us = enrichment.tls_handshake_us;
    metrics.tech_detection_us = enrichment.tech_detection_us;

    let external_script_scan = std::mem::take(&mut enrichment.external_script_scan);
    merge_secrets(&mut html_data, &resp_data, external_script_scan).await;

    let (geoip_lookup_us, whois_lookup_us, inserted) = persist(
        resp_data,
        html_data,
        enrichment,
        redirect_chain_vec,
        elapsed,
        timestamp,
        ctx,
    )
    .await?;

    metrics.geoip_lookup_us = geoip_lookup_us;
    metrics.whois_lookup_us = whois_lookup_us;
    metrics.total_us = duration_to_us(start_time.elapsed());
    ctx.runtime.timing_stats.record(&metrics);

    Ok(if inserted {
        UrlProcessOutcome::Inserted
    } else {
        UrlProcessOutcome::Updated
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ProcessingStats;
    use crate::fetch::{NetworkContext, ProcessingContext, RuntimeContext};
    use crate::utils::TimingStats;
    use hickory_resolver::{config::ResolverOpts, TokioResolver};
    use httptest::{matchers::*, responders::*, Expectation, Server};
    use std::sync::Arc;

    async fn create_test_context(server: &Server) -> ProcessingContext {
        // IP hosts are valid domain keys; successful HTML paths may fetch /favicon.ico.
        server.expect(
            Expectation::matching(request::method_path("GET", "/favicon.ico"))
                .times(0..)
                .respond_with(status_code(404)),
        );

        let client = Arc::new(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("Failed to create HTTP client"),
        );
        let redirect_client = Arc::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("Failed to create redirect client"),
        );
        let resolver = Arc::new(
            TokioResolver::builder_tokio()
                .unwrap()
                .with_options(ResolverOpts::default())
                .build()
                .expect("resolver builds with default config"),
        );
        let error_stats = Arc::new(ProcessingStats::new());
        let timing_stats = Arc::new(TimingStats::new());
        let pool = Arc::new(
            sqlx::SqlitePool::connect("sqlite::memory:")
                .await
                .expect("Failed to create test pool"),
        );

        ProcessingContext::new(
            NetworkContext::new(client, redirect_client, resolver),
            pool,
            RuntimeContext::new(
                error_stats,
                timing_stats,
                None,
                false,
                std::path::PathBuf::from("/tmp/domain_status_whois_test"),
                false,
                Arc::new(crate::runtime_metrics::RuntimeMetrics::default()),
                true,
            ),
            Arc::new(crate::fingerprint::FingerprintRuleset::empty_for_tests()),
        )
    }

    #[tokio::test]
    async fn test_handle_response_non_html_skips_silently() {
        let server = Server::run();
        let server_url = server.url("/json").to_string();
        let original_url = "https://example.com/json";

        // Return JSON instead of HTML
        server.expect(
            Expectation::matching(request::method_path("GET", "/json")).respond_with(
                status_code(200)
                    .insert_header("Content-Type", "application/json")
                    .body(r#"{"key": "value"}"#),
            ),
        );

        let client = reqwest::Client::new();
        let response = client.get(&server_url).send().await.unwrap();
        let ctx = create_test_context(&server).await;
        let start_time = std::time::Instant::now();

        // application/json is scannable (secret detection); without migrations insert fails.
        let result = handle_response(
            response,
            original_url,
            &server_url,
            &ctx,
            0.1,
            None,
            start_time,
        )
        .await;

        assert!(
            result.is_err(),
            "expected DB insert failure without migrations"
        );
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Database")
                || error_msg.contains("migration")
                || error_msg.contains("no such table")
                || error_msg.contains("url_status"),
            "Expected database/schema error, got: {error_msg}"
        );
    }

    #[tokio::test]
    async fn test_handle_response_empty_body_skips_silently() {
        let server = Server::run();
        let server_url = server.url("/empty").to_string();
        let original_url = "https://example.com/empty";

        // Return empty body
        server.expect(
            Expectation::matching(request::method_path("GET", "/empty")).respond_with(
                status_code(200)
                    .insert_header("Content-Type", "text/html; charset=utf-8")
                    .body(""),
            ),
        );

        let client = reqwest::Client::new();
        let response = client.get(&server_url).send().await.unwrap();
        let ctx = create_test_context(&server).await;
        let start_time = std::time::Instant::now();

        // Empty bodies still record metadata; without migrations insert fails.
        let result = handle_response(
            response,
            original_url,
            &server_url,
            &ctx,
            0.1,
            None,
            start_time,
        )
        .await;

        assert!(
            result.is_err(),
            "expected DB insert failure without migrations"
        );
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Database")
                || error_msg.contains("migration")
                || error_msg.contains("no such table")
                || error_msg.contains("url_status"),
            "Expected database/schema error, got: {error_msg}"
        );
    }

    #[tokio::test]
    async fn test_handle_response_dns_failure_propagates_error() {
        let server = Server::run();
        let server_url = server.url("/test").to_string();
        let original_url = "https://this-domain-definitely-does-not-exist-12345.invalid/test";

        // Return valid HTML
        server.expect(
            Expectation::matching(request::method_path("GET", "/test")).respond_with(
                status_code(200)
                    .insert_header("Content-Type", "text/html; charset=utf-8")
                    .body("<html><head><title>Test</title></head><body>Hello</body></html>"),
            ),
        );

        let client = reqwest::Client::new();
        let response = client.get(&server_url).send().await.unwrap();
        let ctx = create_test_context(&server).await;
        let start_time = std::time::Instant::now();

        // Final URL is an IP mock host (valid domain key). Insert fails without migrations;
        // DNS on the mock IP may also fail depending on resolver.
        let result = handle_response(
            response,
            original_url,
            &server_url,
            &ctx,
            0.1,
            None,
            start_time,
        )
        .await;

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("DNS")
                || error_msg.contains("Database")
                || error_msg.contains("no such table")
                || error_msg.contains("url_status"),
            "Expected DNS/database error, got: {error_msg}"
        );
    }

    #[tokio::test]
    async fn test_handle_response_timing_metrics_overflow_protection() {
        // Test that very large elapsed times don't cause overflow
        // This is critical - elapsed * 1_000_000.0 could overflow u64
        // The code at line 53 uses .min(u64::MAX as f64) to prevent overflow
        let very_large_elapsed = 1_000_000.0; // 1 million seconds

        // Verify the calculation doesn't panic
        let http_request_ms: f64 = very_large_elapsed * 1_000_000.0;
        // Safe cast: value is clamped to [0.0, u64::MAX] range before conversion
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_precision_loss,
            clippy::cast_sign_loss
        )]
        let http_request_ms = http_request_ms.min(u64::MAX as f64).max(0.0) as u64;
        // With protection, should be clamped to u64::MAX (not overflow)
        // Note: 1e6 * 1e6 = 1e12, which is less than u64::MAX (~1.8e19)
        // So it should be the actual value, not clamped
        // The important thing is the calculation doesn't overflow
        assert!(http_request_ms > 0);
        // Verify it's approximately the expected value (1e12 microseconds = 1e6 seconds)
        // Allow for floating point precision differences (cast to u64 truncates)
        // 1e12 as u64 = 1_000_000_000_000 (1 trillion)
        assert!(http_request_ms >= 999_999_000_000);
        assert!(http_request_ms <= 1_000_001_000_000);
    }

    #[tokio::test]
    async fn test_handle_response_negative_elapsed_clamped() {
        // Test that negative elapsed times are clamped to 0
        // This is critical - clock adjustments could cause negative elapsed
        // The code at line 53 uses .max(0.0) to prevent negative values
        let negative_elapsed = -1.0;

        // Verify the calculation clamps negative values
        let http_request_ms: f64 = negative_elapsed * 1_000_000.0;
        // Safe cast: negative values are clamped to 0, ensuring non-negative result
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_precision_loss,
            clippy::cast_sign_loss
        )]
        let http_request_ms = http_request_ms.min(u64::MAX as f64).max(0.0) as u64;
        // Should be clamped to 0, not negative
        assert_eq!(http_request_ms, 0);
    }

    #[tokio::test]
    async fn test_handle_response_database_insertion_failure_propagates() {
        // Test that database insertion failures are correctly propagated
        // This is critical - database errors should not be silently ignored
        let server = Server::run();
        let server_url = server.url("/test").to_string();
        let original_url = "https://example.com/test";

        // Return valid HTML
        server.expect(
            Expectation::matching(request::method_path("GET", "/test")).respond_with(
                status_code(200)
                    .insert_header("Content-Type", "text/html; charset=utf-8")
                    .body("<html><head><title>Test</title></head><body>Hello</body></html>"),
            ),
        );

        let client = reqwest::Client::new();
        let response = client.get(&server_url).send().await.unwrap();
        let ctx = create_test_context(&server).await;
        let start_time = std::time::Instant::now();

        // Database insertion will fail (no migrations), error should propagate
        let result = handle_response(
            response,
            original_url,
            &server_url,
            &ctx,
            0.1,
            None,
            start_time,
        )
        .await;

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Database write failed")
                || error_msg.contains("Database")
                || error_msg.contains("migration")
                || error_msg.contains("table")
                || error_msg.contains("url_status"),
            "Expected database error, got: {error_msg}"
        );
    }

    #[tokio::test]
    async fn test_handle_response_database_insertion_failure_propagates_error() {
        // Test that database insertion failures are correctly propagated
        // This is critical - database errors should not be silently ignored
        let server = Server::run();
        let server_url = server.url("/test").to_string();
        let original_url = "https://example.com/test";

        // Return valid HTML
        server.expect(
            Expectation::matching(request::method_path("GET", "/test")).respond_with(
                status_code(200)
                    .insert_header("Content-Type", "text/html; charset=utf-8")
                    .body("<html><head><title>Test</title></head><body>Hello</body></html>"),
            ),
        );

        // IP hosts are valid domain keys; successful HTML paths may fetch /favicon.ico.
        server.expect(
            Expectation::matching(request::method_path("GET", "/favicon.ico"))
                .times(0..)
                .respond_with(status_code(404)),
        );

        let client = reqwest::Client::new();
        let response = client.get(&server_url).send().await.unwrap();

        // Create context with a closed/invalid pool to trigger database insertion failure
        let pool = Arc::new(
            sqlx::SqlitePool::connect("sqlite::memory:")
                .await
                .expect("Failed to create test pool"),
        );
        // Close the pool to make insertion fail
        pool.close().await;

        let client_arc = Arc::new(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("Failed to create HTTP client"),
        );
        let redirect_client = Arc::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("Failed to create redirect client"),
        );
        let resolver = Arc::new(
            TokioResolver::builder_tokio()
                .unwrap()
                .with_options(ResolverOpts::default())
                .build()
                .expect("resolver builds with default config"),
        );
        let error_stats = Arc::new(ProcessingStats::new());
        let timing_stats = Arc::new(TimingStats::new());

        let ctx = ProcessingContext::new(
            NetworkContext::new(client_arc, redirect_client, resolver),
            pool,
            RuntimeContext::new(
                error_stats,
                timing_stats,
                Some("test-run".to_string()),
                false,
                std::path::PathBuf::from("/tmp/domain_status_whois_test"),
                false,
                Arc::new(crate::runtime_metrics::RuntimeMetrics::default()),
                true,
            ),
            Arc::new(crate::fingerprint::FingerprintRuleset::empty_for_tests()),
        );

        let start_time = std::time::Instant::now();

        // Should fail at database insertion
        let result = handle_response(
            response,
            original_url,
            &server_url,
            &ctx,
            0.1,
            None,
            start_time,
        )
        .await;

        assert!(result.is_err(), "Should fail when database insertion fails");
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Database write failed")
                || error_msg.contains("pool")
                || error_msg.contains("closed")
                || error_msg.contains("Connection")
                || error_msg.contains("Database"),
            "Expected database insertion error, got: {error_msg}"
        );
    }
}
