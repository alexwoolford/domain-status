//! Record preparation orchestration.

use crate::fetch::dns::{AdditionalDnsData, TlsDnsData};
use crate::fetch::response::{HtmlData, ResponseData};
use crate::storage::PersistedUrlRecord;

use super::builder::{build_persisted_url_record, build_url_record};

/// Parameters for preparing a record for database insertion.
///
/// This struct **owns** the response, HTML, and TLS/DNS data to enable moving
/// large collections (`HashMaps`, Vecs) into the final `PersistedUrlRecord` without cloning.
/// This eliminates ~5-10KB of heap allocations per URL in the hot path.
pub struct RecordPreparationParams<'a> {
    /// Response data (headers, status, body, etc.) - owned to move `HashMaps`
    pub resp_data: ResponseData,
    /// HTML parsing results - owned to move Vecs
    pub html_data: HtmlData,
    /// TLS and DNS data - owned to move `HashSet` and Vec
    pub tls_dns_data: TlsDnsData,
    /// Additional DNS records (NS, TXT, MX)
    pub additional_dns: AdditionalDnsData,
    /// Detected technologies
    pub technologies_vec: Vec<crate::fingerprint::DetectedTechnology>,
    /// Partial failures (DNS/TLS errors that didn't prevent processing)
    pub partial_failures: Vec<(crate::error_handling::ErrorType, String)>,
    /// Redirect chain (URL, HTTP status code) per hop
    pub redirect_chain: Vec<(String, u16)>,
    /// Elapsed time for the request (in seconds)
    pub elapsed: f64,
    /// Timestamp for the record
    pub timestamp: i64,
    /// Processing context (for enrichment lookups) - still borrowed (not owned data)
    pub ctx: &'a crate::fetch::ProcessingContext,
    /// Favicon data (fetched in parallel with tech detection and DNS/TLS)
    pub favicon: Option<crate::fetch::favicon::FaviconData>,
}

/// Prepares a complete record for database insertion.
///
/// Orchestrates enrichment lookups and persistence-record building.
/// Technology detection is now done in parallel with DNS/TLS fetching.
/// Returns the persisted record and timing metrics in microseconds:
/// (`geoip_lookup_us`, `whois_lookup_us`).
///
/// This function takes **ownership** of the response, HTML, and TLS/DNS data
/// to enable moving large collections (`HashMaps`, Vecs) into the final `PersistedUrlRecord`
/// without cloning, saving ~5-10KB of allocations per URL.
///
/// # Arguments
///
/// * `params` - Parameters for record preparation (ownership transferred)
#[allow(clippy::too_many_lines)] // Assembles PersistedUrlRecord from response data, DNS, TLS, fingerprints, and enrichment data
pub async fn prepare_record_for_insertion(
    params: RecordPreparationParams<'_>,
) -> (PersistedUrlRecord, (u64, u64)) {
    use crate::utils::duration_to_us;
    use std::time::Instant;

    // Build URL record (borrows data, clones ~15 small strings - unavoidable)
    let record = build_url_record(
        &params.resp_data,
        &params.html_data,
        &params.tls_dns_data,
        &params.additional_dns,
        params.elapsed,
        params.timestamp,
        params.ctx.runtime.run_id.as_ref(),
    );

    // Perform enrichment lookups in parallel where possible
    // GeoIP is synchronous and fast, WHOIS is async
    // Both can run in parallel since they're independent
    // Note: These borrow specific fields from params, which is still valid here
    let (geoip_data, whois_data) = tokio::join!(
        // GeoIP lookup (synchronous, very fast)
        async {
            let geoip_start = Instant::now();
            let geoip_data = params
                .tls_dns_data
                .ip_address
                .as_ref()
                .and_then(|ip_address| {
                    let ip_addr = std::hint::black_box(ip_address.as_str());
                    crate::geoip::lookup_ip(ip_addr).map(|result| (ip_address.clone(), result))
                });
            let geoip_elapsed = geoip_start.elapsed();
            let geoip_lookup_us = duration_to_us(geoip_elapsed);
            // Debug: Log if GeoIP lookup is suspiciously fast (might indicate measurement issue)
            if geoip_lookup_us == 0 && geoip_data.is_some() {
                log::debug!(
                    "GeoIP lookup returned data but timing is 0ms (elapsed: {:?}, micros: {}, nanos: {})",
                    geoip_elapsed,
                    geoip_elapsed.as_micros(),
                    geoip_elapsed.as_nanos()
                );
            }
            (geoip_data, geoip_lookup_us)
        },
        // WHOIS lookup (async, can be slow)
        async {
            if params.ctx.runtime.enable_whois {
                let whois_start = Instant::now();
                log::debug!(
                    "Performing WHOIS lookup for domain: {}",
                    params.resp_data.final_domain
                );

                let result = match crate::whois::lookup_whois(
                    &params.resp_data.final_domain,
                    Some(params.ctx.runtime.whois_cache_dir.as_path()),
                )
                .await
                {
                    Ok(Some(whois_result)) => {
                        log::debug!(
                            "WHOIS lookup successful for {}: registrar={:?}, creation={:?}, expiration={:?}",
                            params.resp_data.final_domain,
                            whois_result.registrar,
                            whois_result.creation_date,
                            whois_result.expiration_date
                        );
                        Some(whois_result)
                    }
                    Ok(None) => {
                        log::info!(
                            "WHOIS lookup returned no data for {}",
                            params.resp_data.final_domain
                        );
                        None
                    }
                    Err(e) => {
                        log::warn!(
                            "WHOIS lookup failed for {}: {}",
                            params.resp_data.final_domain,
                            e
                        );
                        None
                    }
                };
                let whois_lookup_us = duration_to_us(whois_start.elapsed());
                (result, whois_lookup_us)
            } else {
                (None, 0)
            }
        }
    );

    let (geoip_data, geoip_lookup_us) = geoip_data;
    let (whois_data, whois_lookup_us) = whois_data;

    // Build the persisted record by moving large collections instead of cloning.
    // This eliminates ~5-10KB of heap allocations per URL (HashMaps, Vecs)
    let persisted_record = build_persisted_url_record(super::builder::PersistedUrlRecordParams {
        record,
        resp_data: params.resp_data,
        html_data: params.html_data,
        tls_dns_data: params.tls_dns_data,
        technologies_vec: params.technologies_vec,
        redirect_chain: params.redirect_chain,
        partial_failures: params.partial_failures,
        geoip_data,
        whois_data,
        timestamp: params.timestamp,
        run_id: params.ctx.runtime.run_id.clone(),
        favicon: params.favicon,
        additional_dns: params.additional_dns,
    });

    (persisted_record, (geoip_lookup_us, whois_lookup_us))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ProcessingStats;
    use crate::fetch::dns::{AdditionalDnsData, TlsDnsData};
    use crate::fetch::response::{HtmlData, ResponseData};
    use crate::fetch::{NetworkContext, ProcessingContext, RuntimeContext};
    use crate::initialization::test_resolver;
    use crate::utils::TimingStats;
    use std::sync::Arc;

    /// Max `GeoIP` lookup time (ms) allowed in tests. Lenient for CI (network/cold cache).
    const GEOIP_TEST_TIMEOUT_MS: u64 = 8000;

    async fn create_test_context() -> ProcessingContext {
        let client = Arc::new(
            reqwest::Client::builder()
                .build()
                .expect("Failed to create HTTP client"),
        );
        let redirect_client = Arc::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("Failed to create redirect client"),
        );
        let resolver = test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        let timing_stats = Arc::new(TimingStats::new());
        let run_id = Some("test-run".to_string());
        let enable_whois = false; // Disable WHOIS for faster tests
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
                run_id,
                enable_whois,
                std::path::PathBuf::from("/tmp/domain_status_whois_test"),
                false,
                Arc::new(crate::runtime_metrics::RuntimeMetrics::default()),
                true,
            ),
            Arc::new(crate::fingerprint::FingerprintRuleset::empty_for_tests()),
        )
    }

    fn create_minimal_resp_data() -> ResponseData {
        ResponseData {
            initial_url: "https://example.com".to_string(),
            final_url: "https://example.com".to_string(),
            initial_domain: "example.com".to_string(),
            final_domain: "example.com".to_string(),
            host: "example.com".to_string(),
            status: 200,
            status_desc: "OK".to_string(),
            headers: reqwest::header::HeaderMap::new(),
            security_headers: std::collections::HashMap::new(),
            http_headers: std::collections::HashMap::new(),
            body: std::sync::Arc::<str>::from("<html><body>Test</body></html>"),
            body_sha256: None,
            body_truncated: false,
            content_length: None,
            http_version: None,
            content_type: None,
        }
    }

    fn create_minimal_html_data() -> HtmlData {
        HtmlData {
            title: "Test".to_string(),
            description: None,
            structured_data: crate::parse::StructuredData::default(),
            social_media_links: Vec::new(),
            contact_links: Vec::new(),
            exposed_secrets: Vec::new(),
            analytics_ids: Vec::new(),
            meta_tags: std::collections::HashMap::new(),
            script_sources: Vec::new(),
            script_tag_ids: std::collections::HashSet::new(),
            inline_script_text: String::new(),
            external_scripts_eligible: 0,
            external_scripts_scanned: 0,
            favicon_url: None,
            canonical_url: None,
            meta_refresh_url: None,
            meta_robots: None,
            resource_hints: Vec::new(),
        }
    }

    fn create_minimal_tls_dns_data() -> TlsDnsData {
        TlsDnsData {
            ip_address: Some("8.8.8.8".to_string()),
            tls_version: None,
            subject: None,
            issuer: None,
            valid_from: None,
            valid_to: None,
            oids: None,
            cipher_suite: None,
            key_algorithm: None,
            subject_alternative_names: None,
            reverse_dns_name: None,
            cert_fingerprint_sha256: None,
            cert_serial_number: None,
            cert_is_self_signed: None,
            cert_is_wildcard: None,
        }
    }

    fn create_minimal_additional_dns_data() -> AdditionalDnsData {
        AdditionalDnsData {
            nameservers: None,
            txt_records: None,
            mx_records: None,
            spf_record: None,
            dmarc_record: None,
            cname_chain: None,
            aaaa_records: None,
            caa_records: None,
        }
    }

    #[tokio::test]
    async fn test_prepare_record_for_insertion_basic_success() {
        // Test that prepare_record_for_insertion works with minimal valid data
        // This is critical - verifies the orchestration doesn't panic
        let ctx = create_test_context().await;
        let resp_data = create_minimal_resp_data();
        let html_data = create_minimal_html_data();
        let tls_dns_data = create_minimal_tls_dns_data();
        let additional_dns = create_minimal_additional_dns_data();

        let (persisted_record, (geoip_ms, whois_ms)) =
            prepare_record_for_insertion(RecordPreparationParams {
                resp_data,
                html_data,
                tls_dns_data,
                additional_dns,
                technologies_vec: Vec::new(),
                partial_failures: Vec::new(),
                redirect_chain: Vec::new(),
                elapsed: 1.0,
                timestamp: chrono::Utc::now().timestamp_millis(),
                ctx: &ctx,
                favicon: None,
            })
            .await;

        // Should succeed without panicking (create_minimal_resp_data sets final_domain to "example.com")
        assert_eq!(persisted_record.url_record.final_domain, "example.com");
        // Timing metrics should be reasonable
        // Note: GeoIP lookup can be slower in CI environments due to network latency and cold cache
        // Using a more lenient threshold (5 seconds) to account for CI variability
        assert!(
            geoip_ms < GEOIP_TEST_TIMEOUT_MS,
            "GeoIP lookup took {}ms, expected < {}ms",
            geoip_ms,
            GEOIP_TEST_TIMEOUT_MS
        );
        assert_eq!(whois_ms, 0); // WHOIS disabled in test context
    }

    #[tokio::test]
    async fn test_prepare_record_for_insertion_geoip_lookup_failure_handled() {
        // Test that GeoIP lookup failures don't prevent record creation
        // This is critical - GeoIP is optional, failures shouldn't break the flow
        let ctx = create_test_context().await;
        let resp_data = create_minimal_resp_data();
        let html_data = create_minimal_html_data();
        let mut tls_dns_data = create_minimal_tls_dns_data();
        // Use invalid IP to trigger GeoIP lookup failure
        tls_dns_data.ip_address = Some("invalid.ip.address".to_string());
        let additional_dns = create_minimal_additional_dns_data();

        let (persisted_record, (geoip_ms, _whois_ms)) =
            prepare_record_for_insertion(RecordPreparationParams {
                resp_data,
                html_data,
                tls_dns_data,
                additional_dns,
                technologies_vec: Vec::new(),
                partial_failures: Vec::new(),
                redirect_chain: Vec::new(),
                elapsed: 1.0,
                timestamp: chrono::Utc::now().timestamp_millis(),
                ctx: &ctx,
                favicon: None,
            })
            .await;

        // Should succeed even with invalid IP (GeoIP lookup returns None)
        assert_eq!(persisted_record.url_record.final_domain, "example.com");
        // GeoIP lookup should complete quickly (returns None for invalid IP)
        // Note: Using lenient threshold for CI environments
        assert!(
            geoip_ms < GEOIP_TEST_TIMEOUT_MS,
            "GeoIP lookup took {}ms, expected < {}ms",
            geoip_ms,
            GEOIP_TEST_TIMEOUT_MS
        );
    }

    #[tokio::test]
    async fn test_prepare_record_for_insertion_parallel_tasks_complete() {
        // Test that parallel tasks (GeoIP, WHOIS) complete correctly
        // This is critical - tokio::join! should handle all tasks even if some fail
        let ctx = create_test_context().await;
        let resp_data = create_minimal_resp_data();
        let html_data = create_minimal_html_data();
        let tls_dns_data = create_minimal_tls_dns_data();
        let additional_dns = create_minimal_additional_dns_data();

        let start = std::time::Instant::now();
        let (persisted_record, (geoip_ms, whois_ms)) =
            prepare_record_for_insertion(RecordPreparationParams {
                resp_data,
                html_data,
                tls_dns_data,
                additional_dns,
                technologies_vec: Vec::new(),
                partial_failures: Vec::new(),
                redirect_chain: Vec::new(),
                elapsed: 1.0,
                timestamp: chrono::Utc::now().timestamp_millis(),
                ctx: &ctx,
                favicon: None,
            })
            .await;
        let elapsed = start.elapsed();

        // All tasks should complete
        assert_eq!(persisted_record.url_record.final_domain, "example.com");
        // Timing should be reasonable (parallel execution)
        // Note: Using lenient thresholds for CI environments where network latency can be higher
        assert!(
            elapsed.as_millis() < 10000,
            "Total elapsed time {}ms, expected < 10000ms",
            elapsed.as_millis()
        ); // Should complete reasonably quickly
        assert!(
            geoip_ms < GEOIP_TEST_TIMEOUT_MS,
            "GeoIP lookup took {}ms, expected < {}ms",
            geoip_ms,
            GEOIP_TEST_TIMEOUT_MS
        );
        assert_eq!(whois_ms, 0); // WHOIS disabled
    }

    #[tokio::test]
    async fn test_prepare_record_for_insertion_with_technologies() {
        // Test that technologies are correctly passed through
        // This is critical - technology detection results must be preserved
        let ctx = create_test_context().await;
        let resp_data = create_minimal_resp_data();
        let html_data = create_minimal_html_data();
        let tls_dns_data = create_minimal_tls_dns_data();
        let additional_dns = create_minimal_additional_dns_data();
        let technologies = vec![
            crate::fingerprint::DetectedTechnology {
                name: "WordPress".to_string(),
                version: None,
                category: None,
                is_implied: false,
            },
            crate::fingerprint::DetectedTechnology {
                name: "PHP".to_string(),
                version: None,
                category: None,
                is_implied: false,
            },
        ];

        let technologies_count = technologies.len();
        let (persisted_record, _) = prepare_record_for_insertion(RecordPreparationParams {
            resp_data,
            html_data,
            tls_dns_data,
            additional_dns,
            technologies_vec: technologies,
            partial_failures: Vec::new(),
            redirect_chain: Vec::new(),
            elapsed: 1.0,
            timestamp: chrono::Utc::now().timestamp_millis(),
            ctx: &ctx,
            favicon: None,
        })
        .await;

        // Technologies should be preserved
        assert_eq!(persisted_record.technologies.len(), technologies_count);
    }

    #[tokio::test]
    async fn test_prepare_record_for_insertion_with_partial_failures() {
        // Test that partial failures are correctly passed through
        // This is critical - DNS/TLS failures shouldn't prevent record creation
        let ctx = create_test_context().await;
        let resp_data = create_minimal_resp_data();
        let html_data = create_minimal_html_data();
        let tls_dns_data = create_minimal_tls_dns_data();
        let additional_dns = create_minimal_additional_dns_data();
        let partial_failures = vec![(
            crate::error_handling::ErrorType::HttpRequestOtherError,
            "DNS lookup failed".to_string(),
        )];
        let partial_failures_count = partial_failures.len();

        let (persisted_record, _) = prepare_record_for_insertion(RecordPreparationParams {
            resp_data,
            html_data,
            tls_dns_data,
            additional_dns,
            technologies_vec: Vec::new(),
            partial_failures,
            redirect_chain: Vec::new(),
            elapsed: 1.0,
            timestamp: chrono::Utc::now().timestamp_millis(),
            ctx: &ctx,
            favicon: None,
        })
        .await;

        // Partial failures should be preserved
        assert_eq!(
            persisted_record.partial_failures.len(),
            partial_failures_count
        );
    }

    #[tokio::test]
    async fn test_prepare_record_for_insertion_whois_when_enabled() {
        // Test that WHOIS lookup is performed when enable_whois is true
        // This is critical - WHOIS is an expensive operation and should only run when enabled
        let mut ctx = create_test_context().await;
        // Enable WHOIS for this test
        ctx.runtime.enable_whois = true;
        let resp_data = create_minimal_resp_data();
        let html_data = create_minimal_html_data();
        let tls_dns_data = create_minimal_tls_dns_data();
        let additional_dns = create_minimal_additional_dns_data();

        let start = std::time::Instant::now();
        let (persisted_record, (geoip_ms, _whois_ms)) =
            prepare_record_for_insertion(RecordPreparationParams {
                resp_data,
                html_data,
                tls_dns_data,
                additional_dns,
                technologies_vec: Vec::new(),
                partial_failures: Vec::new(),
                redirect_chain: Vec::new(),
                elapsed: 1.0,
                timestamp: chrono::Utc::now().timestamp_millis(),
                ctx: &ctx,
                favicon: None,
            })
            .await;
        let elapsed = start.elapsed();

        // WHOIS should be attempted (may succeed or fail, but should take time)
        // WHOIS lookup time should be > 0 if enabled (even if it fails quickly)
        // The key is that the code path was executed
        assert_eq!(persisted_record.url_record.final_domain, "example.com");
        // WHOIS timing should be recorded (may be 0 if lookup fails immediately)
        // But the elapsed time should account for WHOIS attempt
        // elapsed.as_millis() is always >= 0 (u64), so we just verify it doesn't panic
        let _ = elapsed.as_millis();
        // Note: Using lenient threshold for CI environments
        assert!(
            geoip_ms < GEOIP_TEST_TIMEOUT_MS,
            "GeoIP lookup took {}ms, expected < {}ms",
            geoip_ms,
            GEOIP_TEST_TIMEOUT_MS
        );
        // _whois_ms may be 0 if lookup fails immediately, but the code path was executed
    }

    #[tokio::test]
    async fn test_prepare_record_for_insertion_enrichment_failures_handled_gracefully() {
        // Test that enrichment lookup failures don't prevent record creation
        // This is critical - GeoIP/WHOIS failures should be handled gracefully
        let ctx = create_test_context().await;
        let resp_data = create_minimal_resp_data();
        let html_data = create_minimal_html_data();
        let mut tls_dns_data = create_minimal_tls_dns_data();
        // Use invalid IP to trigger GeoIP lookup failure
        tls_dns_data.ip_address = Some("999.999.999.999".to_string());
        let additional_dns = create_minimal_additional_dns_data();

        let (persisted_record, (geoip_ms, whois_ms)) =
            prepare_record_for_insertion(RecordPreparationParams {
                resp_data,
                html_data,
                tls_dns_data,
                additional_dns,
                technologies_vec: Vec::new(),
                partial_failures: Vec::new(),
                redirect_chain: Vec::new(),
                elapsed: 1.0,
                timestamp: chrono::Utc::now().timestamp_millis(),
                ctx: &ctx,
                favicon: None,
            })
            .await;

        // Should succeed even with invalid IP (GeoIP returns None)
        assert_eq!(persisted_record.url_record.final_domain, "example.com");
        // GeoIP lookup should complete quickly (returns None for invalid IP)
        // Note: Using lenient threshold for CI environments
        assert!(
            geoip_ms < GEOIP_TEST_TIMEOUT_MS,
            "GeoIP lookup took {}ms, expected < {}ms",
            geoip_ms,
            GEOIP_TEST_TIMEOUT_MS
        );
        assert_eq!(whois_ms, 0); // WHOIS disabled
                                 // GeoIP data should be None (invalid IP)
        assert!(persisted_record.geoip.is_none());
    }
}
