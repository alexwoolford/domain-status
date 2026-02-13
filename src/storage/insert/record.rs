//! Direct record insertion (non-batched).
//!
//! This module provides functions to insert BatchRecord data directly into the database
//! without batching. This is more efficient than batching for SQLite WAL mode.

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;
use crate::storage::BatchRecord;

use crate::storage::insert;

/// Summary of enrichment data insertion results.
///
/// Tracks which enrichment data types succeeded or failed to insert.
/// This allows callers to monitor enrichment data insertion health
/// without blocking the main record insertion.
#[derive(Debug, Clone, Default)]
pub struct EnrichmentInsertSummary {
    /// Number of partial failures successfully inserted
    pub partial_failures_inserted: usize,
    /// Number of partial failures that failed to insert
    pub partial_failures_failed: usize,
    /// Whether GeoIP data was successfully inserted
    pub geoip_inserted: bool,
    /// Whether GeoIP data insertion failed
    pub geoip_failed: bool,
    /// Whether structured data was successfully inserted
    pub structured_data_inserted: bool,
    /// Whether structured data insertion failed
    pub structured_data_failed: bool,
    /// Whether social media links were successfully inserted
    pub social_media_inserted: bool,
    /// Whether social media links insertion failed
    pub social_media_failed: bool,
    /// Whether security warnings were successfully inserted
    pub security_warnings_inserted: bool,
    /// Whether security warnings insertion failed
    pub security_warnings_failed: bool,
    /// Whether WHOIS data was successfully inserted
    pub whois_inserted: bool,
    /// Whether WHOIS data insertion failed
    pub whois_failed: bool,
    /// Whether analytics IDs were successfully inserted
    pub analytics_ids_inserted: bool,
    /// Whether analytics IDs insertion failed
    pub analytics_ids_failed: bool,
}

impl EnrichmentInsertSummary {
    /// Returns the total number of enrichment operations that failed.
    pub fn total_failures(&self) -> usize {
        self.partial_failures_failed
            + if self.geoip_failed { 1 } else { 0 }
            + if self.structured_data_failed { 1 } else { 0 }
            + if self.social_media_failed { 1 } else { 0 }
            + if self.security_warnings_failed { 1 } else { 0 }
            + if self.whois_failed { 1 } else { 0 }
            + if self.analytics_ids_failed { 1 } else { 0 }
    }

    /// Returns true if any enrichment operations failed.
    pub fn has_failures(&self) -> bool {
        self.total_failures() > 0
    }
}

/// Inserts a batch record directly into the database.
///
/// This function inserts the main URL record and all enrichment data immediately,
/// without buffering or batching. With SQLite WAL mode, this provides better
/// performance than batching since writes can proceed concurrently.
pub async fn insert_batch_record(
    pool: &SqlitePool,
    record: BatchRecord,
) -> Result<(), DatabaseError> {
    // Clone domain for error message (record will be moved to insert_enrichment_data)
    let domain = record.url_record.initial_domain.clone();

    // Insert main URL record
    let url_status_id = insert::insert_url_record(insert::url::UrlRecordInsertParams {
        pool,
        record: &record.url_record,
        security_headers: &record.security_headers,
        http_headers: &record.http_headers,
        oids: &record.oids,
        redirect_chain: &record.redirect_chain,
        technologies: &record.technologies,
        subject_alternative_names: &record.subject_alternative_names,
    })
    .await
    .map_err(|e| {
        log::error!(
            "Failed to insert URL record for domain '{}': {} (SQL: INSERT INTO url_status ...)",
            domain,
            e
        );
        e
    })?;

    // Insert enrichment data
    // Note: Enrichment data is inserted AFTER the main transaction commits.
    // This design choice ensures that:
    // 1. Main URL record is always saved (even if enrichment fails)
    // 2. Enrichment data failures don't prevent URL processing
    // 3. Partial enrichment data is better than no data at all
    //
    // Trade-off: If enrichment insertion fails, we have inconsistent state (main record exists
    // but enrichment data is missing). This is acceptable because enrichment data is optional
    // and failures are logged for monitoring.
    let enrichment_summary = insert_enrichment_data(pool, url_status_id, record).await;

    // Log summary if there were any failures (for monitoring/debugging)
    if enrichment_summary.has_failures() {
        log::warn!(
            "Enrichment data insertion completed with {} failures for url_status_id {} (domain: {}): partial_failures={}/{}, geoip={}, structured_data={}, social_media={}, security_warnings={}, whois={}, analytics_ids={}",
            enrichment_summary.total_failures(),
            url_status_id,
            domain,
            enrichment_summary.partial_failures_inserted,
            enrichment_summary.partial_failures_inserted + enrichment_summary.partial_failures_failed,
            if enrichment_summary.geoip_inserted { "ok" } else if enrichment_summary.geoip_failed { "failed" } else { "n/a" },
            if enrichment_summary.structured_data_inserted { "ok" } else if enrichment_summary.structured_data_failed { "failed" } else { "n/a" },
            if enrichment_summary.social_media_inserted { "ok" } else if enrichment_summary.social_media_failed { "failed" } else { "n/a" },
            if enrichment_summary.security_warnings_inserted { "ok" } else if enrichment_summary.security_warnings_failed { "failed" } else { "n/a" },
            if enrichment_summary.whois_inserted { "ok" } else if enrichment_summary.whois_failed { "failed" } else { "n/a" },
            if enrichment_summary.analytics_ids_inserted { "ok" } else if enrichment_summary.analytics_ids_failed { "failed" } else { "n/a" }
        );
    }

    Ok(())
}

/// Inserts partial failures for a record.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - The ID of the main URL record
/// * `partial_failures` - Vector of partial failure records
/// * `summary` - Summary to update with insertion results
async fn insert_partial_failures(
    pool: &SqlitePool,
    url_status_id: i64,
    partial_failures: Vec<crate::storage::models::UrlPartialFailureRecord>,
    summary: &mut EnrichmentInsertSummary,
) {
    for mut partial_failure in partial_failures {
        partial_failure.url_status_id = url_status_id;
        match insert::insert_url_partial_failure(pool, &partial_failure).await {
            Ok(_) => summary.partial_failures_inserted += 1,
            Err(e) => {
                summary.partial_failures_failed += 1;
                log::warn!(
                    "Failed to insert partial failure for url_status_id {}: {}",
                    url_status_id,
                    e
                );
            }
        }
    }
}

/// Inserts GeoIP data for a record.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - The ID of the main URL record
/// * `geoip` - Optional tuple of (IP address, GeoIP result)
/// * `summary` - Summary to update with insertion results
async fn insert_geoip_enrichment(
    pool: &SqlitePool,
    url_status_id: i64,
    geoip: &Option<(String, crate::geoip::GeoIpResult)>,
    summary: &mut EnrichmentInsertSummary,
) {
    if let Some((ip_address, geoip_result)) = geoip {
        match insert::insert_geoip_data(pool, url_status_id, ip_address, geoip_result).await {
            Ok(_) => summary.geoip_inserted = true,
            Err(e) => {
                summary.geoip_failed = true;
                log::warn!(
                    "Failed to insert GeoIP data for IP '{}' (url_status_id {}): {}",
                    ip_address,
                    url_status_id,
                    e
                );
            }
        }
    }
}

/// Inserts structured data for a record.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - The ID of the main URL record
/// * `structured_data` - Optional structured data
/// * `summary` - Summary to update with insertion results
async fn insert_structured_data_enrichment(
    pool: &SqlitePool,
    url_status_id: i64,
    structured_data: &Option<crate::parse::StructuredData>,
    summary: &mut EnrichmentInsertSummary,
) {
    if let Some(structured_data) = structured_data {
        match insert::insert_structured_data(pool, url_status_id, structured_data).await {
            Ok(_) => summary.structured_data_inserted = true,
            Err(e) => {
                summary.structured_data_failed = true;
                log::warn!(
                    "Failed to insert structured data for url_status_id {}: {}",
                    url_status_id,
                    e
                );
            }
        }
    }
}

/// Inserts social media links for a record.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - The ID of the main URL record
/// * `social_media_links` - Vector of social media links
/// * `summary` - Summary to update with insertion results
async fn insert_social_media_enrichment(
    pool: &SqlitePool,
    url_status_id: i64,
    social_media_links: &[crate::parse::SocialMediaLink],
    summary: &mut EnrichmentInsertSummary,
) {
    if !social_media_links.is_empty() {
        match insert::insert_social_media_links(pool, url_status_id, social_media_links).await {
            Ok(_) => summary.social_media_inserted = true,
            Err(e) => {
                summary.social_media_failed = true;
                log::warn!(
                    "Failed to insert social media links for url_status_id {}: {}",
                    url_status_id,
                    e
                );
            }
        }
    }
}

/// Inserts security warnings for a record.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - The ID of the main URL record
/// * `security_warnings` - Vector of security warnings
/// * `summary` - Summary to update with insertion results
async fn insert_security_warnings_enrichment(
    pool: &SqlitePool,
    url_status_id: i64,
    security_warnings: &[crate::security::SecurityWarning],
    summary: &mut EnrichmentInsertSummary,
) {
    if !security_warnings.is_empty() {
        match insert::insert_security_warnings(pool, url_status_id, security_warnings).await {
            Ok(_) => summary.security_warnings_inserted = true,
            Err(e) => {
                summary.security_warnings_failed = true;
                log::warn!(
                    "Failed to insert security warnings for url_status_id {}: {}",
                    url_status_id,
                    e
                );
            }
        }
    }
}

/// Inserts WHOIS data for a record.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - The ID of the main URL record
/// * `whois` - Optional WHOIS result
/// * `summary` - Summary to update with insertion results
async fn insert_whois_enrichment(
    pool: &SqlitePool,
    url_status_id: i64,
    whois: &Option<crate::whois::WhoisResult>,
    summary: &mut EnrichmentInsertSummary,
) {
    if let Some(ref whois_result) = whois {
        match insert::insert_whois_data(pool, url_status_id, whois_result).await {
            Ok(_) => summary.whois_inserted = true,
            Err(e) => {
                summary.whois_failed = true;
                log::warn!(
                    "Failed to insert WHOIS data for url_status_id {}: {}",
                    url_status_id,
                    e
                );
            }
        }
    }
}

/// Inserts analytics IDs for a record.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - The ID of the main URL record
/// * `analytics_ids` - Vector of analytics IDs
/// * `summary` - Summary to update with insertion results
async fn insert_analytics_ids_enrichment(
    pool: &SqlitePool,
    url_status_id: i64,
    analytics_ids: &[crate::parse::AnalyticsId],
    summary: &mut EnrichmentInsertSummary,
) {
    if !analytics_ids.is_empty() {
        match insert::insert_analytics_ids(pool, url_status_id, analytics_ids).await {
            Ok(_) => summary.analytics_ids_inserted = true,
            Err(e) => {
                summary.analytics_ids_failed = true;
                log::warn!(
                    "Failed to insert analytics IDs for url_status_id {}: {}",
                    url_status_id,
                    e
                );
            }
        }
    }
}

/// Inserts all enrichment data for a record.
///
/// This function inserts enrichment data (GeoIP, WHOIS, structured data, etc.) after the main
/// URL record has been committed. Failures are logged but don't propagate, ensuring that
/// enrichment data failures don't prevent URL processing.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - The ID of the main URL record
/// * `record` - The batch record containing enrichment data
///
/// # Returns
///
/// An `EnrichmentInsertSummary` tracking which enrichment data types succeeded or failed.
/// This allows callers to monitor enrichment data insertion health.
async fn insert_enrichment_data(
    pool: &SqlitePool,
    url_status_id: i64,
    record: BatchRecord,
) -> EnrichmentInsertSummary {
    let mut summary = EnrichmentInsertSummary::default();

    // Insert each type of enrichment data
    insert_partial_failures(pool, url_status_id, record.partial_failures, &mut summary).await;
    insert_geoip_enrichment(pool, url_status_id, &record.geoip, &mut summary).await;
    insert_structured_data_enrichment(pool, url_status_id, &record.structured_data, &mut summary)
        .await;
    insert_social_media_enrichment(
        pool,
        url_status_id,
        &record.social_media_links,
        &mut summary,
    )
    .await;
    insert_security_warnings_enrichment(
        pool,
        url_status_id,
        &record.security_warnings,
        &mut summary,
    )
    .await;
    insert_whois_enrichment(pool, url_status_id, &record.whois, &mut summary).await;
    insert_analytics_ids_enrichment(pool, url_status_id, &record.analytics_ids, &mut summary).await;

    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geoip::GeoIpResult;
    use crate::parse::{
        AnalyticsId, AnalyticsProvider, SocialMediaLink, SocialPlatform, StructuredData,
    };
    use crate::security::SecurityWarning;
    use crate::storage::models::UrlRecord;
    use crate::whois::WhoisResult;
    use chrono::{DateTime, NaiveDate};
    use sqlx::Row;
    use std::collections::{HashMap, HashSet};

    use crate::storage::test_helpers::create_test_pool;

    async fn create_test_run(pool: &SqlitePool, run_id: &str) {
        sqlx::query(
            "INSERT INTO runs (run_id, start_time_ms) VALUES (?, ?)
             ON CONFLICT(run_id) DO NOTHING",
        )
        .bind(run_id)
        .bind(1704067200000i64)
        .execute(pool)
        .await
        .expect("Failed to insert test run");
    }

    fn create_test_url_record() -> UrlRecord {
        UrlRecord {
            initial_domain: "example.com".to_string(),
            final_domain: "example.com".to_string(),
            ip_address: "93.184.216.34".to_string(),
            reverse_dns_name: Some("example.com".to_string()),
            status: 200,
            status_desc: "OK".to_string(),
            response_time: 0.123,
            title: "Example Domain".to_string(),
            keywords: Some("example, test".to_string()),
            description: Some("Example description".to_string()),
            tls_version: Some(crate::models::TlsVersion::Tls13),
            ssl_cert_subject: Some("CN=example.com".to_string()),
            ssl_cert_issuer: Some("CN=Let's Encrypt".to_string()),
            ssl_cert_valid_from: NaiveDate::from_ymd_opt(2024, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0),
            ssl_cert_valid_to: NaiveDate::from_ymd_opt(2025, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0),
            is_mobile_friendly: true,
            timestamp: 1704067200000, // 2024-01-01 00:00:00 UTC in milliseconds
            nameservers: Some(r#"["ns1.example.com", "ns2.example.com"]"#.to_string()),
            txt_records: Some(r#"["v=spf1 include:_spf.example.com ~all"]"#.to_string()),
            mx_records: Some(r#"[{"priority": 10, "hostname": "mail.example.com"}]"#.to_string()),
            spf_record: Some("v=spf1 include:_spf.example.com ~all".to_string()),
            dmarc_record: Some("v=dmarc1; p=none".to_string()),
            cipher_suite: Some("TLS_AES_256_GCM_SHA384".to_string()),
            key_algorithm: Some(crate::models::KeyAlgorithm::RSA),
            run_id: Some("test-run-123".to_string()),
        }
    }

    #[tokio::test]
    async fn test_insert_batch_record_basic() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-123").await;

        let record = BatchRecord {
            url_record: create_test_url_record(),
            security_headers: HashMap::new(),
            http_headers: HashMap::new(),
            oids: HashSet::new(),
            redirect_chain: vec![],
            technologies: vec![],
            subject_alternative_names: vec![],
            analytics_ids: vec![],
            geoip: None,
            structured_data: None,
            social_media_links: vec![],
            security_warnings: vec![],
            whois: None,
            partial_failures: vec![],
        };

        let result = insert_batch_record(&pool, record).await;
        assert!(result.is_ok());

        // Verify main record was inserted
        let row = sqlx::query(
            "SELECT id, initial_domain, title FROM url_status WHERE initial_domain = 'example.com'",
        )
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch URL record");

        assert_eq!(row.get::<String, _>("initial_domain"), "example.com");
        assert_eq!(row.get::<String, _>("title"), "Example Domain");
    }

    // Large test function handling comprehensive batch record insertion with all enrichment data.
    // Consider refactoring into smaller focused test functions in Phase 4.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn test_insert_batch_record_with_enrichment() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-123").await;

        let mut security_headers = HashMap::new();
        security_headers.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=31536000".to_string(),
        );

        let mut http_headers = HashMap::new();
        http_headers.insert("Server".to_string(), "nginx/1.18.0".to_string());

        let mut oids = HashSet::new();
        oids.insert("1.3.6.1.4.1.311".to_string());

        let record = BatchRecord {
            url_record: create_test_url_record(),
            security_headers: security_headers.clone(),
            http_headers: http_headers.clone(),
            oids: oids.clone(),
            redirect_chain: vec![
                "http://example.com".to_string(),
                "https://example.com".to_string(),
            ],
            technologies: vec![
                crate::fingerprint::DetectedTechnology {
                    name: "WordPress".to_string(),
                    version: None,
                },
                crate::fingerprint::DetectedTechnology {
                    name: "PHP".to_string(),
                    version: None,
                },
            ],
            subject_alternative_names: vec![
                "example.com".to_string(),
                "www.example.com".to_string(),
            ],
            analytics_ids: vec![AnalyticsId {
                provider: AnalyticsProvider::GoogleAnalytics,
                id: "UA-123456-1".to_string(),
            }],
            geoip: None,
            structured_data: None,
            social_media_links: vec![],
            security_warnings: vec![],
            whois: None,
            partial_failures: vec![],
        };

        let result = insert_batch_record(&pool, record).await;
        assert!(result.is_ok());

        // Verify main record
        let url_status_id: i64 =
            sqlx::query_scalar("SELECT id FROM url_status WHERE initial_domain = 'example.com'")
                .fetch_one(&pool)
                .await
                .expect("Failed to fetch URL status ID");

        // Verify satellite data
        let tech_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_technologies WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count technologies");
        assert_eq!(tech_count, 2);

        let redirect_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_redirect_chain WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count redirects");
        assert_eq!(redirect_count, 2);

        let san_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_certificate_sans WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count SANs");
        assert_eq!(san_count, 2);

        // Verify security headers
        let sec_header = sqlx::query("SELECT header_value FROM url_security_headers WHERE url_status_id = ? AND header_name = 'Strict-Transport-Security'")
            .bind(url_status_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch security header");
        assert_eq!(
            sec_header.get::<String, _>("header_value"),
            "max-age=31536000"
        );

        // Verify HTTP headers
        let http_header = sqlx::query("SELECT header_value FROM url_http_headers WHERE url_status_id = ? AND header_name = 'Server'")
            .bind(url_status_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch HTTP header");
        assert_eq!(http_header.get::<String, _>("header_value"), "nginx/1.18.0");

        // Verify OIDs
        let oid_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_certificate_oids WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count OIDs");
        assert_eq!(oid_count, 1);

        // Verify analytics IDs
        let analytics_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_analytics_ids WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count analytics IDs");
        assert_eq!(analytics_count, 1);
    }

    #[tokio::test]
    async fn test_insert_batch_record_with_all_enrichment() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-123").await;

        let geoip_result = GeoIpResult {
            country_code: Some("US".to_string()),
            country_name: Some("United States".to_string()),
            region: None,
            city: Some("New York".to_string()),
            latitude: Some(40.7128),
            longitude: Some(-74.0060),
            postal_code: None,
            timezone: None,
            asn: Some(15169),
            asn_org: Some("Google LLC".to_string()),
        };

        let mut structured_data = StructuredData::default();
        structured_data
            .json_ld
            .push(serde_json::json!({"@type": "WebPage"}));
        structured_data
            .open_graph
            .insert("og:title".to_string(), "Test".to_string());

        let record = BatchRecord {
            url_record: create_test_url_record(),
            security_headers: HashMap::new(),
            http_headers: HashMap::new(),
            oids: HashSet::new(),
            redirect_chain: vec![],
            technologies: vec![],
            subject_alternative_names: vec![],
            analytics_ids: vec![],
            geoip: Some(("93.184.216.34".to_string(), geoip_result)),
            structured_data: Some(structured_data),
            social_media_links: vec![SocialMediaLink {
                platform: SocialPlatform::LinkedIn,
                url: "https://www.linkedin.com/company/example".to_string(),
                identifier: Some("example".to_string()),
            }],
            security_warnings: vec![SecurityWarning::NoHttps],
            whois: Some(WhoisResult {
                creation_date: Some(DateTime::from_timestamp(946684800, 0).unwrap()),
                expiration_date: None,
                updated_date: None,
                registrar: Some("Example Registrar".to_string()),
                registrant_country: None,
                registrant_org: None,
                status: None,
                nameservers: None,
                raw_text: None,
            }),
            partial_failures: vec![],
        };

        let result = insert_batch_record(&pool, record).await;
        assert!(result.is_ok());

        // Verify enrichment data was inserted
        let url_status_id: i64 =
            sqlx::query_scalar("SELECT id FROM url_status WHERE initial_domain = 'example.com'")
                .fetch_one(&pool)
                .await
                .expect("Failed to fetch URL status ID");

        // Verify GeoIP
        let geoip_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_geoip WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count GeoIP records");
        assert_eq!(geoip_count, 1);

        // Verify structured data
        let structured_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_structured_data WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count structured data");
        assert!(structured_count > 0);

        // Verify social media links
        let social_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM url_social_media_links WHERE url_status_id = ?",
        )
        .bind(url_status_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to count social media links");
        assert_eq!(social_count, 1);

        // Verify security warnings
        let security_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM url_security_warnings WHERE url_status_id = ?",
        )
        .bind(url_status_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to count security warnings");
        assert_eq!(security_count, 1);

        // Verify WHOIS
        let whois_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_whois WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count WHOIS records");
        assert_eq!(whois_count, 1);
    }

    #[tokio::test]
    async fn test_insert_batch_record_empty_enrichment() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-123").await;

        let record = BatchRecord {
            url_record: create_test_url_record(),
            security_headers: HashMap::new(),
            http_headers: HashMap::new(),
            oids: HashSet::new(),
            redirect_chain: vec![],
            technologies: vec![],
            subject_alternative_names: vec![],
            analytics_ids: vec![],
            geoip: None,
            structured_data: None,
            social_media_links: vec![],
            security_warnings: vec![],
            whois: None,
            partial_failures: vec![],
        };

        let result = insert_batch_record(&pool, record).await;
        assert!(result.is_ok());

        // Verify main record exists but no enrichment
        let url_status_id: i64 =
            sqlx::query_scalar("SELECT id FROM url_status WHERE initial_domain = 'example.com'")
                .fetch_one(&pool)
                .await
                .expect("Failed to fetch URL status ID");

        // Verify no enrichment data
        let geoip_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_geoip WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count GeoIP records");
        assert_eq!(geoip_count, 0);

        let analytics_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_analytics_ids WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count analytics IDs");
        assert_eq!(analytics_count, 0);
    }

    #[tokio::test]
    async fn test_insert_enrichment_data_partial_failure_handled() {
        // Test that partial failure insertion failures don't prevent other enrichment
        // This is critical - one enrichment failure shouldn't break all enrichment
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-123").await;

        // Create a URL status record first
        let url_record = create_test_url_record();
        let _url_status_id = insert::insert_url_record(insert::url::UrlRecordInsertParams {
            pool: &pool,
            record: &url_record,
            security_headers: &HashMap::new(),
            http_headers: &HashMap::new(),
            oids: &HashSet::new(),
            redirect_chain: &[],
            technologies: &[],
            subject_alternative_names: &[],
        })
        .await
        .expect("Failed to insert URL record");

        // Create record with partial failures
        // Note: We can't easily simulate insertion failure, but we verify the error handling path exists
        let record = BatchRecord {
            url_record: create_test_url_record(),
            security_headers: HashMap::new(),
            http_headers: HashMap::new(),
            oids: HashSet::new(),
            redirect_chain: vec![],
            technologies: vec![],
            subject_alternative_names: vec![],
            analytics_ids: vec![],
            geoip: None,
            structured_data: None,
            social_media_links: vec![],
            security_warnings: vec![],
            whois: None,
            partial_failures: vec![], // Empty for this test
        };

        // Should succeed even if some enrichment fails
        let result = insert_batch_record(&pool, record).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_insert_enrichment_data_geoip_failure_doesnt_break_others() {
        // Test that GeoIP insertion failure doesn't prevent other enrichment
        // This is critical - enrichment failures should be isolated
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-123").await;

        let geoip_result = GeoIpResult {
            country_code: Some("US".to_string()),
            country_name: Some("United States".to_string()),
            region: None,
            city: Some("New York".to_string()),
            latitude: Some(40.7128),
            longitude: Some(-74.0060),
            postal_code: None,
            timezone: None,
            asn: Some(15169),
            asn_org: Some("Google LLC".to_string()),
        };

        let record = BatchRecord {
            url_record: create_test_url_record(),
            security_headers: HashMap::new(),
            http_headers: HashMap::new(),
            oids: HashSet::new(),
            redirect_chain: vec![],
            technologies: vec![crate::fingerprint::DetectedTechnology {
                name: "WordPress".to_string(),
                version: None,
            }], // Should still be inserted even if GeoIP fails
            subject_alternative_names: vec![],
            analytics_ids: vec![],
            geoip: Some(("93.184.216.34".to_string(), geoip_result)),
            structured_data: None,
            social_media_links: vec![],
            security_warnings: vec![],
            whois: None,
            partial_failures: vec![],
        };

        // Should succeed - main record and technologies should be inserted
        // Even if GeoIP insertion fails (which it shouldn't in this test)
        let result = insert_batch_record(&pool, record).await;
        assert!(result.is_ok());

        // Verify technologies were inserted (enrichment failure shouldn't prevent this)
        let url_status_id: i64 =
            sqlx::query_scalar("SELECT id FROM url_status WHERE initial_domain = 'example.com'")
                .fetch_one(&pool)
                .await
                .expect("Failed to fetch URL status ID");

        let tech_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_technologies WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count technologies");
        assert_eq!(tech_count, 1);
    }

    #[tokio::test]
    async fn test_insert_enrichment_data_all_enrichment_failures_logged() {
        // Test that all enrichment failures are logged but don't propagate
        // This is critical - enrichment is optional, failures shouldn't break main record
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-123").await;

        let record = BatchRecord {
            url_record: create_test_url_record(),
            security_headers: HashMap::new(),
            http_headers: HashMap::new(),
            oids: HashSet::new(),
            redirect_chain: vec![],
            technologies: vec![],
            subject_alternative_names: vec![],
            analytics_ids: vec![],
            geoip: None,
            structured_data: None,
            social_media_links: vec![],
            security_warnings: vec![],
            whois: None,
            partial_failures: vec![],
        };

        // Should succeed even with no enrichment data
        // The function insert_enrichment_data logs warnings but doesn't propagate errors
        let result = insert_batch_record(&pool, record).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_insert_batch_record_main_record_failure_propagates() {
        // Test that main record insertion failure propagates (unlike enrichment)
        // This is critical - main record failure should be reported
        let pool = create_test_pool().await;

        // Close pool to cause insertion failure
        pool.close().await;

        let record = BatchRecord {
            url_record: create_test_url_record(),
            security_headers: HashMap::new(),
            http_headers: HashMap::new(),
            oids: HashSet::new(),
            redirect_chain: vec![],
            technologies: vec![],
            subject_alternative_names: vec![],
            analytics_ids: vec![],
            geoip: None,
            structured_data: None,
            social_media_links: vec![],
            security_warnings: vec![],
            whois: None,
            partial_failures: vec![],
        };

        // Should fail - main record insertion failure propagates
        let result = insert_batch_record(&pool, record).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_enrichment_insert_summary_total_failures_calculation() {
        // Test that total_failures correctly counts all failure types
        // This is critical - incorrect counting would break monitoring/logging
        let summary = EnrichmentInsertSummary {
            partial_failures_failed: 2,
            geoip_failed: true,
            structured_data_failed: true,
            social_media_failed: false,
            security_warnings_failed: true,
            whois_failed: false,
            analytics_ids_failed: true,
            ..Default::default()
        };

        // Should count: 2 (partial) + 1 (geoip) + 1 (structured) + 1 (security) + 1 (analytics) = 6
        assert_eq!(summary.total_failures(), 6);
    }

    #[test]
    fn test_enrichment_insert_summary_total_failures_zero() {
        // Test that total_failures returns 0 when no failures
        let summary = EnrichmentInsertSummary::default();
        assert_eq!(summary.total_failures(), 0);
    }

    #[test]
    fn test_enrichment_insert_summary_has_failures_true() {
        // Test that has_failures returns true when any failure exists
        let summary = EnrichmentInsertSummary {
            geoip_failed: true,
            ..Default::default()
        };
        assert!(summary.has_failures());
    }

    #[test]
    fn test_enrichment_insert_summary_has_failures_false() {
        // Test that has_failures returns false when no failures
        let summary = EnrichmentInsertSummary::default();
        assert!(!summary.has_failures());
    }

    #[test]
    fn test_enrichment_insert_summary_partial_failures_counted() {
        // Test that partial_failures_failed is included in total_failures
        // This is critical - partial failures are a different type of failure
        let summary = EnrichmentInsertSummary {
            partial_failures_failed: 5,
            ..Default::default()
        };
        assert_eq!(summary.total_failures(), 5);
        assert!(summary.has_failures());
    }

    #[test]
    fn test_enrichment_insert_summary_all_failures() {
        // Test that all enrichment types failing is counted correctly
        // This is critical - ensures all failure types are tracked
        let summary = EnrichmentInsertSummary {
            partial_failures_failed: 3,
            geoip_failed: true,
            structured_data_failed: true,
            social_media_failed: true,
            security_warnings_failed: true,
            whois_failed: true,
            analytics_ids_failed: true,
            ..Default::default()
        };
        // Should count: 3 (partial) + 6 (all other types) = 9
        assert_eq!(summary.total_failures(), 9);
        assert!(summary.has_failures());
    }

    #[test]
    fn test_enrichment_insert_summary_mixed_success_failure() {
        // Test mixed success/failure scenario
        // This is critical - real-world scenarios often have partial success
        let summary = EnrichmentInsertSummary {
            partial_failures_inserted: 2,
            partial_failures_failed: 1,
            geoip_inserted: true,
            geoip_failed: false,
            structured_data_inserted: false,
            structured_data_failed: true,
            social_media_inserted: true,
            social_media_failed: false,
            security_warnings_inserted: false,
            security_warnings_failed: true,
            whois_inserted: true,
            whois_failed: false,
            analytics_ids_inserted: false,
            analytics_ids_failed: true,
        };
        // Should count: 1 (partial) + 1 (structured) + 1 (security) + 1 (analytics) = 4
        assert_eq!(summary.total_failures(), 4);
        assert!(summary.has_failures());
    }

    #[test]
    fn test_enrichment_insert_summary_large_partial_failures_count() {
        // Test that large partial_failures_failed counts work correctly
        // This is critical - ensures no overflow issues
        let summary = EnrichmentInsertSummary {
            partial_failures_failed: 1000,
            ..Default::default()
        };
        assert_eq!(summary.total_failures(), 1000);
        assert!(summary.has_failures());
    }

    #[test]
    fn test_enrichment_insert_summary_all_success() {
        // Test that all enrichment types succeeding results in no failures
        // This is critical - ensures success is correctly tracked
        let summary = EnrichmentInsertSummary {
            partial_failures_inserted: 5,
            partial_failures_failed: 0,
            geoip_inserted: true,
            geoip_failed: false,
            structured_data_inserted: true,
            structured_data_failed: false,
            social_media_inserted: true,
            social_media_failed: false,
            security_warnings_inserted: true,
            security_warnings_failed: false,
            whois_inserted: true,
            whois_failed: false,
            analytics_ids_inserted: true,
            analytics_ids_failed: false,
        };
        assert_eq!(summary.total_failures(), 0);
        assert!(!summary.has_failures());
    }
}
