//! Direct record insertion (non-batched).
//!
//! This module provides functions to insert BatchRecord data directly into the database
//! without batching. This is more efficient than batching for SQLite WAL mode.

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;
use crate::storage::BatchRecord;

use crate::storage::insert;

/// Inserts a batch record directly into the database.
///
/// This function inserts the main URL record and all enrichment data immediately,
/// without buffering or batching. With SQLite WAL mode, this provides better
/// performance than batching since writes can proceed concurrently.
pub async fn insert_batch_record(
    pool: &SqlitePool,
    record: BatchRecord,
) -> Result<(), DatabaseError> {
    // Use reference instead of clone for error message (domain is already owned in record)
    let domain = &record.url_record.initial_domain;

    // Insert main URL record
    let url_status_id = insert::insert_url_record(
        pool,
        &record.url_record,
        &record.security_headers,
        &record.http_headers,
        &record.oids,
        &record.redirect_chain,
        &record.technologies,
        &record.subject_alternative_names,
    )
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
    insert_enrichment_data(pool, url_status_id, record).await;

    Ok(())
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
async fn insert_enrichment_data(pool: &SqlitePool, url_status_id: i64, record: BatchRecord) {
    // Insert partial failures (DNS/TLS errors that didn't prevent processing)
    for mut partial_failure in record.partial_failures {
        partial_failure.url_status_id = url_status_id;
        if let Err(e) = insert::insert_url_partial_failure(pool, &partial_failure).await {
            log::warn!(
                "Failed to insert partial failure for url_status_id {}: {}",
                url_status_id,
                e
            );
        }
    }

    // Insert GeoIP data if available
    if let Some((ip_address, geoip_result)) = &record.geoip {
        if let Err(e) =
            insert::insert_geoip_data(pool, url_status_id, ip_address, geoip_result).await
        {
            log::warn!(
                "Failed to insert GeoIP data for IP '{}' (url_status_id {}): {}",
                ip_address,
                url_status_id,
                e
            );
        }
    }

    // Insert structured data if available
    if let Some(structured_data) = &record.structured_data {
        if let Err(e) = insert::insert_structured_data(pool, url_status_id, structured_data).await {
            log::warn!(
                "Failed to insert structured data for url_status_id {}: {}",
                url_status_id,
                e
            );
        }
    }

    // Insert social media links if available
    if !record.social_media_links.is_empty() {
        if let Err(e) =
            insert::insert_social_media_links(pool, url_status_id, &record.social_media_links).await
        {
            log::warn!(
                "Failed to insert social media links for url_status_id {}: {}",
                url_status_id,
                e
            );
        }
    }

    // Insert security warnings if available
    if !record.security_warnings.is_empty() {
        if let Err(e) =
            insert::insert_security_warnings(pool, url_status_id, &record.security_warnings).await
        {
            log::warn!(
                "Failed to insert security warnings for url_status_id {}: {}",
                url_status_id,
                e
            );
        }
    }

    // Insert WHOIS data if available
    if let Some(ref whois_result) = record.whois {
        if let Err(e) = insert::insert_whois_data(pool, url_status_id, whois_result).await {
            log::warn!(
                "Failed to insert WHOIS data for url_status_id {}: {}",
                url_status_id,
                e
            );
        }
    }

    // Insert analytics IDs if available
    if !record.analytics_ids.is_empty() {
        if let Err(e) =
            insert::insert_analytics_ids(pool, url_status_id, &record.analytics_ids).await
        {
            log::warn!(
                "Failed to insert analytics IDs for url_status_id {}: {}",
                url_status_id,
                e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geoip::GeoIpResult;
    use crate::parse::{AnalyticsId, SocialMediaLink, StructuredData};
    use crate::security::SecurityWarning;
    use crate::storage::migrations::run_migrations;
    use crate::storage::models::UrlRecord;
    use crate::whois::WhoisResult;
    use chrono::{DateTime, NaiveDate};
    use sqlx::{Row, SqlitePool};
    use std::collections::{HashMap, HashSet};

    async fn create_test_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");
        pool
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
            tls_version: Some("TLSv1.3".to_string()),
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
            key_algorithm: Some("RSA".to_string()),
            run_id: Some("test-run-123".to_string()),
        }
    }

    #[tokio::test]
    async fn test_insert_batch_record_basic() {
        let pool = create_test_pool().await;

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
        let row =
            sqlx::query("SELECT id, domain, title FROM url_status WHERE domain = 'example.com'")
                .fetch_one(&pool)
                .await
                .expect("Failed to fetch URL record");

        assert_eq!(row.get::<String, _>("domain"), "example.com");
        assert_eq!(row.get::<String, _>("title"), "Example Domain");
    }

    #[tokio::test]
    async fn test_insert_batch_record_with_enrichment() {
        let pool = create_test_pool().await;

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
            technologies: vec!["WordPress".to_string(), "PHP".to_string()],
            subject_alternative_names: vec![
                "example.com".to_string(),
                "www.example.com".to_string(),
            ],
            analytics_ids: vec![AnalyticsId {
                provider: "Google Analytics".to_string(),
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
            sqlx::query_scalar("SELECT id FROM url_status WHERE domain = 'example.com'")
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
            sqlx::query_scalar("SELECT COUNT(*) FROM url_oids WHERE url_status_id = ?")
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
                platform: "LinkedIn".to_string(),
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
            sqlx::query_scalar("SELECT id FROM url_status WHERE domain = 'example.com'")
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
            sqlx::query_scalar("SELECT id FROM url_status WHERE domain = 'example.com'")
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
}
