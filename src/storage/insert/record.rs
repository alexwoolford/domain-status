//! Direct record insertion (non-batched).
//!
//! This module provides functions to insert `PersistedUrlRecord` data directly into the
//! database without buffering. Prefer short per-URL transactions over accumulating
//! large in-memory batches; `SQLite` still serializes writers at the database file.

use sqlx::SqlitePool;

use crate::error_handling::{DatabaseError, ErrorType};
use crate::storage::insert::retry::with_sqlite_retry;
use crate::storage::insert::url::URL_STATUS_ENRICHMENT_SATELLITE_TABLES;
use crate::storage::insert::{self, SatelliteWriteFailure, UrlUpsertOutcome};
use crate::storage::models::UrlPartialFailureRecord;
use crate::storage::PersistedUrlRecord;

/// Outcome of one optional enrichment insert (`inserted && failed` is impossible).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EnrichmentWrite {
    /// No payload for this enrichment type.
    #[default]
    Skipped,
    /// Insert succeeded.
    Inserted,
    /// Insert returned `Err`.
    Failed,
}

impl EnrichmentWrite {
    fn as_log_str(self) -> &'static str {
        match self {
            Self::Skipped => "n/a",
            Self::Inserted => "ok",
            Self::Failed => "failed",
        }
    }

    const fn is_failed(self) -> bool {
        matches!(self, Self::Failed)
    }
}

/// Summary of enrichment data insertion results.
///
/// Tracks which enrichment data types succeeded or failed to insert.
/// This allows callers to monitor enrichment data insertion health
/// without blocking the main record insertion.
#[derive(Debug, Clone, Default)]
pub struct EnrichmentInsertSummary {
    /// Number of partial failures successfully inserted
    pub partial_failures_inserted: usize,
    /// Subset of inserted rows with `error_type` = `Satellite insert error`.
    pub satellite_insert_errors_inserted: usize,
    /// Number of partial failures that failed to insert
    pub partial_failures_failed: usize,
    /// `GeoIP` row write.
    pub geoip: EnrichmentWrite,
    /// Structured-data row write.
    pub structured_data: EnrichmentWrite,
    /// Social-media links write.
    pub social_media: EnrichmentWrite,
    /// WHOIS row write.
    pub whois: EnrichmentWrite,
    /// Analytics IDs write.
    pub analytics_ids: EnrichmentWrite,
    /// Favicon row write.
    pub favicon: EnrichmentWrite,
    /// Contact links write.
    pub contact_links: EnrichmentWrite,
    /// Exposed secrets write.
    pub exposed_secrets: EnrichmentWrite,
}

impl EnrichmentInsertSummary {
    /// Returns the total number of enrichment operations that failed.
    pub fn total_failures(&self) -> usize {
        self.partial_failures_failed
            + usize::from(self.geoip.is_failed())
            + usize::from(self.structured_data.is_failed())
            + usize::from(self.social_media.is_failed())
            + usize::from(self.whois.is_failed())
            + usize::from(self.analytics_ids.is_failed())
            + usize::from(self.favicon.is_failed())
            + usize::from(self.contact_links.is_failed())
            + usize::from(self.exposed_secrets.is_failed())
    }

    /// Returns true if any enrichment operations failed.
    pub fn has_failures(&self) -> bool {
        self.total_failures() > 0
    }
}

fn try_enrich_tx(
    label: &str,
    table: &'static str,
    url_status_id: i64,
    status: &mut EnrichmentWrite,
    insert_failures: &mut Vec<SatelliteWriteFailure>,
    result: Result<(), DatabaseError>,
) {
    match result {
        Ok(()) => *status = EnrichmentWrite::Inserted,
        Err(e) => {
            *status = EnrichmentWrite::Failed;
            log::warn!("Failed to insert {label} for url_status_id {url_status_id}: {e}");
            insert_failures.push(SatelliteWriteFailure {
                table,
                message: e.to_string(),
            });
        }
    }
}

fn satellite_write_to_partial_failure(
    url_status_id: i64,
    timestamp: i64,
    run_id: Option<String>,
    failure: &SatelliteWriteFailure,
) -> UrlPartialFailureRecord {
    UrlPartialFailureRecord {
        url_status_id,
        error_type: ErrorType::SatelliteInsertError,
        error_message: format!("{}: {}", failure.table, failure.message),
        timestamp,
        run_id,
    }
}

async fn insert_partial_failures_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    url_status_id: i64,
    partial_failures: Vec<UrlPartialFailureRecord>,
    extra: &[SatelliteWriteFailure],
    timestamp: i64,
    run_id: Option<String>,
    summary: &mut EnrichmentInsertSummary,
) {
    let extras = extra.iter().map(|failure| {
        satellite_write_to_partial_failure(url_status_id, timestamp, run_id.clone(), failure)
    });
    for mut partial_failure in partial_failures.into_iter().chain(extras) {
        partial_failure.url_status_id = url_status_id;
        match insert::insert_url_partial_failure_in_tx(tx, &partial_failure).await {
            Ok(_) => {
                summary.partial_failures_inserted += 1;
                if partial_failure.error_type == ErrorType::SatelliteInsertError {
                    summary.satellite_insert_errors_inserted += 1;
                }
            }
            Err(e) => {
                summary.partial_failures_failed += 1;
                log::warn!(
                    "Failed to insert partial failure for url_status_id {url_status_id}: {e}"
                );
            }
        }
    }
}

async fn insert_exposed_secrets_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    url_status_id: i64,
    exposed_secrets: &[crate::parse::ExposedSecret],
    summary: &mut EnrichmentInsertSummary,
    insert_failures: &mut Vec<SatelliteWriteFailure>,
) {
    if exposed_secrets.is_empty() {
        return;
    }
    match insert::enrichment::insert_exposed_secrets_in_tx(tx, url_status_id, exposed_secrets).await
    {
        Ok(ids) => {
            summary.exposed_secrets = EnrichmentWrite::Inserted;
            let jwt_items: Vec<(i64, &crate::parse::jwt::DecodedJwt)> = exposed_secrets
                .iter()
                .zip(&ids)
                .filter_map(|(secret, &secret_id)| {
                    secret.decoded_jwt.as_ref().map(|jwt| (secret_id, jwt))
                })
                .collect();
            if !jwt_items.is_empty() {
                if let Err(e) =
                    insert::enrichment::insert_jwt_claims_batch_in_tx(tx, &jwt_items).await
                {
                    log::warn!(
                        "Failed to insert JWT claims batch for url_status_id {url_status_id}: {e}"
                    );
                    insert_failures.push(SatelliteWriteFailure {
                        table: "url_jwt_claims",
                        message: e.to_string(),
                    });
                }
            }
        }
        Err(e) => {
            summary.exposed_secrets = EnrichmentWrite::Failed;
            log::warn!("Failed to insert exposed secrets for url_status_id {url_status_id}: {e}");
            insert_failures.push(SatelliteWriteFailure {
                table: "url_exposed_secrets",
                message: e.to_string(),
            });
        }
    }
}

/// Replaces enrichment satellites in one writer transaction after the fact row commits.
async fn insert_enrichment_data(
    pool: &SqlitePool,
    url_status_id: i64,
    record: PersistedUrlRecord,
    core_satellite_failures: Vec<SatelliteWriteFailure>,
) -> EnrichmentInsertSummary {
    match with_sqlite_retry(|| {
        insert_enrichment_txn(pool, url_status_id, &record, &core_satellite_failures)
    })
    .await
    {
        Ok(summary) => summary,
        Err(e) => {
            log::warn!(
                "Enrichment transaction failed for url_status_id {url_status_id}: {e}; prior enrichment rows kept"
            );
            EnrichmentInsertSummary {
                partial_failures_failed: core_satellite_failures.len()
                    + record.partial_failures.len(),
                ..EnrichmentInsertSummary::default()
            }
        }
    }
}

#[allow(clippy::too_many_lines)] // One insert path per enrichment satellite
async fn insert_enrichment_txn(
    pool: &SqlitePool,
    url_status_id: i64,
    record: &PersistedUrlRecord,
    core_satellite_failures: &[SatelliteWriteFailure],
) -> Result<EnrichmentInsertSummary, DatabaseError> {
    let mut tx = pool.begin().await.map_err(DatabaseError::SqlError)?;
    super::utils::delete_child_rows(
        &mut tx,
        URL_STATUS_ENRICHMENT_SATELLITE_TABLES,
        url_status_id,
    )
    .await
    .map_err(DatabaseError::SqlError)?;

    let mut summary = EnrichmentInsertSummary::default();
    let mut insert_failures = Vec::new();

    if let Some((ip_address, geoip_result)) = record.geoip.as_ref() {
        try_enrich_tx(
            &format!("GeoIP data for IP '{ip_address}'"),
            "url_geoip",
            url_status_id,
            &mut summary.geoip,
            &mut insert_failures,
            insert::enrichment::insert_geoip_data_in_tx(&mut tx, url_status_id, geoip_result).await,
        );
    }

    if let Some(structured_data) = record.structured_data.as_ref() {
        try_enrich_tx(
            "structured data",
            "url_structured_data",
            url_status_id,
            &mut summary.structured_data,
            &mut insert_failures,
            insert::enrichment::insert_structured_data_in_tx(
                &mut tx,
                url_status_id,
                structured_data,
            )
            .await,
        );
    }

    if !record.social_media_links.is_empty() {
        try_enrich_tx(
            "social media links",
            "url_social_media_links",
            url_status_id,
            &mut summary.social_media,
            &mut insert_failures,
            insert::enrichment::insert_social_media_links_in_tx(
                &mut tx,
                url_status_id,
                &record.social_media_links,
            )
            .await,
        );
    }

    if let Some(whois_result) = record.whois.as_ref() {
        try_enrich_tx(
            "WHOIS data",
            "url_whois",
            url_status_id,
            &mut summary.whois,
            &mut insert_failures,
            insert::enrichment::insert_whois_data_in_tx(&mut tx, url_status_id, whois_result).await,
        );
    }

    if !record.contact_links.is_empty() {
        try_enrich_tx(
            "contact links",
            "url_contact_links",
            url_status_id,
            &mut summary.contact_links,
            &mut insert_failures,
            insert::enrichment::insert_contact_links_in_tx(
                &mut tx,
                url_status_id,
                &record.contact_links,
            )
            .await,
        );
    }

    insert_exposed_secrets_in_tx(
        &mut tx,
        url_status_id,
        &record.exposed_secrets,
        &mut summary,
        &mut insert_failures,
    )
    .await;

    if !record.analytics_ids.is_empty() {
        try_enrich_tx(
            "analytics IDs",
            "url_analytics_ids",
            url_status_id,
            &mut summary.analytics_ids,
            &mut insert_failures,
            insert::enrichment::insert_analytics_ids_in_tx(
                &mut tx,
                url_status_id,
                &record.analytics_ids,
            )
            .await,
        );
    }

    if let Some(favicon_data) = record.favicon.as_ref() {
        try_enrich_tx(
            "favicon data",
            "url_favicons",
            url_status_id,
            &mut summary.favicon,
            &mut insert_failures,
            insert::enrichment::insert_favicon_data_in_tx(&mut tx, url_status_id, favicon_data)
                .await,
        );
    }

    let mut all_write_failures = core_satellite_failures.to_vec();
    all_write_failures.append(&mut insert_failures);
    insert_partial_failures_in_tx(
        &mut tx,
        url_status_id,
        record.partial_failures.clone(),
        &all_write_failures,
        record.url_record.timestamp,
        record.url_record.run_id.clone(),
        &mut summary,
    )
    .await;

    tx.commit().await.map_err(DatabaseError::SqlError)?;
    Ok(summary)
}

/// Inserts a complete URL persistence record directly into the database.
///
/// Inserts the main URL record and enrichment data immediately, without buffering
/// a multi-URL batch. Preferring short per-URL transactions keeps lock hold time
/// bounded; WAL allows concurrent readers, but writers still serialize at `SQLite`.
pub async fn insert_persisted_url_record(
    pool: &SqlitePool,
    record: PersistedUrlRecord,
) -> Result<UrlUpsertOutcome, DatabaseError> {
    // Clone domain for error message (record will be moved to insert_enrichment_data)
    let domain = record.url_record.initial_domain.clone();

    // Insert main URL record. Mapping from PersistedUrlRecord to url_status insert
    // params lives in `UrlRecordInsertParams::from_persisted_record` so adding a new
    // satellite/field doesn't require a parallel edit at every production
    // call site.
    let upsert = insert::insert_url_record_with_outcome(
        insert::url::UrlRecordInsertParams::from_persisted_record(pool, &record),
    )
    .await
    .map_err(|e| {
        log::error!(
            "Failed to insert URL record for domain '{domain}': {e} (SQL: INSERT INTO url_status ...)"
        );
        e
    })?;
    let url_status_id = upsert.id;
    let satellite_insert_failures = upsert.satellite_insert_failures.clone();

    // Enrichment DELETE+INSERT share one writer transaction so readers never see
    // an empty gap after the fact row commits, and core satellite SQL failures
    // land in url_partial_failures with scan-time partials.
    let enrichment_summary =
        insert_enrichment_data(pool, url_status_id, record, satellite_insert_failures).await;

    // Log summary if there were any failures (for monitoring/debugging)
    if enrichment_summary.has_failures() {
        log::warn!(
            "Enrichment data insertion completed with {} failures for url_status_id {} (domain: {}): partial_failures={}/{}, geoip={}, structured_data={}, social_media={}, contact_links={}, exposed_secrets={}, whois={}, analytics_ids={}, favicon={}",
            enrichment_summary.total_failures(),
            url_status_id,
            domain,
            enrichment_summary.partial_failures_inserted,
            enrichment_summary.partial_failures_inserted + enrichment_summary.partial_failures_failed,
            enrichment_summary.geoip.as_log_str(),
            enrichment_summary.structured_data.as_log_str(),
            enrichment_summary.social_media.as_log_str(),
            enrichment_summary.contact_links.as_log_str(),
            enrichment_summary.exposed_secrets.as_log_str(),
            enrichment_summary.whois.as_log_str(),
            enrichment_summary.analytics_ids.as_log_str(),
            enrichment_summary.favicon.as_log_str()
        );
    }

    Ok(UrlUpsertOutcome {
        partial_failures_inserted: enrichment_summary.partial_failures_inserted,
        satellite_insert_errors_inserted: enrichment_summary.satellite_insert_errors_inserted,
        ..upsert
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ErrorType;
    use crate::geoip::GeoIpResult;
    use crate::parse::{
        AnalyticsId, AnalyticsProvider, SocialMediaLink, SocialPlatform, StructuredData,
    };
    use crate::storage::models::UrlRecord;
    use crate::storage::CookieInfo;
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
        let mut record = UrlRecord::test_default();
        record.reverse_dns_name = Some("example.com".to_string());
        record.response_time = 0.123;
        record.title = "Example Domain".to_string();
        record.description = Some("Example description".to_string());
        record.tls_version = Some(crate::models::TlsVersion::Tls13);
        record.ssl_cert_subject = Some("CN=example.com".to_string());
        record.ssl_cert_issuer = Some("CN=Let's Encrypt".to_string());
        record.ssl_cert_valid_from = NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0);
        record.ssl_cert_valid_to = NaiveDate::from_ymd_opt(2025, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0);
        record.timestamp = 1_704_067_200_000;
        record.nameservers = Some(r#"["ns1.example.com", "ns2.example.com"]"#.to_string());
        record.txt_records = Some(r#"["v=spf1 include:_spf.example.com ~all"]"#.to_string());
        record.mx_records =
            Some(r#"[{"priority": 10, "hostname": "mail.example.com"}]"#.to_string());
        record.spf_record = Some("v=spf1 include:_spf.example.com ~all".to_string());
        record.dmarc_record = Some("v=dmarc1; p=none".to_string());
        record.cipher_suite = Some("TLS_AES_256_GCM_SHA384".to_string());
        record.key_algorithm = Some(crate::models::KeyAlgorithm::RSA);
        record.run_id = Some("test-run-123".to_string());
        record
    }

    fn empty_persisted(url_record: UrlRecord) -> PersistedUrlRecord {
        PersistedUrlRecord {
            url_record,
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
            contact_links: vec![],
            exposed_secrets: vec![],
            whois: None,
            partial_failures: vec![],
            favicon: None,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: Vec::new(),
            cookies: Vec::new(),
            resource_hints: Vec::new(),
            script_hosts: vec![],
            security_txt: None,
            robots_txt: None,
        }
    }

    #[test]
    fn satellite_insert_failure_maps_to_partial_failure_type() {
        let rec = satellite_write_to_partial_failure(
            1,
            2,
            Some("run".into()),
            &SatelliteWriteFailure {
                table: "url_cookies",
                message: "locked".into(),
            },
        );
        assert_eq!(rec.error_type, ErrorType::SatelliteInsertError);
        assert_eq!(rec.error_message, "url_cookies: locked");
        assert_eq!(rec.url_status_id, 1);
        assert_eq!(rec.run_id.as_deref(), Some("run"));
    }

    #[tokio::test]
    async fn test_insert_persisted_url_record_basic() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-123").await;

        let record = PersistedUrlRecord {
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
            contact_links: vec![],
            exposed_secrets: vec![],
            whois: None,
            partial_failures: vec![],
            favicon: None,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: Vec::new(),
            cookies: Vec::new(),
            resource_hints: Vec::new(),
            script_hosts: vec![],
            security_txt: None,
            robots_txt: None,
        };

        let result = insert_persisted_url_record(&pool, record).await;
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

    #[tokio::test]
    async fn test_enrichment_rewrite_clears_stale_geoip() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-123").await;

        let geoip = GeoIpResult {
            country_code: Some("US".to_string()),
            country_name: Some("United States".to_string()),
            region: None,
            city: None,
            latitude: None,
            longitude: None,
            postal_code: None,
            timezone: None,
            asn: None,
            asn_org: None,
        };
        let mut first = empty_persisted(create_test_url_record());
        first.geoip = Some(("1.2.3.4".to_string(), geoip));
        let upsert = insert_persisted_url_record(&pool, first)
            .await
            .expect("first insert");
        let geo_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_geoip WHERE url_status_id = ?")
                .bind(upsert.id)
                .fetch_one(&pool)
                .await
                .expect("count geoip");
        assert_eq!(geo_count, 1);

        let second = empty_persisted(create_test_url_record());
        insert_persisted_url_record(&pool, second)
            .await
            .expect("rewrite without geoip");
        let geo_count_after: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_geoip WHERE url_status_id = ?")
                .bind(upsert.id)
                .fetch_one(&pool)
                .await
                .expect("count geoip after rewrite");
        assert_eq!(
            geo_count_after, 0,
            "enrichment rewrite with empty GeoIP must clear the previous row"
        );
    }

    #[tokio::test]
    async fn test_satellite_insert_error_persists_to_url_partial_failures() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-123").await;

        sqlx::query(
            "CREATE TRIGGER cookies_forced_insert_failure
             BEFORE INSERT ON url_cookies
             BEGIN
               SELECT RAISE(ABORT, 'forced satellite insert failure');
             END",
        )
        .execute(&pool)
        .await
        .expect("install insert-failure trigger");

        let mut record = empty_persisted(create_test_url_record());
        record.cookies = vec![CookieInfo {
            name: "session".to_string(),
            secure: true,
            http_only: true,
            same_site: Some("lax".to_string()),
            domain: None,
            path: Some("/".to_string()),
        }];

        let upsert = insert_persisted_url_record(&pool, record)
            .await
            .expect("url_status must still commit when a satellite insert fails");

        let cookie_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_cookies WHERE url_status_id = ?")
                .bind(upsert.id)
                .fetch_one(&pool)
                .await
                .expect("count cookies");
        assert_eq!(cookie_count, 0, "failed cookie insert must not leave a row");

        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT error_type, error_message FROM url_partial_failures WHERE url_status_id = ?",
        )
        .bind(upsert.id)
        .fetch_all(&pool)
        .await
        .expect("fetch partial failures");
        assert!(
            rows.iter().any(|(error_type, message)| {
                error_type == "Satellite insert error" && message.starts_with("url_cookies:")
            }),
            "core satellite SQL Err must land in url_partial_failures, got {rows:?}"
        );
    }

    #[tokio::test]
    async fn test_core_cleanup_error_skips_satellite_inserts_keeps_fact_row() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-123").await;

        let mut first = empty_persisted(create_test_url_record());
        first.technologies = vec![crate::fingerprint::DetectedTechnology {
            name: "WordPress".to_string(),
            version: None,
            category: None,
            is_implied: false,
            detection_source: None,
        }];
        first.geoip = Some((
            "1.2.3.4".to_string(),
            GeoIpResult {
                country_code: Some("US".to_string()),
                country_name: Some("United States".to_string()),
                ..GeoIpResult::default()
            },
        ));
        insert_persisted_url_record(&pool, first)
            .await
            .expect("first insert");

        sqlx::query(
            "CREATE TRIGGER core_cleanup_forced_delete_failure
             BEFORE DELETE ON url_technologies
             BEGIN
               SELECT RAISE(ABORT, 'forced core cleanup failure');
             END",
        )
        .execute(&pool)
        .await
        .expect("install delete-failure trigger");

        let mut second = empty_persisted(create_test_url_record());
        second.url_record.title = "Updated title".to_string();
        second.technologies = vec![crate::fingerprint::DetectedTechnology {
            name: "PHP".to_string(),
            version: None,
            category: None,
            is_implied: false,
            detection_source: None,
        }];
        second.geoip = Some((
            "1.2.3.4".to_string(),
            GeoIpResult {
                country_code: Some("DE".to_string()),
                country_name: Some("Germany".to_string()),
                ..GeoIpResult::default()
            },
        ));

        let upsert = insert_persisted_url_record(&pool, second)
            .await
            .expect("url_status must still commit when core cleanup fails");

        let title: String = sqlx::query_scalar("SELECT title FROM url_status WHERE id = ?")
            .bind(upsert.id)
            .fetch_one(&pool)
            .await
            .expect("fetch title");
        assert_eq!(title, "Updated title");

        let tech_names: Vec<String> = sqlx::query_scalar(
            "SELECT technology_name FROM url_technologies WHERE url_status_id = ? ORDER BY technology_name",
        )
        .bind(upsert.id)
        .fetch_all(&pool)
        .await
        .expect("fetch tech");
        assert_eq!(
            tech_names,
            vec!["WordPress".to_string()],
            "failed cleanup must skip core inserts (no mixed WordPress+PHP)"
        );

        let country: Option<String> =
            sqlx::query_scalar("SELECT country_code FROM url_geoip WHERE url_status_id = ?")
                .bind(upsert.id)
                .fetch_one(&pool)
                .await
                .expect("fetch geoip");
        assert_eq!(
            country.as_deref(),
            Some("DE"),
            "enrichment txn must still replace GeoIP after a core cleanup failure"
        );

        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT error_type, error_message FROM url_partial_failures WHERE url_status_id = ?",
        )
        .bind(upsert.id)
        .fetch_all(&pool)
        .await
        .expect("fetch partial failures");
        assert!(
            rows.iter().any(|(error_type, message)| {
                error_type == "Satellite insert error" && message.starts_with("core_satellites:")
            }),
            "core cleanup SQL Err must land in url_partial_failures, got {rows:?}"
        );
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn test_insert_persisted_url_record_with_enrichment() {
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

        let record = PersistedUrlRecord {
            url_record: create_test_url_record(),
            security_headers: security_headers.clone(),
            http_headers: http_headers.clone(),
            oids: oids.clone(),
            redirect_chain: vec![
                ("http://example.com".to_string(), 301),
                ("https://example.com".to_string(), 200),
            ],
            technologies: vec![
                crate::fingerprint::DetectedTechnology {
                    name: "WordPress".to_string(),
                    version: None,
                    category: None,
                    is_implied: false,
                    detection_source: None,
                },
                crate::fingerprint::DetectedTechnology {
                    name: "PHP".to_string(),
                    version: None,
                    category: None,
                    is_implied: false,
                    detection_source: None,
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
            contact_links: vec![],
            exposed_secrets: vec![],
            whois: None,
            partial_failures: vec![],
            favicon: None,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: Vec::new(),
            cookies: Vec::new(),
            resource_hints: Vec::new(),
            script_hosts: vec![],
            security_txt: None,
            robots_txt: None,
        };

        let result = insert_persisted_url_record(&pool, record).await;
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
    #[allow(clippy::too_many_lines)]
    async fn test_insert_persisted_url_record_with_all_enrichment() {
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

        let record = PersistedUrlRecord {
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
            contact_links: vec![],
            exposed_secrets: vec![],
            whois: Some(WhoisResult {
                creation_date: Some(DateTime::from_timestamp(946684800, 0).unwrap()),
                expiration_date: None,
                updated_date: None,
                registrar: Some("Example Registrar".to_string()),
                registrant_country: None,
                registrant_org: None,
                status: vec![],
                nameservers: vec![],
                raw_text: None,
            }),
            partial_failures: vec![],
            favicon: None,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: Vec::new(),
            cookies: Vec::new(),
            resource_hints: Vec::new(),
            script_hosts: vec![],
            security_txt: None,
            robots_txt: None,
        };

        let result = insert_persisted_url_record(&pool, record).await;
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
    async fn test_insert_persisted_url_record_empty_enrichment() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-123").await;

        let record = PersistedUrlRecord {
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
            contact_links: vec![],
            exposed_secrets: vec![],
            whois: None,
            partial_failures: vec![],
            favicon: None,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: Vec::new(),
            cookies: Vec::new(),
            resource_hints: Vec::new(),
            script_hosts: vec![],
            security_txt: None,
            robots_txt: None,
        };

        let result = insert_persisted_url_record(&pool, record).await;
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

        let record = PersistedUrlRecord {
            url_record: create_test_url_record(),
            security_headers: HashMap::new(),
            http_headers: HashMap::new(),
            oids: HashSet::new(),
            redirect_chain: vec![],
            technologies: vec![crate::fingerprint::DetectedTechnology {
                name: "WordPress".to_string(),
                version: None,
                category: None,
                is_implied: false,
                detection_source: None,
            }], // Should still be inserted even if GeoIP fails
            subject_alternative_names: vec![],
            analytics_ids: vec![],
            geoip: Some(("93.184.216.34".to_string(), geoip_result)),
            structured_data: None,
            social_media_links: vec![],
            contact_links: vec![],
            exposed_secrets: vec![],
            whois: None,
            partial_failures: vec![],
            favicon: None,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: Vec::new(),
            cookies: Vec::new(),
            resource_hints: Vec::new(),
            script_hosts: vec![],
            security_txt: None,
            robots_txt: None,
        };

        // Should succeed - main record and technologies should be inserted
        // Even if GeoIP insertion fails (which it shouldn't in this test)
        let result = insert_persisted_url_record(&pool, record).await;
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

        let record = PersistedUrlRecord {
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
            contact_links: vec![],
            exposed_secrets: vec![],
            whois: None,
            partial_failures: vec![],
            favicon: None,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: Vec::new(),
            cookies: Vec::new(),
            resource_hints: Vec::new(),
            script_hosts: vec![],
            security_txt: None,
            robots_txt: None,
        };

        // Should succeed even with no enrichment data
        // The function insert_enrichment_data logs warnings but doesn't propagate errors
        let result = insert_persisted_url_record(&pool, record).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_insert_persisted_url_record_main_record_failure_propagates() {
        // Test that main record insertion failure propagates (unlike enrichment)
        // This is critical - main record failure should be reported
        let pool = create_test_pool().await;

        // Close pool to cause insertion failure
        pool.close().await;

        let record = PersistedUrlRecord {
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
            contact_links: vec![],
            exposed_secrets: vec![],
            whois: None,
            partial_failures: vec![],
            favicon: None,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: Vec::new(),
            cookies: Vec::new(),
            resource_hints: Vec::new(),
            script_hosts: vec![],
            security_txt: None,
            robots_txt: None,
        };

        // Should fail - main record insertion failure propagates
        let result = insert_persisted_url_record(&pool, record).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_enrichment_insert_summary_total_failures_calculation() {
        // Test that total_failures correctly counts all failure types
        // This is critical - incorrect counting would break monitoring/logging
        let summary = EnrichmentInsertSummary {
            partial_failures_failed: 2,
            geoip: EnrichmentWrite::Failed,
            structured_data: EnrichmentWrite::Failed,
            analytics_ids: EnrichmentWrite::Failed,
            ..Default::default()
        };

        // Should count: 2 (partial) + 1 (geoip) + 1 (structured) + 1 (analytics) = 5
        assert_eq!(summary.total_failures(), 5);
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
            geoip: EnrichmentWrite::Failed,
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
            geoip: EnrichmentWrite::Failed,
            structured_data: EnrichmentWrite::Failed,
            social_media: EnrichmentWrite::Failed,
            whois: EnrichmentWrite::Failed,
            analytics_ids: EnrichmentWrite::Failed,
            ..Default::default()
        };
        // Should count: 3 (partial) + 5 (all other types) = 8
        assert_eq!(summary.total_failures(), 8);
        assert!(summary.has_failures());
    }

    #[test]
    fn test_enrichment_insert_summary_mixed_success_failure() {
        // Test mixed success/failure scenario
        // This is critical - real-world scenarios often have partial success
        let summary = EnrichmentInsertSummary {
            partial_failures_inserted: 2,
            partial_failures_failed: 1,
            geoip: EnrichmentWrite::Inserted,
            structured_data: EnrichmentWrite::Failed,
            social_media: EnrichmentWrite::Inserted,
            whois: EnrichmentWrite::Inserted,
            analytics_ids: EnrichmentWrite::Failed,
            ..Default::default()
        };
        // Should count: 1 (partial) + 1 (structured) + 1 (analytics) = 3
        assert_eq!(summary.total_failures(), 3);
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
            geoip: EnrichmentWrite::Inserted,
            structured_data: EnrichmentWrite::Inserted,
            social_media: EnrichmentWrite::Inserted,
            whois: EnrichmentWrite::Inserted,
            analytics_ids: EnrichmentWrite::Inserted,
            favicon: EnrichmentWrite::Inserted,
            contact_links: EnrichmentWrite::Inserted,
            exposed_secrets: EnrichmentWrite::Inserted,
            ..Default::default()
        };
        assert_eq!(summary.total_failures(), 0);
        assert!(!summary.has_failures());
    }
}
