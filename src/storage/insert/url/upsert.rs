//! `url_status` UPSERT plus in-transaction core satellite inserts.

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;
use crate::storage::insert::retry::with_sqlite_retry;
use crate::storage::insert::utils::naive_datetime_to_millis;
use crate::storage::models::UrlRecord;

use super::columns::upsert_url_status_row;
use super::core_satellites::URL_STATUS_CORE_SATELLITE_TABLES;
use super::satellite::{
    insert_caa_records, insert_certificate_sans, insert_cname_records, insert_cookies,
    insert_csp_domains, insert_http_headers, insert_ipv6_addresses, insert_mx_records,
    insert_nameservers, insert_oids, insert_redirect_chain, insert_resource_hints,
    insert_robots_txt, insert_script_hosts, insert_security_headers, insert_security_txt,
    insert_technologies, insert_txt_records,
};

/// Result of upserting into `url_status` (unique on `(run_id, initial_domain)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlUpsertOutcome {
    pub id: i64,
    /// `true` when this call created a new row; `false` when an existing row was updated.
    pub inserted: bool,
    /// In-transaction satellite SQL failures (logged; main row still commits).
    pub satellite_insert_failures: Vec<SatelliteWriteFailure>,
    /// `url_partial_failures` rows inserted in the enrichment transaction (0 until persist).
    pub partial_failures_inserted: usize,
    /// Subset with `error_type` = `Satellite insert error` (0 until persist).
    pub satellite_insert_errors_inserted: usize,
}

/// One failed in-transaction satellite insert (table name + driver message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SatelliteWriteFailure {
    pub table: &'static str,
    pub message: String,
}

/// Parameters for inserting a URL record.
///
/// This struct groups all parameters needed to insert a URL record, reducing
/// function argument count and improving maintainability.
#[derive(Debug)]
pub struct UrlRecordInsertParams<'a> {
    /// Database connection pool
    pub pool: &'a SqlitePool,
    /// The URL record to insert
    pub record: &'a UrlRecord,
    /// Security headers `HashMap` (will be inserted into `url_security_headers` table)
    pub security_headers: &'a std::collections::HashMap<String, String>,
    /// HTTP headers `HashMap` (will be inserted into `url_http_headers` table)
    pub http_headers: &'a std::collections::HashMap<String, String>,
    /// Vector of OID strings (will be inserted into `url_certificate_oids` table)
    pub oids: &'a std::collections::HashSet<String>,
    /// Redirect chain (URL, HTTP status) per hop (will be inserted into `url_redirect_chain` table)
    pub redirect_chain: &'a [(String, u16)],
    /// Vector of detected technologies (will be inserted into `url_technologies` table)
    pub technologies: &'a [crate::fingerprint::DetectedTechnology],
    /// Vector of DNS names from certificate SAN extension (will be inserted into `url_certificate_sans` table)
    pub subject_alternative_names: &'a [String],
    /// CNAME records JSON (will be inserted into `url_cname_records` table)
    pub cname_records: Option<&'a String>,
    /// AAAA (IPv6) records JSON (will be inserted into `url_ipv6_addresses` table)
    pub aaaa_records: Option<&'a String>,
    /// CAA records JSON (will be inserted into `url_caa_records` table)
    pub caa_records: Option<&'a String>,
    /// CSP domains (directive, fqdn, `registrable_domain`)
    pub csp_domains: &'a [(String, String, Option<String>)],
    /// Cookie security info
    pub cookies: &'a [crate::storage::CookieInfo],
    /// Resource hints (`hint_type`, href); `hint_type` includes preconnect, dns-prefetch,
    /// preload, prefetch, and modulepreload
    pub resource_hints: &'a [(String, String)],
    /// Script `src` host inventory
    pub script_hosts: &'a [crate::storage::ScriptHostInfo],
    /// Parsed security.txt (if fetched)
    pub security_txt: Option<&'a crate::fetch::well_known::SecurityTxtData>,
    /// Parsed robots.txt (if fetched)
    pub robots_txt: Option<&'a crate::fetch::well_known::RobotsTxtData>,
}

impl<'a> UrlRecordInsertParams<'a> {
    /// Build params from a complete [`crate::storage::record::PersistedUrlRecord`].
    ///
    /// The production scan pipeline collects everything that goes into a
    /// URL row into a `PersistedUrlRecord`, then calls `insert_url_record`. Mapping
    /// the individual fields manually at the call site (the previous
    /// shape) made every new field a two-place edit — the struct definition
    /// here, plus the manual field assignment in `insert_persisted_url_record`. By
    /// putting the mapping in one place, the call site stays a one-liner
    /// and the struct can grow without churning callers.
    ///
    /// Crate-internal (`pub(crate)`) because `PersistedUrlRecord` is itself a
    /// crate-internal aggregate — exposing this constructor publicly would
    /// pull `PersistedUrlRecord` (and through it, several other crate-private types
    /// like `FaviconData`) into the public API surface.
    #[must_use]
    pub(crate) fn from_persisted_record(
        pool: &'a sqlx::SqlitePool,
        persisted: &'a crate::storage::record::PersistedUrlRecord,
    ) -> Self {
        Self {
            pool,
            record: &persisted.url_record,
            security_headers: &persisted.security_headers,
            http_headers: &persisted.http_headers,
            oids: &persisted.oids,
            redirect_chain: &persisted.redirect_chain,
            technologies: &persisted.technologies,
            subject_alternative_names: &persisted.subject_alternative_names,
            cname_records: persisted.cname_records.as_ref(),
            aaaa_records: persisted.aaaa_records.as_ref(),
            caa_records: persisted.caa_records.as_ref(),
            csp_domains: &persisted.csp_domains,
            cookies: &persisted.cookies,
            resource_hints: &persisted.resource_hints,
            script_hosts: &persisted.script_hosts,
            security_txt: persisted.security_txt.as_ref(),
            robots_txt: persisted.robots_txt.as_ref(),
        }
    }

    /// Insert params with empty satellite collections.
    ///
    /// Prefer this in integration tests that only exercise the main row /
    /// pool / transaction behavior. New satellite fields then default here
    /// (and in the crate-internal `from_persisted_record` constructor) instead of
    /// breaking every `UrlRecordInsertParams { ... }` literal under `tests/`.
    ///
    /// Unit tests that need non-empty satellites should still construct the
    /// struct literally (or start from this and override after copying fields).
    #[must_use]
    #[cfg_attr(not(any(test, feature = "test-utils")), allow(dead_code))]
    pub fn with_empty_satellites(
        pool: &'a SqlitePool,
        record: &'a UrlRecord,
        security_headers: &'a std::collections::HashMap<String, String>,
        http_headers: &'a std::collections::HashMap<String, String>,
        oids: &'a std::collections::HashSet<String>,
    ) -> Self {
        Self {
            pool,
            record,
            security_headers,
            http_headers,
            oids,
            redirect_chain: &[],
            technologies: &[],
            subject_alternative_names: &[],
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        }
    }
}

/// Inserts a `UrlRecord` into the database with retry logic for transient errors.
///
/// This function inserts data into:
/// 1. The main `url_status` table (fact table)
/// 2. In-transaction satellite tables listed in `URL_STATUS_CORE_SATELLITE_TABLES`
///    (DNS, headers, TLS OIDs/SANs, redirects, CSP, cookies, resource hints,
///    script hosts, etc.)
///
/// The main `url_status` row and those in-transaction satellites share one transaction;
/// individual satellite insert failures are logged and do not roll back the main row.
/// `SQLITE_BUSY` and `SQLITE_LOCKED` errors are retried with exponential backoff.
///
/// Multi-valued fields are stored in normalized child tables (not as JSON on `url_status`).
/// Enrichment satellites (`GeoIP`, WHOIS, secrets, …) are written after this transaction.
///
/// # Arguments
///
/// * `params` - Parameters for URL record insertion
///
/// # Returns
///
/// Returns the `id` of the inserted (or updated) `url_status` record, or an error if insertion fails.
///
/// # Errors
/// Returns `Err` when the transaction or any insert fails.
#[cfg_attr(not(any(test, feature = "test-utils")), allow(dead_code))]
pub async fn insert_url_record(params: UrlRecordInsertParams<'_>) -> Result<i64, DatabaseError> {
    insert_url_record_with_outcome(params)
        .await
        .map(|outcome| outcome.id)
}

/// Like [`insert_url_record`] but reports whether the row was newly inserted or updated.
pub async fn insert_url_record_with_outcome(
    params: UrlRecordInsertParams<'_>,
) -> Result<UrlUpsertOutcome, DatabaseError> {
    with_sqlite_retry(|| insert_url_record_impl(&params)).await
}

/// Internal implementation of `insert_url_record` (without retry logic).
#[allow(clippy::too_many_lines)] // Main record + ~17 in-txn satellite inserts
#[allow(clippy::cognitive_complexity)] // Each satellite table has distinct insert logic
async fn insert_url_record_impl(
    params: &UrlRecordInsertParams<'_>,
) -> Result<UrlUpsertOutcome, DatabaseError> {
    let valid_from_millis = naive_datetime_to_millis(params.record.ssl_cert_valid_from.as_ref());
    let valid_to_millis = naive_datetime_to_millis(params.record.ssl_cert_valid_to.as_ref());

    log::debug!(
        "Inserting UrlRecord: initial_domain={}",
        params.record.initial_domain
    );

    // Start transaction for atomic dual-write
    let mut tx = params.pool.begin().await.map_err(DatabaseError::SqlError)?;

    let (url_status_id, inserted) =
        upsert_url_status_row(&mut tx, params.record, valid_from_millis, valid_to_millis).await?;

    // Insert into core satellite tables (see URL_STATUS_CORE_SATELLITE_TABLES).
    //
    // DESIGN DECISION: Core satellite SQL failures do not roll back `url_status`
    // (see ADR 0007). Partial child data is better than losing the observation.
    // Failures are collected and persisted as `url_partial_failures` in the
    // enrichment writer transaction (`error_type` = Satellite insert error).
    //
    // This differs from failure record satellite inserts (insert_url_failure_impl) which
    // propagate errors because failure records require atomicity - either all related data
    // is saved together, or none of it is (transaction rollback).
    //
    // If any satellite insert panics, the transaction will be rolled back by Drop.
    //
    // Clean up stale *core* satellite data before inserting fresh rows. Enrichment
    // children are replaced in the enrichment writer transaction so a successful
    // fact row never blanks GeoIP/WHOIS/secrets for concurrent readers.
    let mut satellite_insert_failures = Vec::new();
    if let Err(e) = crate::storage::insert::utils::delete_child_rows(
        &mut tx,
        URL_STATUS_CORE_SATELLITE_TABLES,
        url_status_id,
    )
    .await
    {
        log::warn!(
            "Failed to clean stale core satellite rows for url_status_id {url_status_id}: {e}"
        );
    }

    record_satellite_write(
        "url_technologies",
        url_status_id,
        &mut satellite_insert_failures,
        insert_technologies(&mut tx, url_status_id, params.technologies).await,
    );
    record_satellite_write(
        "url_nameservers",
        url_status_id,
        &mut satellite_insert_failures,
        insert_nameservers(&mut tx, url_status_id, params.record.nameservers.as_ref()).await,
    );
    record_satellite_write(
        "url_txt_records",
        url_status_id,
        &mut satellite_insert_failures,
        insert_txt_records(&mut tx, url_status_id, params.record.txt_records.as_ref()).await,
    );
    record_satellite_write(
        "url_mx_records",
        url_status_id,
        &mut satellite_insert_failures,
        insert_mx_records(&mut tx, url_status_id, params.record.mx_records.as_ref()).await,
    );
    record_satellite_write(
        "url_security_headers",
        url_status_id,
        &mut satellite_insert_failures,
        insert_security_headers(&mut tx, url_status_id, params.security_headers).await,
    );
    record_satellite_write(
        "url_http_headers",
        url_status_id,
        &mut satellite_insert_failures,
        insert_http_headers(&mut tx, url_status_id, params.http_headers).await,
    );
    record_satellite_write(
        "url_certificate_oids",
        url_status_id,
        &mut satellite_insert_failures,
        insert_oids(&mut tx, url_status_id, params.oids).await,
    );
    record_satellite_write(
        "url_redirect_chain",
        url_status_id,
        &mut satellite_insert_failures,
        insert_redirect_chain(&mut tx, url_status_id, params.redirect_chain).await,
    );
    record_satellite_write(
        "url_certificate_sans",
        url_status_id,
        &mut satellite_insert_failures,
        insert_certificate_sans(&mut tx, url_status_id, params.subject_alternative_names).await,
    );
    record_satellite_write(
        "url_cname_records",
        url_status_id,
        &mut satellite_insert_failures,
        insert_cname_records(&mut tx, url_status_id, params.cname_records).await,
    );
    record_satellite_write(
        "url_ipv6_addresses",
        url_status_id,
        &mut satellite_insert_failures,
        insert_ipv6_addresses(&mut tx, url_status_id, params.aaaa_records).await,
    );
    record_satellite_write(
        "url_caa_records",
        url_status_id,
        &mut satellite_insert_failures,
        insert_caa_records(&mut tx, url_status_id, params.caa_records).await,
    );
    record_satellite_write(
        "url_csp_domains",
        url_status_id,
        &mut satellite_insert_failures,
        insert_csp_domains(&mut tx, url_status_id, params.csp_domains).await,
    );
    record_satellite_write(
        "url_cookies",
        url_status_id,
        &mut satellite_insert_failures,
        insert_cookies(&mut tx, url_status_id, params.cookies).await,
    );
    record_satellite_write(
        "url_resource_hints",
        url_status_id,
        &mut satellite_insert_failures,
        insert_resource_hints(&mut tx, url_status_id, params.resource_hints).await,
    );
    record_satellite_write(
        "url_script_hosts",
        url_status_id,
        &mut satellite_insert_failures,
        insert_script_hosts(&mut tx, url_status_id, params.script_hosts).await,
    );
    record_satellite_write(
        "url_security_txt",
        url_status_id,
        &mut satellite_insert_failures,
        insert_security_txt(&mut tx, url_status_id, params.security_txt).await,
    );
    record_satellite_write(
        "url_robots_txt",
        url_status_id,
        &mut satellite_insert_failures,
        insert_robots_txt(&mut tx, url_status_id, params.robots_txt).await,
    );

    // Commit transaction - all inserts succeeded
    // If any satellite insert had failed internally, it would have been logged but not propagated.
    // The transaction will be rolled back by Drop if commit fails.
    tx.commit().await.map_err(|e| {
        log::error!(
            "Failed to commit transaction for url_status_id {} (domain: {}): {}",
            url_status_id,
            params.record.initial_domain,
            e
        );
        DatabaseError::SqlError(e)
    })?;

    Ok(UrlUpsertOutcome {
        id: url_status_id,
        inserted,
        satellite_insert_failures,
        partial_failures_inserted: 0,
        satellite_insert_errors_inserted: 0,
    })
}

fn record_satellite_write(
    table: &'static str,
    url_status_id: i64,
    failures: &mut Vec<SatelliteWriteFailure>,
    result: Result<(), sqlx::Error>,
) {
    if let Err(e) = result {
        log::warn!("Failed to insert {table} for url_status_id {url_status_id}: {e}");
        failures.push(SatelliteWriteFailure {
            table,
            message: e.to_string(),
        });
    }
}
