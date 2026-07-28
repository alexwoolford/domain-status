//! Main URL record insertion.
//!
//! This module handles inserting URL status records and related satellite tables.
//! In-transaction satellites and the UPSERT cleanup list live in
//! `URL_STATUS_SATELLITE_TABLES`; enrichment satellites (`GeoIP`, WHOIS, secrets, etc.)
//! are inserted after that transaction commits.

mod satellite;

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;

use super::super::models::UrlRecord;
use super::retry::with_sqlite_retry;
use super::utils::naive_datetime_to_millis;

use satellite::{
    insert_caa_records, insert_certificate_sans, insert_cname_records, insert_http_headers,
    insert_ipv6_addresses, insert_mx_records, insert_nameservers, insert_oids,
    insert_redirect_chain, insert_security_headers, insert_technologies, insert_txt_records,
};

/// One `url_status` column paired with its bind extractor.
///
/// SQL column order and `.bind(...)` values are derived from the same table so
/// adding/removing/reordering a column is a single edit — a previous dual list
/// (column names + a parallel bind chain) could silently mis-assign values.
pub(crate) struct UrlStatusColumn {
    pub name: &'static str,
    pub extract: for<'a> fn(&'a UrlRecord, Option<i64>, Option<i64>) -> UrlStatusBind<'a>,
}

/// Bindable value for one `url_status` placeholder.
pub(crate) enum UrlStatusBind<'a> {
    Text(&'a str),
    OptText(Option<&'a str>),
    U16(u16),
    U32(u32),
    I64(i64),
    OptI64(Option<i64>),
    F64(f64),
    Bool(bool),
    OptBool(Option<bool>),
}

/// `url_status` INSERT / UPSERT columns + binds (canonical column/bind registry).
///
/// `final_domain` is part of the conflict key and is omitted from the UPDATE SET
/// clause; every other column is refreshed on conflict.
#[allow(clippy::too_many_lines)] // One entry per url_status column; intentional registry
pub(crate) const URL_STATUS_COLUMN_DEFS: &[UrlStatusColumn] = &[
    UrlStatusColumn {
        name: "initial_domain",
        extract: |r, _, _| UrlStatusBind::Text(r.initial_domain.as_str()),
    },
    UrlStatusColumn {
        name: "final_domain",
        extract: |r, _, _| UrlStatusBind::Text(r.final_domain.as_str()),
    },
    UrlStatusColumn {
        name: "initial_url",
        extract: |r, _, _| UrlStatusBind::OptText(r.initial_url.as_deref()),
    },
    UrlStatusColumn {
        name: "final_url",
        extract: |r, _, _| UrlStatusBind::OptText(r.final_url.as_deref()),
    },
    UrlStatusColumn {
        name: "ip_address",
        extract: |r, _, _| UrlStatusBind::Text(r.ip_address.as_str()),
    },
    UrlStatusColumn {
        name: "reverse_dns_name",
        extract: |r, _, _| UrlStatusBind::OptText(r.reverse_dns_name.as_deref()),
    },
    UrlStatusColumn {
        name: "http_status",
        extract: |r, _, _| UrlStatusBind::U16(r.status),
    },
    UrlStatusColumn {
        name: "http_status_text",
        extract: |r, _, _| UrlStatusBind::Text(r.status_desc.as_str()),
    },
    UrlStatusColumn {
        name: "response_time_seconds",
        extract: |r, _, _| UrlStatusBind::F64(r.response_time),
    },
    UrlStatusColumn {
        name: "title",
        extract: |r, _, _| UrlStatusBind::Text(r.title.as_str()),
    },
    UrlStatusColumn {
        name: "keywords",
        extract: |r, _, _| UrlStatusBind::OptText(r.keywords.as_deref()),
    },
    UrlStatusColumn {
        name: "description",
        extract: |r, _, _| UrlStatusBind::OptText(r.description.as_deref()),
    },
    UrlStatusColumn {
        name: "meta_robots",
        extract: |r, _, _| UrlStatusBind::OptText(r.meta_robots.as_deref()),
    },
    UrlStatusColumn {
        name: "tls_version",
        extract: |r, _, _| {
            UrlStatusBind::OptText(
                r.tls_version
                    .as_ref()
                    .map(crate::models::TlsVersion::as_str),
            )
        },
    },
    UrlStatusColumn {
        name: "ssl_cert_subject",
        extract: |r, _, _| UrlStatusBind::OptText(r.ssl_cert_subject.as_deref()),
    },
    UrlStatusColumn {
        name: "ssl_cert_issuer",
        extract: |r, _, _| UrlStatusBind::OptText(r.ssl_cert_issuer.as_deref()),
    },
    UrlStatusColumn {
        name: "ssl_cert_valid_from_ms",
        extract: |_, valid_from_ms, _| UrlStatusBind::OptI64(valid_from_ms),
    },
    UrlStatusColumn {
        name: "ssl_cert_valid_to_ms",
        extract: |_, _, valid_to_ms| UrlStatusBind::OptI64(valid_to_ms),
    },
    UrlStatusColumn {
        name: "is_mobile_friendly",
        extract: |r, _, _| UrlStatusBind::Bool(r.is_mobile_friendly),
    },
    UrlStatusColumn {
        name: "observed_at_ms",
        extract: |r, _, _| UrlStatusBind::I64(r.timestamp),
    },
    UrlStatusColumn {
        name: "spf_record",
        extract: |r, _, _| UrlStatusBind::OptText(r.spf_record.as_deref()),
    },
    UrlStatusColumn {
        name: "dmarc_record",
        extract: |r, _, _| UrlStatusBind::OptText(r.dmarc_record.as_deref()),
    },
    UrlStatusColumn {
        name: "cipher_suite",
        extract: |r, _, _| UrlStatusBind::OptText(r.cipher_suite.as_deref()),
    },
    UrlStatusColumn {
        name: "key_algorithm",
        extract: |r, _, _| {
            UrlStatusBind::OptText(
                r.key_algorithm
                    .as_ref()
                    .map(crate::models::KeyAlgorithm::as_str),
            )
        },
    },
    UrlStatusColumn {
        name: "run_id",
        extract: |r, _, _| UrlStatusBind::OptText(r.run_id.as_deref()),
    },
    UrlStatusColumn {
        name: "body_sha256",
        extract: |r, _, _| UrlStatusBind::OptText(r.body_sha256.as_deref()),
    },
    UrlStatusColumn {
        name: "body_truncated",
        extract: |r, _, _| UrlStatusBind::Bool(r.body_truncated),
    },
    UrlStatusColumn {
        name: "external_scripts_eligible",
        extract: |r, _, _| UrlStatusBind::U32(r.external_scripts_eligible),
    },
    UrlStatusColumn {
        name: "external_scripts_scanned",
        extract: |r, _, _| UrlStatusBind::U32(r.external_scripts_scanned),
    },
    UrlStatusColumn {
        name: "content_length",
        extract: |r, _, _| UrlStatusBind::OptI64(r.content_length),
    },
    UrlStatusColumn {
        name: "http_version",
        extract: |r, _, _| UrlStatusBind::OptText(r.http_version.as_deref()),
    },
    UrlStatusColumn {
        name: "body_word_count",
        extract: |r, _, _| UrlStatusBind::OptI64(r.body_word_count),
    },
    UrlStatusColumn {
        name: "body_line_count",
        extract: |r, _, _| UrlStatusBind::OptI64(r.body_line_count),
    },
    UrlStatusColumn {
        name: "content_type",
        extract: |r, _, _| UrlStatusBind::OptText(r.content_type.as_deref()),
    },
    UrlStatusColumn {
        name: "canonical_url",
        extract: |r, _, _| UrlStatusBind::OptText(r.canonical_url.as_deref()),
    },
    UrlStatusColumn {
        name: "cert_fingerprint_sha256",
        extract: |r, _, _| UrlStatusBind::OptText(r.cert_fingerprint_sha256.as_deref()),
    },
    UrlStatusColumn {
        name: "cert_serial_number",
        extract: |r, _, _| UrlStatusBind::OptText(r.cert_serial_number.as_deref()),
    },
    UrlStatusColumn {
        name: "cert_is_self_signed",
        extract: |r, _, _| UrlStatusBind::OptBool(r.cert_is_self_signed),
    },
    UrlStatusColumn {
        name: "cert_is_wildcard",
        extract: |r, _, _| UrlStatusBind::OptBool(r.cert_is_wildcard),
    },
    UrlStatusColumn {
        name: "cert_is_mismatched",
        extract: |r, _, _| UrlStatusBind::OptBool(r.cert_is_mismatched),
    },
    UrlStatusColumn {
        name: "meta_refresh_url",
        extract: |r, _, _| UrlStatusBind::OptText(r.meta_refresh_url.as_deref()),
    },
];

/// Column names derived from [`URL_STATUS_COLUMN_DEFS`] (same order as binds).
///
/// `pub(crate)` so export/field-inventory tests can assert capture ↔ schema sync
/// without duplicating this list.
pub(crate) fn url_status_column_names() -> impl Iterator<Item = &'static str> {
    URL_STATUS_COLUMN_DEFS.iter().map(|c| c.name)
}

fn url_status_upsert_sql() -> String {
    let columns = url_status_column_names().collect::<Vec<_>>().join(", ");
    let placeholders = std::iter::repeat_n("?", URL_STATUS_COLUMN_DEFS.len())
        .collect::<Vec<_>>()
        .join(", ");
    let updates = url_status_column_names()
        .filter(|&col| col != "final_domain")
        .map(|col| format!("{col}=excluded.{col}"))
        .collect::<Vec<_>>()
        .join(",\n            ");
    format!(
        "INSERT INTO url_status (
            {columns}
        ) VALUES ({placeholders})
        ON CONFLICT(run_id, final_domain) DO UPDATE SET
            {updates}
        RETURNING id"
    )
}

fn bind_url_status_query<'q>(
    query: sqlx::query::QueryScalar<'q, sqlx::Sqlite, i64, sqlx::sqlite::SqliteArguments<'q>>,
    record: &'q UrlRecord,
    valid_from_millis: Option<i64>,
    valid_to_millis: Option<i64>,
) -> sqlx::query::QueryScalar<'q, sqlx::Sqlite, i64, sqlx::sqlite::SqliteArguments<'q>> {
    let mut q = query;
    for col in URL_STATUS_COLUMN_DEFS {
        q = match (col.extract)(record, valid_from_millis, valid_to_millis) {
            UrlStatusBind::Text(v) => q.bind(v),
            UrlStatusBind::OptText(v) => q.bind(v),
            UrlStatusBind::U16(v) => q.bind(v),
            UrlStatusBind::U32(v) => q.bind(v),
            UrlStatusBind::I64(v) => q.bind(v),
            UrlStatusBind::OptI64(v) => q.bind(v),
            UrlStatusBind::F64(v) => q.bind(v),
            UrlStatusBind::Bool(v) => q.bind(v),
            UrlStatusBind::OptBool(v) => q.bind(v),
        };
    }
    q
}

/// Satellite and enrichment tables hanging off `url_status.id`.
///
/// Cleaned before re-insert on UPSERT so rescans do not leave stale child rows.
/// Shared by production cleanup and upsert-clear tests — do not mirror this list.
pub(crate) const URL_STATUS_SATELLITE_TABLES: &[&str] = &[
    // Core satellites (inserted inside the url_status transaction)
    "url_technologies",
    "url_nameservers",
    "url_txt_records",
    "url_mx_records",
    "url_security_headers",
    "url_http_headers",
    "url_certificate_oids",
    "url_redirect_chain",
    "url_certificate_sans",
    "url_cname_records",
    "url_ipv6_addresses",
    "url_caa_records",
    "url_csp_domains",
    "url_cookies",
    "url_resource_hints",
    "url_body_domains",
    "url_script_hosts",
    // Enrichment tables (inserted after that transaction, but cleaned here)
    "url_analytics_ids",
    "url_structured_data",
    "url_social_media_links",
    "url_security_warnings",
    "url_contact_links",
    "url_exposed_secrets",
    "url_partial_failures",
    "url_favicons",
    "url_geoip",
    "url_whois",
];

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
    /// Body domains (fqdn, `registrable_domain`)
    pub body_domains: &'a [(String, Option<String>)],
    /// Script `src` host inventory
    pub script_hosts: &'a [crate::storage::ScriptHostInfo],
}

impl<'a> UrlRecordInsertParams<'a> {
    /// Build params from a complete [`crate::storage::record::BatchRecord`].
    ///
    /// The production scan pipeline collects everything that goes into a
    /// URL row into a `BatchRecord`, then calls `insert_url_record`. Mapping
    /// the individual fields manually at the call site (the previous
    /// shape) made every new field a two-place edit — the struct definition
    /// here, plus the manual field assignment in `insert_batch_record`. By
    /// putting the mapping in one place, the call site stays a one-liner
    /// and the struct can grow without churning callers.
    ///
    /// Crate-internal (`pub(crate)`) because `BatchRecord` is itself a
    /// crate-internal aggregate — exposing this constructor publicly would
    /// pull `BatchRecord` (and through it, several other crate-private types
    /// like `FaviconData`) into the public API surface.
    #[must_use]
    pub(crate) fn from_batch(
        pool: &'a sqlx::SqlitePool,
        batch: &'a crate::storage::record::BatchRecord,
    ) -> Self {
        Self {
            pool,
            record: &batch.url_record,
            security_headers: &batch.security_headers,
            http_headers: &batch.http_headers,
            oids: &batch.oids,
            redirect_chain: &batch.redirect_chain,
            technologies: &batch.technologies,
            subject_alternative_names: &batch.subject_alternative_names,
            cname_records: batch.cname_records.as_ref(),
            aaaa_records: batch.aaaa_records.as_ref(),
            caa_records: batch.caa_records.as_ref(),
            csp_domains: &batch.csp_domains,
            cookies: &batch.cookies,
            resource_hints: &batch.resource_hints,
            body_domains: &batch.body_domains,
            script_hosts: &batch.script_hosts,
        }
    }

    /// Insert params with empty satellite collections.
    ///
    /// Prefer this in integration tests that only exercise the main row /
    /// pool / transaction behavior. New satellite fields then default here
    /// (and in the crate-internal `from_batch` constructor) instead of
    /// breaking every `UrlRecordInsertParams { ... }` literal under `tests/`.
    ///
    /// Unit tests that need non-empty satellites should still construct the
    /// struct literally (or start from this and override after copying fields).
    #[must_use]
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
            body_domains: &[],
            script_hosts: &[],
        }
    }
}

/// Inserts a `UrlRecord` into the database with retry logic for transient errors.
///
/// This function inserts data into:
/// 1. The main `url_status` table (fact table)
/// 2. In-transaction satellite tables listed under the core section of
///    `URL_STATUS_SATELLITE_TABLES` (DNS, headers, TLS OIDs/SANs, redirects, CSP,
///    cookies, resource hints, script hosts, etc.)
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
#[allow(clippy::too_many_lines)] // Thin wrapper; length comes from insert_url_record_impl
pub async fn insert_url_record(params: UrlRecordInsertParams<'_>) -> Result<i64, DatabaseError> {
    with_sqlite_retry(|| insert_url_record_impl(&params)).await
}

/// Internal implementation of `insert_url_record` (without retry logic).
#[allow(clippy::too_many_lines)] // Main record + ~17 in-txn satellite inserts
#[allow(clippy::cognitive_complexity)] // Each satellite table has distinct insert logic
async fn insert_url_record_impl(params: &UrlRecordInsertParams<'_>) -> Result<i64, DatabaseError> {
    let valid_from_millis = naive_datetime_to_millis(params.record.ssl_cert_valid_from.as_ref());
    let valid_to_millis = naive_datetime_to_millis(params.record.ssl_cert_valid_to.as_ref());

    log::debug!(
        "Inserting UrlRecord: initial_domain={}",
        params.record.initial_domain
    );

    // Start transaction for atomic dual-write
    let mut tx = params.pool.begin().await.map_err(DatabaseError::SqlError)?;

    // 1. Insert into main url_status table
    // Use RETURNING clause to get the ID in a single query (SQLite 3.35.0+)
    // This eliminates the need for a separate SELECT query and improves performance
    let upsert_sql = url_status_upsert_sql();
    let url_status_id_result = bind_url_status_query(
        sqlx::query_scalar::<_, i64>(&upsert_sql),
        params.record,
        valid_from_millis,
        valid_to_millis,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        log::error!(
            "Failed to insert UrlRecord for domain {} (final_domain: {}, status: {}, timestamp: {}): {} (SQL: INSERT INTO url_status ... ON CONFLICT)",
            params.record.initial_domain,
            params.record.final_domain,
            params.record.status,
            params.record.timestamp,
            e
        );
        DatabaseError::SqlError(e)
    });

    let url_status_id = match url_status_id_result {
        Ok(id) => id,
        Err(e) => {
            // Main insert failed - explicitly rollback transaction
            // Note: We ignore rollback errors since the transaction will be rolled back
            // by Drop anyway, but being explicit makes the intent clear
            if let Err(rollback_err) = tx.rollback().await {
                log::warn!(
                    "Failed to rollback transaction after main insert error (this is non-fatal): {rollback_err}"
                );
            }
            return Err(e);
        }
    };

    // Insert into satellite tables (see URL_STATUS_SATELLITE_TABLES for the full set).
    //
    // DESIGN DECISION: Satellite insert functions return () and handle errors internally.
    // This design prioritizes partial success over atomicity:
    // - If a satellite insert fails (e.g., technologies), the main URL record is still saved
    // - Partial data is better than no data at all
    // - Failures are logged for monitoring but don't block the main record insertion
    //
    // This differs from failure record satellite inserts (insert_url_failure_impl) which
    // propagate errors because failure records require atomicity - either all related data
    // is saved together, or none of it is (transaction rollback).
    //
    // If any satellite insert panics, the transaction will be rolled back by Drop.
    //
    // Clean up stale satellite data before inserting fresh rows. This handles the UPSERT
    // case where the same (run_id, final_domain) is scanned twice: the main url_status row
    // is updated, but old satellite rows (e.g., redirect hops from a previous scan) would
    // remain orphaned without this cleanup.
    for table in URL_STATUS_SATELLITE_TABLES {
        let sql = format!("DELETE FROM {table} WHERE url_status_id = ?");
        if let Err(e) = sqlx::query(&sql)
            .bind(url_status_id)
            .execute(&mut *tx)
            .await
        {
            log::warn!(
                "Failed to clean stale rows from {table} for url_status_id {url_status_id}: {e}"
            );
        }
    }

    insert_technologies(&mut tx, url_status_id, params.technologies).await;
    insert_nameservers(&mut tx, url_status_id, params.record.nameservers.as_ref()).await;
    insert_txt_records(&mut tx, url_status_id, params.record.txt_records.as_ref()).await;
    insert_mx_records(&mut tx, url_status_id, params.record.mx_records.as_ref()).await;
    insert_security_headers(&mut tx, url_status_id, params.security_headers).await;
    insert_http_headers(&mut tx, url_status_id, params.http_headers).await;
    insert_oids(&mut tx, url_status_id, params.oids).await;
    insert_redirect_chain(&mut tx, url_status_id, params.redirect_chain).await;
    insert_certificate_sans(&mut tx, url_status_id, params.subject_alternative_names).await;
    insert_cname_records(&mut tx, url_status_id, params.cname_records).await;
    insert_ipv6_addresses(&mut tx, url_status_id, params.aaaa_records).await;
    insert_caa_records(&mut tx, url_status_id, params.caa_records).await;
    insert_csp_domains(&mut tx, url_status_id, params.csp_domains).await;
    insert_cookies(&mut tx, url_status_id, params.cookies).await;
    insert_resource_hints(&mut tx, url_status_id, params.resource_hints).await;
    insert_body_domains(&mut tx, url_status_id, params.body_domains).await;
    insert_script_hosts(&mut tx, url_status_id, params.script_hosts).await;

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

    Ok(url_status_id)
}

/// Inserts CSP domains into `url_csp_domains` table.
async fn insert_csp_domains(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    url_status_id: i64,
    domains: &[(String, String, Option<String>)],
) {
    if domains.is_empty() {
        return;
    }
    let query = super::utils::build_batch_insert_query(
        "url_csp_domains",
        &["url_status_id", "directive", "fqdn", "registrable_domain"],
        domains.len(),
        Some("ON CONFLICT(url_status_id, directive, fqdn) DO NOTHING"),
    );
    let mut qb = sqlx::query(&query);
    for (directive, fqdn, reg_domain) in domains {
        qb = qb
            .bind(url_status_id)
            .bind(directive)
            .bind(fqdn)
            .bind(reg_domain);
    }
    if let Err(e) = qb.execute(&mut **tx).await {
        log::warn!("Failed to insert CSP domains for {url_status_id}: {e}");
    }
}

/// Inserts cookie security info into `url_cookies` table.
async fn insert_cookies(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    url_status_id: i64,
    cookies: &[crate::storage::CookieInfo],
) {
    if cookies.is_empty() {
        return;
    }
    let query = super::utils::build_batch_insert_query(
        "url_cookies",
        &[
            "url_status_id",
            "cookie_name",
            "secure",
            "http_only",
            "same_site",
            "domain",
            "path",
        ],
        cookies.len(),
        Some("ON CONFLICT(url_status_id, cookie_name) DO UPDATE SET secure=excluded.secure, http_only=excluded.http_only, same_site=excluded.same_site"),
    );
    let mut qb = sqlx::query(&query);
    for c in cookies {
        qb = qb
            .bind(url_status_id)
            .bind(&c.name)
            .bind(c.secure)
            .bind(c.http_only)
            .bind(&c.same_site)
            .bind(&c.domain)
            .bind(&c.path);
    }
    if let Err(e) = qb.execute(&mut **tx).await {
        log::warn!("Failed to insert cookies for {url_status_id}: {e}");
    }
}

/// Inserts script `src` host inventory into `url_script_hosts`.
async fn insert_script_hosts(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    url_status_id: i64,
    hosts: &[crate::storage::ScriptHostInfo],
) {
    if hosts.is_empty() {
        return;
    }
    let query = super::utils::build_batch_insert_query(
        "url_script_hosts",
        &[
            "url_status_id",
            "host",
            "registrable_domain",
            "is_first_party",
        ],
        hosts.len(),
        Some(
            "ON CONFLICT(url_status_id, host) DO UPDATE SET \
             registrable_domain=excluded.registrable_domain, \
             is_first_party=excluded.is_first_party",
        ),
    );
    let mut qb = sqlx::query(&query);
    for h in hosts {
        qb = qb
            .bind(url_status_id)
            .bind(&h.host)
            .bind(&h.registrable_domain)
            .bind(h.is_first_party);
    }
    if let Err(e) = qb.execute(&mut **tx).await {
        log::warn!("Failed to insert script hosts for {url_status_id}: {e}");
    }
}

/// Inserts resource hints into `url_resource_hints` table. `hint_type` may be
/// preconnect, dns-prefetch, preload, prefetch, or modulepreload.
async fn insert_resource_hints(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    url_status_id: i64,
    hints: &[(String, String)],
) {
    if hints.is_empty() {
        return;
    }
    let query = super::utils::build_batch_insert_query(
        "url_resource_hints",
        &["url_status_id", "hint_type", "href"],
        hints.len(),
        Some("ON CONFLICT(url_status_id, hint_type, href) DO NOTHING"),
    );
    let mut qb = sqlx::query(&query);
    for (hint_type, href) in hints {
        qb = qb
            .bind(url_status_id)
            .bind(hint_type.to_ascii_lowercase())
            .bind(href);
    }
    if let Err(e) = qb.execute(&mut **tx).await {
        log::warn!("Failed to insert resource hints for {url_status_id}: {e}");
    }
}

/// Inserts body domains into `url_body_domains` table.
async fn insert_body_domains(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    url_status_id: i64,
    domains: &[(String, Option<String>)],
) {
    if domains.is_empty() {
        return;
    }
    let query = super::utils::build_batch_insert_query(
        "url_body_domains",
        &["url_status_id", "fqdn", "registrable_domain"],
        domains.len(),
        Some("ON CONFLICT(url_status_id, fqdn) DO NOTHING"),
    );
    let mut qb = sqlx::query(&query);
    for (fqdn, reg_domain) in domains {
        qb = qb.bind(url_status_id).bind(fqdn).bind(reg_domain);
    }
    if let Err(e) = qb.execute(&mut **tx).await {
        log::warn!("Failed to insert body domains for {url_status_id}: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use sqlx::Row;
    use std::collections::{HashMap, HashSet};

    use crate::storage::migrations::run_migrations;

    #[test]
    fn url_status_column_defs_are_unique_and_ordered_with_names_iter() {
        let names: Vec<_> = url_status_column_names().collect();
        assert_eq!(names.len(), URL_STATUS_COLUMN_DEFS.len());
        let mut seen = HashSet::new();
        for (i, name) in names.iter().enumerate() {
            assert_eq!(*name, URL_STATUS_COLUMN_DEFS[i].name);
            assert!(seen.insert(*name), "duplicate url_status column: {name}");
        }
        assert_eq!(names.len(), 41, "url_status column count drifted");
    }

    /// Creates an in-memory `SQLite` database pool for testing
    async fn create_test_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");
        pool
    }

    /// Creates a test run record for FK constraint
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

    /// Creates a minimal `UrlRecord` for testing
    fn create_test_url_record() -> UrlRecord {
        let mut record = UrlRecord::test_default();
        record.reverse_dns_name = Some("example.com".to_string());
        record.response_time = 0.123;
        record.title = "Example Domain".to_string();
        record.keywords = Some("example, test".to_string());
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
        record.is_mobile_friendly = true;
        record.timestamp = 1_704_067_200_000; // 2024-01-01 00:00:00 UTC in milliseconds
        record.nameservers = Some(r#"["ns1.example.com", "ns2.example.com"]"#.to_string());
        record.txt_records = Some(r#"["v=spf1 include:_spf.example.com ~all"]"#.to_string());
        record.mx_records =
            Some(r#"[{"priority": 10, "hostname": "mail.example.com"}]"#.to_string());
        record.spf_record = Some("v=spf1 include:_spf.example.com ~all".to_string());
        record.dmarc_record = Some("v=DMARC1; p=none".to_string());
        record.cipher_suite = Some("TLS_AES_256_GCM_SHA384".to_string());
        record.key_algorithm = Some(crate::models::KeyAlgorithm::ECDSA);
        record.run_id = Some("test-run-1".to_string());
        record
    }

    #[tokio::test]
    async fn test_insert_url_record_basic() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let record = create_test_url_record();
        let security_headers = HashMap::new();
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = Vec::new();
        let technologies = Vec::new();
        let sans = Vec::new();

        let result = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            body_domains: &[],
            script_hosts: &[],
        })
        .await;

        assert!(result.is_ok());
        let url_status_id = result.unwrap();
        assert!(url_status_id > 0);

        // Verify the record was inserted
        let row = sqlx::query(
            "SELECT initial_domain, final_domain, http_status, title FROM url_status WHERE id = ?",
        )
        .bind(url_status_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch inserted record");

        assert_eq!(row.get::<String, _>("initial_domain"), "example.com");
        assert_eq!(row.get::<String, _>("final_domain"), "example.com");
        assert_eq!(row.get::<i64, _>("http_status"), 200);
        assert_eq!(row.get::<String, _>("title"), "Example Domain");
    }

    #[tokio::test]
    async fn test_insert_high_value_capture_fields() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let mut record = create_test_url_record();
        record.initial_url = Some("http://example.com/start".to_string());
        record.final_url = Some("https://example.com/land?x=1".to_string());
        record.meta_robots = Some("noindex".to_string());

        let script_hosts = vec![crate::storage::ScriptHostInfo {
            host: "cdn.example.com".to_string(),
            registrable_domain: Some("example.com".to_string()),
            is_first_party: true,
        }];

        let id = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &HashMap::new(),
            http_headers: &HashMap::new(),
            oids: &HashSet::new(),
            redirect_chain: &[],
            technologies: &[],
            subject_alternative_names: &[],
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            body_domains: &[],
            script_hosts: &script_hosts,
        })
        .await
        .expect("insert");

        let row =
            sqlx::query("SELECT initial_url, final_url, meta_robots FROM url_status WHERE id = ?")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("fetch");
        assert_eq!(
            row.get::<Option<String>, _>("initial_url").as_deref(),
            Some("http://example.com/start")
        );
        assert_eq!(
            row.get::<Option<String>, _>("final_url").as_deref(),
            Some("https://example.com/land?x=1")
        );
        assert_eq!(
            row.get::<Option<String>, _>("meta_robots").as_deref(),
            Some("noindex")
        );

        let host_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_script_hosts WHERE url_status_id = ?")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(host_count, 1);
    }

    #[tokio::test]
    async fn test_insert_url_record_scan_completeness_columns() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let mut record = create_test_url_record();
        record.body_truncated = true;
        record.external_scripts_eligible = 5;
        record.external_scripts_scanned = 3;

        let id = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &HashMap::new(),
            http_headers: &HashMap::new(),
            oids: &HashSet::new(),
            redirect_chain: &[],
            technologies: &[],
            subject_alternative_names: &[],
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            body_domains: &[],
            script_hosts: &[],
        })
        .await
        .expect("insert");

        let row = sqlx::query(
            "SELECT body_truncated, external_scripts_eligible, external_scripts_scanned
             FROM url_status WHERE id = ?",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("select");

        assert_eq!(row.get::<i64, _>("body_truncated"), 1);
        assert_eq!(row.get::<i64, _>("external_scripts_eligible"), 5);
        assert_eq!(row.get::<i64, _>("external_scripts_scanned"), 3);

        // Upsert flips completeness fields; excluded.* must win.
        record.body_truncated = false;
        record.external_scripts_eligible = 7;
        record.external_scripts_scanned = 2;
        record.title = "Rescan".to_string();
        let id2 = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &HashMap::new(),
            http_headers: &HashMap::new(),
            oids: &HashSet::new(),
            redirect_chain: &[],
            technologies: &[],
            subject_alternative_names: &[],
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            body_domains: &[],
            script_hosts: &[],
        })
        .await
        .expect("upsert");
        assert_eq!(id, id2);

        let row2 = sqlx::query(
            "SELECT body_truncated, external_scripts_eligible, external_scripts_scanned, title
             FROM url_status WHERE id = ?",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("select after upsert");

        assert_eq!(row2.get::<i64, _>("body_truncated"), 0);
        assert_eq!(row2.get::<i64, _>("external_scripts_eligible"), 7);
        assert_eq!(row2.get::<i64, _>("external_scripts_scanned"), 2);
        assert_eq!(row2.get::<String, _>("title"), "Rescan");
    }

    #[tokio::test]
    async fn test_insert_url_record_with_technologies() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let record = create_test_url_record();
        let security_headers = HashMap::new();
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = Vec::new();
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
        let sans = Vec::new();

        let url_status_id = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            body_domains: &[],
            script_hosts: &[],
        })
        .await
        .expect("Failed to insert record");

        // Verify technologies were inserted
        let tech_rows =
            sqlx::query("SELECT technology_name FROM url_technologies WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_all(&pool)
                .await
                .expect("Failed to fetch technologies");

        assert_eq!(tech_rows.len(), 2);
        let tech_names: Vec<String> = tech_rows
            .iter()
            .map(|row| row.get::<String, _>("technology_name"))
            .collect();
        assert!(tech_names.contains(&"WordPress".to_string()));
        assert!(tech_names.contains(&"PHP".to_string()));
    }

    #[tokio::test]
    async fn test_insert_url_record_with_redirect_chain() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let record = create_test_url_record();
        let security_headers = HashMap::new();
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = vec![
            ("http://example.com".to_string(), 301u16),
            ("https://example.com".to_string(), 200u16),
        ];
        let technologies = Vec::new();
        let sans = Vec::new();

        let url_status_id = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            body_domains: &[],
            script_hosts: &[],
        })
        .await
        .expect("Failed to insert record");

        // Verify redirect chain was inserted
        let redirect_rows = sqlx::query(
            "SELECT redirect_url FROM url_redirect_chain WHERE url_status_id = ? ORDER BY sequence_order",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch redirect chain");

        assert_eq!(redirect_rows.len(), 2);
        assert_eq!(
            redirect_rows[0].get::<String, _>("redirect_url"),
            "http://example.com"
        );
        assert_eq!(
            redirect_rows[1].get::<String, _>("redirect_url"),
            "https://example.com"
        );
    }

    #[tokio::test]
    async fn test_insert_url_record_with_security_headers() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let record = create_test_url_record();
        let mut security_headers = HashMap::new();
        security_headers.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=31536000".to_string(),
        );
        security_headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = Vec::new();
        let technologies = Vec::new();
        let sans = Vec::new();

        let url_status_id = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            body_domains: &[],
            script_hosts: &[],
        })
        .await
        .expect("Failed to insert record");

        // Verify security headers were inserted
        let header_rows = sqlx::query(
            "SELECT header_name, header_value FROM url_security_headers WHERE url_status_id = ?",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch security headers");

        assert_eq!(header_rows.len(), 2);
        let mut header_map = HashMap::new();
        for row in header_rows {
            let name: String = row.get("header_name");
            let value: String = row.get("header_value");
            header_map.insert(name, value);
        }
        assert_eq!(
            header_map.get("Strict-Transport-Security"),
            Some(&"max-age=31536000".to_string())
        );
        assert_eq!(
            header_map.get("X-Content-Type-Options"),
            Some(&"nosniff".to_string())
        );
    }

    #[tokio::test]
    async fn test_insert_url_record_upsert() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let mut record = create_test_url_record();
        let security_headers = HashMap::new();
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = Vec::new();
        let technologies = Vec::new();
        let sans = Vec::new();

        // Insert first time
        let id1 = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            body_domains: &[],
            script_hosts: &[],
        })
        .await
        .expect("Failed to insert record");

        // Update record and insert again (same final_domain and timestamp)
        record.title = "Updated Title".to_string();
        record.status = 301;
        let id2 = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            body_domains: &[],
            script_hosts: &[],
        })
        .await
        .expect("Failed to upsert record");

        // Should return same ID (UPSERT)
        assert_eq!(id1, id2);

        // Verify the record was updated
        let row = sqlx::query("SELECT title, http_status FROM url_status WHERE id = ?")
            .bind(id1)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch updated record");

        assert_eq!(row.get::<String, _>("title"), "Updated Title");
        assert_eq!(row.get::<i64, _>("http_status"), 301);
    }

    /// Adversarial: UPSERT must DELETE stale satellite rows before re-inserting.
    /// Without the `URL_STATUS_SATELLITE_TABLES` cleanup, rescans leave orphan techs/redirects.
    #[tokio::test]
    async fn test_upsert_clears_stale_satellite_rows() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let record = create_test_url_record();
        let empty_headers = HashMap::new();
        let empty_oids = HashSet::new();
        let empty_sans: Vec<String> = Vec::new();

        let tech_a = vec![crate::fingerprint::DetectedTechnology {
            name: "TechA".to_string(),
            version: None,
            category: None,
            is_implied: false,
        }];
        let redirects_first: Vec<(String, u16)> = vec![
            ("http://old.example.com".to_string(), 301),
            ("https://example.com".to_string(), 200),
        ];

        let id1 = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &empty_headers,
            http_headers: &empty_headers,
            oids: &empty_oids,
            redirect_chain: &redirects_first,
            technologies: &tech_a,
            subject_alternative_names: &empty_sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            body_domains: &[],
            script_hosts: &[],
        })
        .await
        .expect("first insert");

        let tech_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_technologies WHERE url_status_id = ?")
                .bind(id1)
                .fetch_one(&pool)
                .await
                .expect("count techs");
        let redirect_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_redirect_chain WHERE url_status_id = ?")
                .bind(id1)
                .fetch_one(&pool)
                .await
                .expect("count redirects");
        assert_eq!(tech_count, 1);
        assert_eq!(redirect_count, 2);

        let tech_b = vec![crate::fingerprint::DetectedTechnology {
            name: "TechB".to_string(),
            version: Some("2.0".to_string()),
            category: None,
            is_implied: false,
        }];
        let redirects_second: Vec<(String, u16)> = Vec::new();

        let id2 = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &empty_headers,
            http_headers: &empty_headers,
            oids: &empty_oids,
            redirect_chain: &redirects_second,
            technologies: &tech_b,
            subject_alternative_names: &empty_sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            body_domains: &[],
            script_hosts: &[],
        })
        .await
        .expect("upsert");

        assert_eq!(id1, id2, "UPSERT should keep the same url_status id");

        let tech_names: Vec<String> = sqlx::query_scalar(
            "SELECT technology_name FROM url_technologies WHERE url_status_id = ? ORDER BY 1",
        )
        .bind(id2)
        .fetch_all(&pool)
        .await
        .expect("fetch techs after upsert");
        assert_eq!(
            tech_names,
            vec!["TechB".to_string()],
            "stale TechA must be gone; only TechB remains"
        );

        let redirect_count_after: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_redirect_chain WHERE url_status_id = ?")
                .bind(id2)
                .fetch_one(&pool)
                .await
                .expect("count redirects after upsert");
        assert_eq!(
            redirect_count_after, 0,
            "stale redirect hops must be deleted on UPSERT with empty chain"
        );
    }

    /// DNS/header/cert satellites: `url_technologies`, `url_nameservers`, `url_txt_records`,
    /// `url_mx_records`, `url_security_headers`, `url_http_headers`, `url_certificate_oids`.
    async fn seed_dns_and_header_satellite_tables(pool: &SqlitePool, url_status_id: i64) {
        sqlx::query("INSERT INTO url_technologies (url_status_id, technology_name) VALUES (?, ?)")
            .bind(url_status_id)
            .bind("SeedTech")
            .execute(pool)
            .await
            .expect("seed url_technologies");

        sqlx::query("INSERT INTO url_nameservers (url_status_id, nameserver) VALUES (?, ?)")
            .bind(url_status_id)
            .bind("ns1.seed.example")
            .execute(pool)
            .await
            .expect("seed url_nameservers");

        sqlx::query(
            "INSERT INTO url_txt_records (url_status_id, record_type, record_value) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("SPF")
        .bind("v=spf1 -all")
        .execute(pool)
        .await
        .expect("seed url_txt_records");

        sqlx::query(
            "INSERT INTO url_mx_records (url_status_id, priority, mail_exchange) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind(10i64)
        .bind("mail.seed.example")
        .execute(pool)
        .await
        .expect("seed url_mx_records");

        sqlx::query(
            "INSERT INTO url_security_headers (url_status_id, header_name, header_value) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("X-Seed-Security")
        .bind("seed-value")
        .execute(pool)
        .await
        .expect("seed url_security_headers");

        sqlx::query(
            "INSERT INTO url_http_headers (url_status_id, header_name, header_value) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("X-Seed-Header")
        .bind("seed-value")
        .execute(pool)
        .await
        .expect("seed url_http_headers");

        sqlx::query("INSERT INTO url_certificate_oids (url_status_id, oid) VALUES (?, ?)")
            .bind(url_status_id)
            .bind("1.2.3.4.5")
            .execute(pool)
            .await
            .expect("seed url_certificate_oids");
    }

    /// Cert/redirect/DNS-record satellites: `url_redirect_chain`, `url_certificate_sans`,
    /// `url_cname_records`, `url_ipv6_addresses`, `url_caa_records`, `url_csp_domains`,
    /// `url_cookies`.
    async fn seed_redirect_and_record_satellite_tables(pool: &SqlitePool, url_status_id: i64) {
        sqlx::query(
            "INSERT INTO url_redirect_chain (url_status_id, sequence_order, redirect_url) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind(1i64)
        .bind("https://seed.example/hop")
        .execute(pool)
        .await
        .expect("seed url_redirect_chain");

        sqlx::query("INSERT INTO url_certificate_sans (url_status_id, san_value) VALUES (?, ?)")
            .bind(url_status_id)
            .bind("seed.example")
            .execute(pool)
            .await
            .expect("seed url_certificate_sans");

        sqlx::query("INSERT INTO url_cname_records (url_status_id, cname_target) VALUES (?, ?)")
            .bind(url_status_id)
            .bind("cdn.seed.example")
            .execute(pool)
            .await
            .expect("seed url_cname_records");

        sqlx::query("INSERT INTO url_ipv6_addresses (url_status_id, ipv6_address) VALUES (?, ?)")
            .bind(url_status_id)
            .bind("::1")
            .execute(pool)
            .await
            .expect("seed url_ipv6_addresses");

        sqlx::query(
            "INSERT INTO url_caa_records (url_status_id, flag, tag, value) VALUES (?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind(0i64)
        .bind("issue")
        .bind("seed-ca.example")
        .execute(pool)
        .await
        .expect("seed url_caa_records");

        sqlx::query(
            "INSERT INTO url_csp_domains (url_status_id, directive, fqdn, registrable_domain) VALUES (?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("script-src")
        .bind("cdn.seed.example")
        .bind("seed.example")
        .execute(pool)
        .await
        .expect("seed url_csp_domains");

        sqlx::query(
            "INSERT INTO url_cookies (url_status_id, cookie_name, secure, http_only, same_site, domain, path) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("seed_session")
        .bind(true)
        .bind(true)
        .bind("Strict")
        .bind("seed.example")
        .bind("/")
        .execute(pool)
        .await
        .expect("seed url_cookies");
    }

    /// Body-content satellites: `url_resource_hints`, `url_body_domains`, `url_analytics_ids`,
    /// `url_structured_data`, `url_social_media_links`, `url_security_warnings`,
    /// `url_contact_links`.
    async fn seed_body_content_satellite_tables(pool: &SqlitePool, url_status_id: i64) {
        sqlx::query(
            "INSERT INTO url_resource_hints (url_status_id, hint_type, href) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("preconnect")
        .bind("https://cdn.seed.example")
        .execute(pool)
        .await
        .expect("seed url_resource_hints");

        sqlx::query(
            "INSERT INTO url_body_domains (url_status_id, fqdn, registrable_domain) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("linked.seed.example")
        .bind("seed.example")
        .execute(pool)
        .await
        .expect("seed url_body_domains");

        sqlx::query(
            "INSERT INTO url_script_hosts (url_status_id, host, registrable_domain, is_first_party) VALUES (?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("cdn.seed.example")
        .bind("seed.example")
        .bind(true)
        .execute(pool)
        .await
        .expect("seed url_script_hosts");

        sqlx::query(
            "INSERT INTO url_analytics_ids (url_status_id, provider, tracking_id) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("Seed Analytics")
        .bind("SEED-1")
        .execute(pool)
        .await
        .expect("seed url_analytics_ids");

        sqlx::query(
            "INSERT INTO url_structured_data (url_status_id, data_type, property_name, property_value) VALUES (?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("open_graph")
        .bind("og:title")
        .bind("Seed Title")
        .execute(pool)
        .await
        .expect("seed url_structured_data");

        sqlx::query(
            "INSERT INTO url_social_media_links (url_status_id, platform, profile_url, identifier) VALUES (?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("Seed Platform")
        .bind("https://seed.example/profile")
        .bind("seeduser")
        .execute(pool)
        .await
        .expect("seed url_social_media_links");

        sqlx::query(
            "INSERT INTO url_security_warnings (url_status_id, warning_code, warning_description) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("seed_warning")
        .bind("Seed warning description")
        .execute(pool)
        .await
        .expect("seed url_security_warnings");

        sqlx::query(
            "INSERT INTO url_contact_links (url_status_id, contact_type, contact_value, raw_href) VALUES (?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("email")
        .bind("seed@example.com")
        .bind("mailto:seed@example.com")
        .execute(pool)
        .await
        .expect("seed url_contact_links");
    }

    /// Enrichment satellites populated outside the main insert transaction:
    /// `url_exposed_secrets`, `url_partial_failures`, `url_favicons`, `url_geoip`, `url_whois`.
    async fn seed_enrichment_satellite_tables(pool: &SqlitePool, url_status_id: i64) {
        sqlx::query(
            "INSERT INTO url_exposed_secrets (url_status_id, secret_type, matched_value, severity, location, context) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("seed_secret")
        .bind("seed-matched-value")
        .bind("low")
        .bind("inline_script")
        .bind("...seed context...")
        .execute(pool)
        .await
        .expect("seed url_exposed_secrets");

        sqlx::query(
            "INSERT INTO url_partial_failures (url_status_id, error_type, error_message, observed_at_ms) VALUES (?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("seed_error")
        .bind("seed error message")
        .bind(1_704_067_200_000i64)
        .execute(pool)
        .await
        .expect("seed url_partial_failures");

        sqlx::query(
            "INSERT INTO url_favicons (url_status_id, favicon_url, hash, base64_data) VALUES (?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("https://seed.example/favicon.ico")
        .bind(12345i64)
        .bind("c2VlZA==")
        .execute(pool)
        .await
        .expect("seed url_favicons");

        sqlx::query("INSERT INTO url_geoip (url_status_id, country_code) VALUES (?, ?)")
            .bind(url_status_id)
            .bind("US")
            .execute(pool)
            .await
            .expect("seed url_geoip");

        sqlx::query("INSERT INTO url_whois (url_status_id, registrar) VALUES (?, ?)")
            .bind(url_status_id)
            .bind("Seed Registrar")
            .execute(pool)
            .await
            .expect("seed url_whois");
    }

    /// Inserts one minimal, schema-valid row into every table in [`URL_STATUS_SATELLITE_TABLES`]
    /// for the given `url_status_id`, using the columns required by each table's schema
    /// (see `migrations/`).
    async fn seed_one_row_per_satellite_table(pool: &SqlitePool, url_status_id: i64) {
        seed_dns_and_header_satellite_tables(pool, url_status_id).await;
        seed_redirect_and_record_satellite_tables(pool, url_status_id).await;
        seed_body_content_satellite_tables(pool, url_status_id).await;
        seed_enrichment_satellite_tables(pool, url_status_id).await;
    }

    /// Adversarial: UPSERT must clear stale rows from *every* satellite/enrichment table
    /// that hangs off `url_status.id`, not just the ones this transaction re-inserts.
    /// Without cleanup, a rescan with (e.g.) no more exposed secrets or `GeoIP` data would
    /// leave a stale "detection" from a previous scan visible forever.
    #[tokio::test]
    async fn test_upsert_clears_all_satellite_tables() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        // Use the bare default (not `create_test_url_record()`, whose nameservers/txt/mx
        // JSON fields would themselves insert satellite rows) so the "first insert
        // produces zero satellite rows" assumption below holds.
        let mut record = UrlRecord::test_default();
        record.run_id = Some("test-run-1".to_string());

        let id1 = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &HashMap::new(),
            http_headers: &HashMap::new(),
            oids: &HashSet::new(),
            redirect_chain: &[],
            technologies: &[],
            subject_alternative_names: &[],
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            body_domains: &[],
            script_hosts: &[],
        })
        .await
        .expect("first insert");

        seed_one_row_per_satellite_table(&pool, id1).await;

        for table in URL_STATUS_SATELLITE_TABLES {
            let count: i64 = sqlx::query_scalar(&format!(
                "SELECT COUNT(*) FROM {table} WHERE url_status_id = ?"
            ))
            .bind(id1)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("failed to count seeded rows in {table}: {e}"));
            assert_eq!(
                count, 1,
                "seed setup should have inserted exactly 1 row into {table}"
            );
        }

        // Second UPSERT with the same (run_id, final_domain) and empty satellites/tech.
        let id2 = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &HashMap::new(),
            http_headers: &HashMap::new(),
            oids: &HashSet::new(),
            redirect_chain: &[],
            technologies: &[],
            subject_alternative_names: &[],
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            body_domains: &[],
            script_hosts: &[],
        })
        .await
        .expect("upsert");
        assert_eq!(id1, id2, "UPSERT must reuse the same url_status id");

        for table in URL_STATUS_SATELLITE_TABLES {
            let count: i64 = sqlx::query_scalar(&format!(
                "SELECT COUNT(*) FROM {table} WHERE url_status_id = ?"
            ))
            .bind(id2)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("failed to count post-upsert rows in {table}: {e}"));
            assert_eq!(
                count, 0,
                "UPSERT with empty satellites must clear stale rows from {table}, found {count}"
            );
        }
    }

    #[tokio::test]
    async fn test_insert_url_record_nullable_fields() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let mut record = create_test_url_record();
        // Set nullable fields to None
        record.keywords = None;
        record.description = None;
        record.reverse_dns_name = None;
        record.tls_version = None;
        record.ssl_cert_subject = None;
        record.ssl_cert_issuer = None;
        record.ssl_cert_valid_from = None;
        record.ssl_cert_valid_to = None;
        record.spf_record = None;
        record.dmarc_record = None;
        record.cipher_suite = None;
        record.key_algorithm = None;
        record.run_id = None;

        let security_headers = HashMap::new();
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = Vec::new();
        let technologies = Vec::new();
        let sans = Vec::new();

        let result = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            body_domains: &[],
            script_hosts: &[],
        })
        .await;

        assert!(result.is_ok());
        // Verify NULL fields are handled correctly
        let row =
            sqlx::query("SELECT keywords, description, tls_version FROM url_status WHERE id = ?")
                .bind(result.unwrap())
                .fetch_one(&pool)
                .await
                .expect("Failed to fetch record");

        assert!(row.get::<Option<String>, _>("keywords").is_none());
        assert!(row.get::<Option<String>, _>("description").is_none());
        assert!(row.get::<Option<String>, _>("tls_version").is_none());
    }
}
