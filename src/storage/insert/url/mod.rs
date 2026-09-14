//! Main URL record insertion.
//!
//! This module handles inserting URL status records and related satellite tables.
//! In-transaction satellites live in `URL_STATUS_CORE_SATELLITE_TABLES`; enrichment
//! satellites (`GeoIP`, WHOIS, secrets, etc.) live in
//! `URL_STATUS_ENRICHMENT_SATELLITE_TABLES` and are replaced after that transaction
//! commits, in a second writer transaction.

mod satellite;

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;

use super::super::models::UrlRecord;
use super::retry::with_sqlite_retry;
use super::utils::naive_datetime_to_millis;

/// Result of upserting into `url_status` (unique on `(run_id, initial_domain)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlUpsertOutcome {
    pub id: i64,
    /// `true` when this call created a new row; `false` when an existing row was updated.
    pub inserted: bool,
    /// In-transaction satellite SQL failures (logged; main row still commits).
    pub satellite_insert_failures: Vec<SatelliteWriteFailure>,
}

/// One failed in-transaction satellite insert (table name + driver message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SatelliteWriteFailure {
    pub table: &'static str,
    pub message: String,
}

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
/// `initial_domain` is part of the conflict key and is omitted from the UPDATE SET
/// clause; every other column (including `final_domain`) is refreshed on conflict.
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
    UrlStatusColumn {
        name: "hsts_max_age",
        extract: |r, _, _| UrlStatusBind::OptI64(r.hsts_max_age),
    },
    UrlStatusColumn {
        name: "hsts_include_subdomains",
        extract: |r, _, _| UrlStatusBind::OptBool(r.hsts_include_subdomains),
    },
    UrlStatusColumn {
        name: "hsts_preload",
        extract: |r, _, _| UrlStatusBind::OptBool(r.hsts_preload),
    },
    UrlStatusColumn {
        name: "mta_sts_record",
        extract: |r, _, _| UrlStatusBind::OptText(r.mta_sts_record.as_deref()),
    },
    UrlStatusColumn {
        name: "tls_rpt_record",
        extract: |r, _, _| UrlStatusBind::OptText(r.tls_rpt_record.as_deref()),
    },
    UrlStatusColumn {
        name: "bimi_record",
        extract: |r, _, _| UrlStatusBind::OptText(r.bimi_record.as_deref()),
    },
    UrlStatusColumn {
        name: "cdn_provider",
        extract: |r, _, _| UrlStatusBind::OptText(r.cdn_provider.as_deref()),
    },
];

/// Column names derived from [`URL_STATUS_COLUMN_DEFS`] (same order as binds).
///
/// `pub(crate)` so export/field-inventory tests can assert capture ↔ schema sync
/// without duplicating this list.
pub(crate) fn url_status_column_names() -> impl Iterator<Item = &'static str> {
    URL_STATUS_COLUMN_DEFS.iter().map(|c| c.name)
}

fn bind_url_status_column<'q>(
    query: sqlx::query::QueryScalar<'q, sqlx::Sqlite, i64, sqlx::sqlite::SqliteArguments<'q>>,
    col: &UrlStatusColumn,
    record: &'q UrlRecord,
    valid_from_millis: Option<i64>,
    valid_to_millis: Option<i64>,
) -> sqlx::query::QueryScalar<'q, sqlx::Sqlite, i64, sqlx::sqlite::SqliteArguments<'q>> {
    match (col.extract)(record, valid_from_millis, valid_to_millis) {
        UrlStatusBind::Text(v) => query.bind(v),
        UrlStatusBind::OptText(v) => query.bind(v),
        UrlStatusBind::U16(v) => query.bind(v),
        UrlStatusBind::U32(v) => query.bind(v),
        UrlStatusBind::I64(v) => query.bind(v),
        UrlStatusBind::OptI64(v) => query.bind(v),
        UrlStatusBind::F64(v) => query.bind(v),
        UrlStatusBind::Bool(v) => query.bind(v),
        UrlStatusBind::OptBool(v) => query.bind(v),
    }
}

/// Insert-or-ignore so `RETURNING id` is present only on a new row (conflict is not TOCTOU).
fn url_status_insert_sql() -> String {
    let columns = url_status_column_names().collect::<Vec<_>>().join(", ");
    let placeholders = std::iter::repeat_n("?", URL_STATUS_COLUMN_DEFS.len())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "INSERT INTO url_status (
            {columns}
        ) VALUES ({placeholders})
        ON CONFLICT(run_id, initial_domain) DO NOTHING
        RETURNING id"
    )
}

fn url_status_update_sql() -> String {
    let updates = url_status_column_names()
        .filter(|&col| col != "initial_domain")
        .map(|col| format!("{col}=?"))
        .collect::<Vec<_>>()
        .join(",\n            ");
    format!(
        "UPDATE url_status SET
            {updates}
        WHERE run_id = ? AND initial_domain = ?
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
        q = bind_url_status_column(q, col, record, valid_from_millis, valid_to_millis);
    }
    q
}

fn bind_url_status_update_query<'q>(
    query: sqlx::query::QueryScalar<'q, sqlx::Sqlite, i64, sqlx::sqlite::SqliteArguments<'q>>,
    record: &'q UrlRecord,
    valid_from_millis: Option<i64>,
    valid_to_millis: Option<i64>,
) -> sqlx::query::QueryScalar<'q, sqlx::Sqlite, i64, sqlx::sqlite::SqliteArguments<'q>> {
    let mut q = query;
    for col in URL_STATUS_COLUMN_DEFS {
        if col.name == "initial_domain" {
            continue;
        }
        q = bind_url_status_column(q, col, record, valid_from_millis, valid_to_millis);
    }
    q.bind(record.run_id.as_deref())
        .bind(&record.initial_domain)
}

/// Insert a new `url_status` row, or update on `(run_id, initial_domain)` conflict.
///
/// `inserted` comes from whether `INSERT … DO NOTHING` returned an id, not a
/// pre-UPSERT `SELECT` (that check raced under concurrent duplicate domains).
async fn upsert_url_status_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    record: &UrlRecord,
    valid_from_millis: Option<i64>,
    valid_to_millis: Option<i64>,
) -> Result<(i64, bool), DatabaseError> {
    let insert_sql = url_status_insert_sql();
    let inserted_id = bind_url_status_query(
        sqlx::query_scalar::<_, i64>(&insert_sql),
        record,
        valid_from_millis,
        valid_to_millis,
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| {
        log::error!(
            "Failed to insert UrlRecord for domain {} (final_domain: {}, status: {}, timestamp: {}): {} (SQL: INSERT INTO url_status ... ON CONFLICT DO NOTHING)",
            record.initial_domain,
            record.final_domain,
            record.status,
            record.timestamp,
            e
        );
        DatabaseError::SqlError(e)
    })?;

    if let Some(id) = inserted_id {
        return Ok((id, true));
    }

    let update_sql = url_status_update_sql();
    let id = bind_url_status_update_query(
        sqlx::query_scalar::<_, i64>(&update_sql),
        record,
        valid_from_millis,
        valid_to_millis,
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| {
        log::error!(
            "Failed to update UrlRecord for domain {} (final_domain: {}, status: {}, timestamp: {}): {} (SQL: UPDATE url_status ...)",
            record.initial_domain,
            record.final_domain,
            record.status,
            record.timestamp,
            e
        );
        DatabaseError::SqlError(e)
    })?;
    Ok((id, false))
}

/// Core satellites inserted inside the `url_status` transaction.
///
/// Cleaned before re-insert on UPSERT so rescans do not leave stale child rows.
/// Enrichment tables are **not** listed here — they are replaced in the enrichment
/// writer transaction so readers never see an empty gap after the fact row commits.
pub(crate) const URL_STATUS_CORE_SATELLITE_TABLES: &[&str] = &[
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
    "url_script_hosts",
    "url_security_txt",
    "url_robots_txt",
    "url_robots_directives",
];

/// Enrichment satellites inserted after the `url_status` transaction commits.
///
/// DELETE + INSERT share one writer transaction in `insert_enrichment_data`.
/// `url_jwt_claims` is omitted: those rows cascade-delete from `url_exposed_secrets`.
pub(crate) const URL_STATUS_ENRICHMENT_SATELLITE_TABLES: &[&str] = &[
    "url_analytics_ids",
    "url_structured_data",
    "url_social_media_links",
    "url_contact_links",
    "url_exposed_secrets",
    "url_partial_failures",
    "url_favicons",
    "url_geoip",
    "url_whois",
];

const fn satellite_bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

const fn satellite_slice_contains(haystack: &[&str], needle: &str) -> bool {
    let mut i = 0;
    while i < haystack.len() {
        if satellite_bytes_eq(haystack[i].as_bytes(), needle.as_bytes()) {
            return true;
        }
        i += 1;
    }
    false
}

const fn core_and_enrichment_overlap() -> bool {
    let mut i = 0;
    while i < URL_STATUS_CORE_SATELLITE_TABLES.len() {
        if satellite_slice_contains(
            URL_STATUS_ENRICHMENT_SATELLITE_TABLES,
            URL_STATUS_CORE_SATELLITE_TABLES[i],
        ) {
            return true;
        }
        i += 1;
    }
    false
}

const _: () = assert!(
    !core_and_enrichment_overlap(),
    "core and enrichment satellite lists must not overlap"
);

/// Union of core + enrichment child tables (core first).
#[cfg(test)]
pub(crate) fn url_status_satellite_tables() -> impl Iterator<Item = &'static str> {
    URL_STATUS_CORE_SATELLITE_TABLES
        .iter()
        .copied()
        .chain(URL_STATUS_ENRICHMENT_SATELLITE_TABLES.iter().copied())
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
    if let Err(e) =
        super::utils::delete_child_rows(&mut tx, URL_STATUS_CORE_SATELLITE_TABLES, url_status_id)
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

/// Inserts CSP domains into `url_csp_domains` table.
async fn insert_csp_domains(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    url_status_id: i64,
    domains: &[(String, String, Option<String>)],
) -> Result<(), sqlx::Error> {
    if domains.is_empty() {
        return Ok(());
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
    qb.execute(&mut **tx).await?;
    Ok(())
}

/// Inserts cookie security info into `url_cookies` table.
///
/// Unique on `(url_status_id, cookie_name)` only — browsers key cookies by
/// name + Domain + Path, so two `Set-Cookie` headers with the same name collapse
/// here (last write wins, including `domain` / `path`).
async fn insert_cookies(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    url_status_id: i64,
    cookies: &[crate::storage::CookieInfo],
) -> Result<(), sqlx::Error> {
    if cookies.is_empty() {
        return Ok(());
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
        Some(
            "ON CONFLICT(url_status_id, cookie_name) DO UPDATE SET \
             secure=excluded.secure, http_only=excluded.http_only, \
             same_site=excluded.same_site, domain=excluded.domain, path=excluded.path",
        ),
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
    qb.execute(&mut **tx).await?;
    Ok(())
}

/// Inserts parsed `security.txt` into `url_security_txt`.
async fn insert_security_txt(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    url_status_id: i64,
    data: Option<&crate::fetch::well_known::SecurityTxtData>,
) -> Result<(), sqlx::Error> {
    let Some(data) = data else {
        return Ok(());
    };
    sqlx::query(
        "INSERT INTO url_security_txt (
            url_status_id, source_url, http_status, contacts, expires, encryption,
            acknowledgments, preferred_languages, canonical, policy, hiring, raw_body
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(url_status_id) DO UPDATE SET
            source_url=excluded.source_url,
            http_status=excluded.http_status,
            contacts=excluded.contacts,
            expires=excluded.expires,
            encryption=excluded.encryption,
            acknowledgments=excluded.acknowledgments,
            preferred_languages=excluded.preferred_languages,
            canonical=excluded.canonical,
            policy=excluded.policy,
            hiring=excluded.hiring,
            raw_body=excluded.raw_body",
    )
    .bind(url_status_id)
    .bind(&data.source_url)
    .bind(i64::from(data.http_status))
    .bind(data.contacts.join("\n"))
    .bind(&data.expires)
    .bind(data.encryption.join("\n"))
    .bind(data.acknowledgments.join("\n"))
    .bind(&data.preferred_languages)
    .bind(data.canonical.join("\n"))
    .bind(data.policy.join("\n"))
    .bind(data.hiring.join("\n"))
    .bind(&data.raw_body)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Inserts parsed `robots.txt` parent row and directives.
async fn insert_robots_txt(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    url_status_id: i64,
    data: Option<&crate::fetch::well_known::RobotsTxtData>,
) -> Result<(), sqlx::Error> {
    let Some(data) = data else {
        return Ok(());
    };
    sqlx::query(
        "INSERT INTO url_robots_txt (url_status_id, http_status, raw_body)
         VALUES (?, ?, ?)
         ON CONFLICT(url_status_id) DO UPDATE SET
            http_status=excluded.http_status,
            raw_body=excluded.raw_body",
    )
    .bind(url_status_id)
    .bind(i64::from(data.http_status))
    .bind(&data.raw_body)
    .execute(&mut **tx)
    .await?;
    if data.directives.is_empty() {
        return Ok(());
    }
    let query = super::utils::build_batch_insert_query(
        "url_robots_directives",
        &["url_status_id", "directive", "value"],
        data.directives.len(),
        Some("ON CONFLICT(url_status_id, directive, value) DO NOTHING"),
    );
    let mut qb = sqlx::query(&query);
    for (directive, value) in &data.directives {
        qb = qb.bind(url_status_id).bind(directive).bind(value);
    }
    qb.execute(&mut **tx).await?;
    Ok(())
}

/// Inserts script `src` host inventory into `url_script_hosts`.
async fn insert_script_hosts(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    url_status_id: i64,
    hosts: &[crate::storage::ScriptHostInfo],
) -> Result<(), sqlx::Error> {
    if hosts.is_empty() {
        return Ok(());
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
    qb.execute(&mut **tx).await?;
    Ok(())
}

/// Inserts resource hints into `url_resource_hints` table. `hint_type` may be
/// preconnect, dns-prefetch, preload, prefetch, or modulepreload.
async fn insert_resource_hints(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    url_status_id: i64,
    hints: &[(String, String)],
) -> Result<(), sqlx::Error> {
    if hints.is_empty() {
        return Ok(());
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
    qb.execute(&mut **tx).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use sqlx::Row;
    use std::collections::{HashMap, HashSet};

    use crate::storage::migrations::run_migrations;
    use crate::storage::CookieInfo;

    #[test]
    fn url_status_column_defs_are_unique_and_ordered_with_names_iter() {
        let names: Vec<_> = url_status_column_names().collect();
        assert_eq!(names.len(), URL_STATUS_COLUMN_DEFS.len());
        let mut seen = HashSet::new();
        for (i, name) in names.iter().enumerate() {
            assert_eq!(*name, URL_STATUS_COLUMN_DEFS[i].name);
            assert!(seen.insert(*name), "duplicate url_status column: {name}");
        }
        assert_eq!(names.len(), 44, "url_status column count drifted");
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
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
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
            script_hosts: &script_hosts,
            security_txt: None,
            robots_txt: None,
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
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
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
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
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
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
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
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
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
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
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
        let first = insert_url_record_with_outcome(UrlRecordInsertParams {
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
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        })
        .await
        .expect("Failed to insert record");
        assert!(first.inserted);
        let id1 = first.id;

        // Update record and insert again (same final_domain and timestamp)
        record.title = "Updated Title".to_string();
        record.status = 301;
        let second = insert_url_record_with_outcome(UrlRecordInsertParams {
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
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        })
        .await
        .expect("Failed to upsert record");
        assert!(!second.inserted);
        let id2 = second.id;

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

    #[tokio::test]
    async fn test_insert_cookies_same_name_updates_domain_and_path() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let record = create_test_url_record();
        let security_headers = HashMap::new();
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let cookies = [
            CookieInfo {
                name: "sid".to_string(),
                secure: false,
                http_only: false,
                same_site: Some("Lax".to_string()),
                domain: Some("a.example".to_string()),
                path: Some("/a".to_string()),
            },
            CookieInfo {
                name: "sid".to_string(),
                secure: true,
                http_only: true,
                same_site: Some("None".to_string()),
                domain: Some("b.example".to_string()),
                path: Some("/b".to_string()),
            },
        ];

        let id = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &[],
            technologies: &[],
            subject_alternative_names: &[],
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &cookies,
            resource_hints: &[],
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        })
        .await
        .expect("insert cookies");

        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM url_cookies WHERE url_status_id = ?")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("count cookies");
        assert_eq!(n, 1, "name-only UNIQUE collapses duplicate cookie names");

        let row = sqlx::query(
            "SELECT cookie_name, secure, http_only, same_site, domain, path
             FROM url_cookies WHERE url_status_id = ?",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("fetch cookie");

        assert_eq!(row.get::<String, _>("cookie_name"), "sid");
        assert_eq!(row.get::<i64, _>("secure"), 1);
        assert_eq!(row.get::<i64, _>("http_only"), 1);
        assert_eq!(row.get::<String, _>("same_site"), "None");
        assert_eq!(row.get::<String, _>("domain"), "b.example");
        assert_eq!(row.get::<String, _>("path"), "/b");
    }

    #[tokio::test]
    async fn test_insert_url_record_same_final_different_initial_keeps_two_rows() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let security_headers = HashMap::new();
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = Vec::new();
        let technologies = Vec::new();
        let sans = Vec::new();

        let mut a = create_test_url_record();
        a.initial_domain = "parked-a.com".to_string();
        a.final_domain = "parked.example.com".to_string();
        a.initial_url = Some("https://parked-a.com".to_string());
        a.final_url = Some("https://parked.example.com/a".to_string());

        let mut b = create_test_url_record();
        b.initial_domain = "parked-b.com".to_string();
        b.final_domain = "parked.example.com".to_string();
        b.initial_url = Some("https://parked-b.com".to_string());
        b.final_url = Some("https://parked.example.com/b".to_string());

        let id_a = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &a,
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
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        })
        .await
        .expect("insert a");

        let id_b = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &b,
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
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        })
        .await
        .expect("insert b");

        assert_ne!(id_a, id_b);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM url_status")
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(count, 2);
    }

    /// Build insert params with empty optional satellites (tests only).
    fn insert_params_with_tech_redirects<'a>(
        pool: &'a SqlitePool,
        record: &'a UrlRecord,
        empty_headers: &'a HashMap<String, String>,
        empty_oids: &'a HashSet<String>,
        empty_sans: &'a [String],
        redirect_chain: &'a [(String, u16)],
        technologies: &'a [crate::fingerprint::DetectedTechnology],
    ) -> UrlRecordInsertParams<'a> {
        UrlRecordInsertParams {
            pool,
            record,
            security_headers: empty_headers,
            http_headers: empty_headers,
            oids: empty_oids,
            redirect_chain,
            technologies,
            subject_alternative_names: empty_sans,
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

    /// Adversarial: UPSERT must DELETE stale satellite rows before re-inserting.
    /// Without core satellite DELETE on UPSERT, rescans leave orphan techs/redirects.
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

        let id1 = insert_url_record(insert_params_with_tech_redirects(
            &pool,
            &record,
            &empty_headers,
            &empty_oids,
            &empty_sans,
            &redirects_first,
            &tech_a,
        ))
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

        let id2 = insert_url_record(insert_params_with_tech_redirects(
            &pool,
            &record,
            &empty_headers,
            &empty_oids,
            &empty_sans,
            &redirects_second,
            &tech_b,
        ))
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

    /// Body-content satellites: `url_resource_hints`, `url_script_hosts`, `url_analytics_ids`,
    /// `url_structured_data`, `url_social_media_links`, `url_contact_links`.
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
            "INSERT INTO url_security_txt (
                url_status_id, source_url, http_status, contacts, expires, encryption,
                acknowledgments, preferred_languages, canonical, policy, hiring, raw_body
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("https://seed.example/.well-known/security.txt")
        .bind(200i64)
        .bind("mailto:security@seed.example")
        .bind(Option::<String>::None)
        .bind("")
        .bind("")
        .bind(Option::<String>::None)
        .bind("")
        .bind("")
        .bind("")
        .bind("Contact: mailto:security@seed.example\n")
        .execute(pool)
        .await
        .expect("seed url_security_txt");

        sqlx::query(
            "INSERT INTO url_robots_txt (url_status_id, http_status, raw_body) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind(200i64)
        .bind("User-agent: *\nDisallow: /admin\n")
        .execute(pool)
        .await
        .expect("seed url_robots_txt");

        sqlx::query(
            "INSERT INTO url_robots_directives (url_status_id, directive, value) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("disallow")
        .bind("/admin")
        .execute(pool)
        .await
        .expect("seed url_robots_directives");

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

        sqlx::query("INSERT INTO url_favicons (url_status_id, favicon_url, hash) VALUES (?, ?, ?)")
            .bind(url_status_id)
            .bind("https://seed.example/favicon.ico")
            .bind(12345i64)
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

    /// Inserts one minimal, schema-valid row into every core and enrichment satellite.
    async fn seed_one_row_per_satellite_table(pool: &SqlitePool, url_status_id: i64) {
        seed_dns_and_header_satellite_tables(pool, url_status_id).await;
        seed_redirect_and_record_satellite_tables(pool, url_status_id).await;
        seed_body_content_satellite_tables(pool, url_status_id).await;
        seed_enrichment_satellite_tables(pool, url_status_id).await;
    }

    #[test]
    fn core_and_enrichment_satellite_lists_partition_children() {
        let mut seen = HashSet::new();
        for table in url_status_satellite_tables() {
            assert!(seen.insert(table), "duplicate satellite table {table}");
        }
        assert_eq!(
            seen.len(),
            URL_STATUS_CORE_SATELLITE_TABLES.len() + URL_STATUS_ENRICHMENT_SATELLITE_TABLES.len()
        );
    }

    fn rust_fn_body<'a>(src: &'a str, sig: &str) -> &'a str {
        let start = src
            .find(sig)
            .unwrap_or_else(|| panic!("missing function `{sig}`"));
        let after = &src[start..];
        let brace = after.find('{').expect("function body");
        let body_start = brace + 1;
        let mut depth = 1usize;
        for (i, b) in after[body_start..].bytes().enumerate() {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &after[body_start..body_start + i];
                    }
                }
                _ => {}
            }
        }
        panic!("unclosed function `{sig}`");
    }

    fn quoted_nth_after_marker<'a>(body: &'a str, marker: &str, n: usize) -> Vec<&'a str> {
        let mut tables = Vec::new();
        let mut rest = body;
        while let Some(i) = rest.find(marker) {
            rest = &rest[i + marker.len()..];
            let mut found = Vec::new();
            let mut search = rest;
            for _ in 0..=n {
                let Some(q) = search.find('"') else {
                    break;
                };
                search = &search[q + 1..];
                let end = search.find('"').expect("closing quote");
                found.push(&search[..end]);
                search = &search[end + 1..];
            }
            tables.push(*found.get(n).unwrap_or_else(|| {
                panic!("{marker} missing quoted arg {n}");
            }));
            rest = search;
        }
        tables
    }

    #[test]
    fn core_satellite_delete_list_matches_insert_call_sites() {
        let src = include_str!("mod.rs");
        let impl_body = rust_fn_body(src, "async fn insert_url_record_impl");
        let mut written: HashSet<&str> =
            quoted_nth_after_marker(impl_body, "record_satellite_write(", 0)
                .into_iter()
                .collect();
        let robots_body = rust_fn_body(src, "async fn insert_robots_txt");
        assert!(
            robots_body.contains("url_robots_directives"),
            "insert_robots_txt must write url_robots_directives (nested under url_robots_txt)"
        );
        written.insert("url_robots_directives");
        let listed: HashSet<&str> = URL_STATUS_CORE_SATELLITE_TABLES.iter().copied().collect();
        assert_eq!(
            written, listed,
            "CORE satellite DELETE list must match insert_url_record_impl writes"
        );
    }

    #[test]
    fn enrichment_satellite_delete_list_matches_insert_call_sites() {
        let src = include_str!("../record.rs");
        let txn_body = rust_fn_body(src, "async fn insert_enrichment_txn");
        let mut written: HashSet<&str> = quoted_nth_after_marker(txn_body, "try_enrich_tx(", 1)
            .into_iter()
            .collect();
        written.insert("url_exposed_secrets");
        written.insert("url_partial_failures");
        let listed: HashSet<&str> = URL_STATUS_ENRICHMENT_SATELLITE_TABLES
            .iter()
            .copied()
            .collect();
        assert_eq!(
            written, listed,
            "ENRICHMENT satellite DELETE list must match insert_enrichment_txn writes"
        );
        let secrets_body = rust_fn_body(src, "async fn insert_exposed_secrets_in_tx");
        assert!(
            secrets_body.contains("url_jwt_claims"),
            "JWT claims are written with secrets and CASCADE on url_exposed_secrets delete"
        );
        assert!(
            !listed.contains("url_jwt_claims"),
            "url_jwt_claims must stay off the ENRICHMENT DELETE list (CASCADE from secrets)"
        );
    }

    /// Core UPSERT clears in-transaction satellites and leaves enrichment in place
    /// until the enrichment writer transaction replaces it.
    #[tokio::test]
    async fn test_upsert_clears_core_satellite_tables_only() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let mut record = UrlRecord::test_default();
        record.run_id = Some("test-run-1".to_string());

        let empty_security = HashMap::new();
        let empty_http = HashMap::new();
        let empty_oids = HashSet::new();

        let id1 = insert_url_record(UrlRecordInsertParams::with_empty_satellites(
            &pool,
            &record,
            &empty_security,
            &empty_http,
            &empty_oids,
        ))
        .await
        .expect("first insert");

        seed_one_row_per_satellite_table(&pool, id1).await;

        for table in url_status_satellite_tables() {
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

        let id2 = insert_url_record(UrlRecordInsertParams::with_empty_satellites(
            &pool,
            &record,
            &empty_security,
            &empty_http,
            &empty_oids,
        ))
        .await
        .expect("upsert");
        assert_eq!(id1, id2, "UPSERT must reuse the same url_status id");

        for table in URL_STATUS_CORE_SATELLITE_TABLES {
            let count: i64 = sqlx::query_scalar(&format!(
                "SELECT COUNT(*) FROM {table} WHERE url_status_id = ?"
            ))
            .bind(id2)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("failed to count post-upsert rows in {table}: {e}"));
            assert_eq!(
                count, 0,
                "core UPSERT must clear stale rows from {table}, found {count}"
            );
        }
        for table in URL_STATUS_ENRICHMENT_SATELLITE_TABLES {
            let count: i64 = sqlx::query_scalar(&format!(
                "SELECT COUNT(*) FROM {table} WHERE url_status_id = ?"
            ))
            .bind(id2)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("failed to count enrichment rows in {table}: {e}"));
            assert_eq!(
                count, 1,
                "core UPSERT must leave enrichment table {table} in place until enrichment rewrite"
            );
        }
    }

    #[tokio::test]
    async fn test_insert_url_record_nullable_fields() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let mut record = create_test_url_record();
        // Set nullable fields to None
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
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        })
        .await;

        assert!(result.is_ok());
        // Verify NULL fields are handled correctly
        let row = sqlx::query("SELECT description, tls_version FROM url_status WHERE id = ?")
            .bind(result.unwrap())
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch record");

        assert!(row.get::<Option<String>, _>("description").is_none());
        assert!(row.get::<Option<String>, _>("tls_version").is_none());
    }
}
