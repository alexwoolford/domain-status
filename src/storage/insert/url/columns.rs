//! `url_status` column registry and fact-row UPSERT SQL.
//!
//! INSERT/UPDATE column order and binds are derived from [`URL_STATUS_COLUMN_DEFS`]
//! so adding a column is a single edit.

use crate::error_handling::DatabaseError;
use crate::storage::models::UrlRecord;

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
pub(crate) fn url_status_insert_sql() -> String {
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

pub(crate) fn url_status_update_sql() -> String {
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
pub(crate) async fn upsert_url_status_row(
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
