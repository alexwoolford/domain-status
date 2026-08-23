//! Shared export field registry.
//!
//! CSV columns, Parquet schema (and flat JSONL keys) are driven from
//! [`EXPORT_FIELDS`] so format-specific serializers cannot drift silently.

use std::sync::Arc;

use arrow::datatypes::{DataType, Field, Schema};
use serde_json::{json, Value};

use super::row::{build_url, ExportRow};

/// One export field spanning CSV / Parquet / flat JSONL as applicable.
pub(crate) struct ExportField {
    /// Stable id (CSV name when the field appears in CSV; otherwise Parquet name).
    pub id: &'static str,
    /// CSV column name + string extractor (`None` = omitted from CSV).
    pub csv: Option<CsvSpec>,
    /// Parquet column (`None` = omitted from Parquet).
    pub parquet: Option<ParquetSpec>,
    /// Flat top-level JSONL value (`None` = nested / hand-built in jsonl.rs).
    pub jsonl_flat: Option<fn(&ExportRow) -> Value>,
    /// Scalar present in both CSV and Parquet (possibly renamed).
    #[cfg_attr(not(test), allow(dead_code))]
    pub flat_shared: bool,
}

pub(crate) struct CsvSpec {
    pub name: &'static str,
    pub extract: fn(&ExportRow) -> String,
}

pub(crate) struct ParquetSpec {
    pub name: &'static str,
    pub data_type: fn() -> DataType,
    pub nullable: bool,
}

fn utf8() -> DataType {
    DataType::Utf8
}
fn int32() -> DataType {
    DataType::Int32
}
fn int64() -> DataType {
    DataType::Int64
}
fn float64() -> DataType {
    DataType::Float64
}
fn boolean() -> DataType {
    DataType::Boolean
}

fn arrow_type_redirect_chain() -> DataType {
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(
            vec![
                Field::new("redirect_url", DataType::Utf8, false),
                Field::new("sequence_order", DataType::Int64, false),
            ]
            .into(),
        ),
        true,
    )))
}

fn arrow_type_technologies() -> DataType {
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(
            vec![
                Field::new("name", DataType::Utf8, false),
                Field::new("version", DataType::Utf8, true),
                Field::new("category", DataType::Utf8, true),
                Field::new("is_implied", DataType::Boolean, false),
            ]
            .into(),
        ),
        true,
    )))
}

fn arrow_type_certificate_sans() -> DataType {
    DataType::List(Arc::new(Field::new("item", DataType::Utf8, true)))
}

fn arrow_type_certificate_oids() -> DataType {
    DataType::List(Arc::new(Field::new("item", DataType::Utf8, true)))
}

fn arrow_type_cname_records() -> DataType {
    DataType::List(Arc::new(Field::new("item", DataType::Utf8, true)))
}

fn arrow_type_ipv6_addresses() -> DataType {
    DataType::List(Arc::new(Field::new("item", DataType::Utf8, true)))
}

fn arrow_type_caa_records() -> DataType {
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(
            vec![
                Field::new("flag", DataType::Int64, false),
                Field::new("tag", DataType::Utf8, false),
                Field::new("value", DataType::Utf8, false),
            ]
            .into(),
        ),
        true,
    )))
}

fn arrow_type_nameservers() -> DataType {
    DataType::List(Arc::new(Field::new("item", DataType::Utf8, true)))
}

fn arrow_type_txt_records() -> DataType {
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(
            vec![
                Field::new("record_type", DataType::Utf8, false),
                Field::new("content", DataType::Utf8, false),
            ]
            .into(),
        ),
        true,
    )))
}

fn arrow_type_mx_records() -> DataType {
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(
            vec![
                Field::new("priority", DataType::Int64, false),
                Field::new("mail_exchange", DataType::Utf8, false),
            ]
            .into(),
        ),
        true,
    )))
}

fn arrow_type_script_hosts() -> DataType {
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(
            vec![
                Field::new("host", DataType::Utf8, false),
                Field::new("registrable_domain", DataType::Utf8, true),
                Field::new("is_first_party", DataType::Boolean, false),
            ]
            .into(),
        ),
        true,
    )))
}

fn arrow_type_analytics_ids() -> DataType {
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(
            vec![
                Field::new("provider", DataType::Utf8, false),
                Field::new("tracking_id", DataType::Utf8, false),
            ]
            .into(),
        ),
        true,
    )))
}

fn arrow_type_social_media_links() -> DataType {
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(
            vec![
                Field::new("platform", DataType::Utf8, false),
                Field::new("url", DataType::Utf8, false),
                Field::new("identifier", DataType::Utf8, true),
            ]
            .into(),
        ),
        true,
    )))
}

fn arrow_type_structured_data() -> DataType {
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(
            vec![
                Field::new("data_type", DataType::Utf8, false),
                Field::new("property_name", DataType::Utf8, false),
                Field::new("property_value", DataType::Utf8, false),
            ]
            .into(),
        ),
        true,
    )))
}

fn arrow_type_http_headers() -> DataType {
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(
            vec![
                Field::new("name", DataType::Utf8, false),
                Field::new("value", DataType::Utf8, false),
            ]
            .into(),
        ),
        true,
    )))
}

fn arrow_type_security_headers() -> DataType {
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(
            vec![
                Field::new("name", DataType::Utf8, false),
                Field::new("value", DataType::Utf8, false),
            ]
            .into(),
        ),
        true,
    )))
}

fn arrow_type_partial_failures() -> DataType {
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(
            vec![
                Field::new("error_type", DataType::Utf8, false),
                Field::new("error_message", DataType::Utf8, false),
            ]
            .into(),
        ),
        true,
    )))
}

fn arrow_type_contact_links() -> DataType {
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(
            vec![
                Field::new("contact_type", DataType::Utf8, false),
                Field::new("contact_value", DataType::Utf8, false),
            ]
            .into(),
        ),
        true,
    )))
}

fn arrow_type_exposed_secrets() -> DataType {
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(
            vec![
                Field::new("secret_type", DataType::Utf8, false),
                Field::new("matched_value", DataType::Utf8, false),
                Field::new("severity", DataType::Utf8, false),
                Field::new("location", DataType::Utf8, false),
                Field::new("context", DataType::Utf8, true),
                Field::new("jwt_algorithm", DataType::Utf8, true),
                Field::new("jwt_issuer", DataType::Utf8, true),
                Field::new("jwt_subject", DataType::Utf8, true),
                Field::new("jwt_audience", DataType::Utf8, true),
                Field::new("jwt_expiration_ms", DataType::Int64, true),
                Field::new("jwt_issued_at_ms", DataType::Int64, true),
                Field::new("jwt_header_json", DataType::Utf8, true),
                Field::new("jwt_payload_json", DataType::Utf8, true),
            ]
            .into(),
        ),
        true,
    )))
}

/// Format a timestamp (milliseconds since epoch) as a date string.
fn format_date(ts_ms: Option<i64>) -> String {
    ts_ms
        .and_then(|ts| chrono::DateTime::from_timestamp(ts / 1000, 0))
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

fn format_caa_records(row: &ExportRow) -> String {
    row.caa_records
        .iter()
        .map(|r| format!("{}:{}:{}", r.flag, r.tag, r.value))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_nameservers(row: &ExportRow) -> String {
    row.nameservers
        .iter()
        .map(|ns| ns.nameserver.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn format_txt_records(row: &ExportRow) -> String {
    row.txt_records
        .iter()
        .map(|r| format!("{}|{}", r.record_type, r.record_value))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_mx_records(row: &ExportRow) -> String {
    row.mx_records
        .iter()
        .map(|r| format!("{}:{}", r.priority, r.mail_exchange))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_structured_data_entries(row: &ExportRow) -> String {
    row.structured_data_entries
        .iter()
        .map(|e| format!("{}|{}|{}", e.data_type, e.property_name, e.property_value))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_social_media_identifiers(row: &ExportRow) -> String {
    row.social_media_links
        .iter()
        .filter_map(|l| {
            l.identifier
                .as_ref()
                .map(|id| format!("{}:{}", l.platform, id))
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn format_partial_failures(row: &ExportRow) -> String {
    row.partial_failures
        .iter()
        .map(|f| format!("{}|{}", f.error_type, f.error_message))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_contact_links(row: &ExportRow) -> String {
    row.contact_links
        .iter()
        .map(|c| format!("{}:{}", c.contact_type, c.contact_value))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_exposed_secrets(row: &ExportRow) -> String {
    row.exposed_secrets
        .iter()
        .map(|s| {
            let base = format!(
                "[{}] {}|{}|{}",
                s.severity, s.secret_type, s.location, s.matched_value
            );
            match (&s.jwt_algorithm, &s.jwt_issuer) {
                (Some(alg), Some(iss)) => format!("{base}|alg={alg}|iss={iss}"),
                (Some(alg), None) => format!("{base}|alg={alg}"),
                (None, Some(iss)) => format!("{base}|iss={iss}"),
                (None, None) => base,
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Canonical export field registry (CSV order first, then Parquet-only).
#[allow(clippy::too_many_lines)] // One entry per export field; intentional registry
pub(crate) const EXPORT_FIELDS: &[ExportField] = &[
    ExportField {
        id: "url",
        csv: Some(CsvSpec {
            name: "url",
            extract: |row| build_url(&row.main.final_domain),
        }),
        parquet: Some(ParquetSpec {
            name: "url",
            data_type: utf8,
            nullable: false,
        }),
        jsonl_flat: Some(|row| json!(build_url(&row.main.final_domain))),
        flat_shared: true,
    },
    ExportField {
        id: "initial_domain",
        csv: Some(CsvSpec {
            name: "initial_domain",
            extract: |row| row.main.initial_domain.clone(),
        }),
        parquet: Some(ParquetSpec {
            name: "initial_domain",
            data_type: utf8,
            nullable: false,
        }),
        jsonl_flat: Some(|row| json!(row.main.initial_domain)),
        flat_shared: true,
    },
    ExportField {
        id: "final_domain",
        csv: Some(CsvSpec {
            name: "final_domain",
            extract: |row| row.main.final_domain.clone(),
        }),
        parquet: Some(ParquetSpec {
            name: "final_domain",
            data_type: utf8,
            nullable: false,
        }),
        jsonl_flat: Some(|row| json!(row.main.final_domain)),
        flat_shared: true,
    },
    ExportField {
        id: "initial_url",
        csv: Some(CsvSpec {
            name: "initial_url",
            extract: |row| row.main.initial_url.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "initial_url",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.initial_url)),
        flat_shared: true,
    },
    ExportField {
        id: "final_url",
        csv: Some(CsvSpec {
            name: "final_url",
            extract: |row| row.main.final_url.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "final_url",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.final_url)),
        flat_shared: true,
    },
    ExportField {
        id: "ip_address",
        csv: Some(CsvSpec {
            name: "ip_address",
            extract: |row| row.main.ip_address.clone(),
        }),
        parquet: Some(ParquetSpec {
            name: "ip_address",
            data_type: utf8,
            nullable: false,
        }),
        jsonl_flat: Some(|row| json!(row.main.ip_address)),
        flat_shared: true,
    },
    ExportField {
        id: "reverse_dns",
        csv: Some(CsvSpec {
            name: "reverse_dns",
            extract: |row| row.main.reverse_dns.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "reverse_dns",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.reverse_dns)),
        flat_shared: true,
    },
    ExportField {
        id: "status",
        csv: Some(CsvSpec {
            name: "status",
            extract: |row| row.main.status.to_string(),
        }),
        parquet: Some(ParquetSpec {
            name: "http_status",
            data_type: int32,
            nullable: false,
        }),
        jsonl_flat: Some(|row| json!(row.main.status)),
        flat_shared: true,
    },
    ExportField {
        id: "status_description",
        csv: Some(CsvSpec {
            name: "status_description",
            extract: |row| row.main.status_desc.clone(),
        }),
        parquet: Some(ParquetSpec {
            name: "http_status_text",
            data_type: utf8,
            nullable: false,
        }),
        jsonl_flat: Some(|row| json!(row.main.status_desc)),
        flat_shared: true,
    },
    ExportField {
        id: "response_time_ms",
        csv: Some(CsvSpec {
            name: "response_time_ms",
            extract: |row| format!("{:.2}", row.main.response_time),
        }),
        parquet: Some(ParquetSpec {
            name: "response_time_seconds",
            data_type: float64,
            nullable: false,
        }),
        jsonl_flat: Some(|row| json!(row.main.response_time)),
        flat_shared: true,
    },
    ExportField {
        id: "title",
        csv: Some(CsvSpec {
            name: "title",
            extract: |row| row.main.title.clone(),
        }),
        parquet: Some(ParquetSpec {
            name: "title",
            data_type: utf8,
            nullable: false,
        }),
        jsonl_flat: Some(|row| json!(row.main.title)),
        flat_shared: true,
    },
    ExportField {
        id: "description",
        csv: Some(CsvSpec {
            name: "description",
            extract: |row| row.main.description.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "description",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.description)),
        flat_shared: true,
    },
    ExportField {
        id: "meta_robots",
        csv: Some(CsvSpec {
            name: "meta_robots",
            extract: |row| row.main.meta_robots.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "meta_robots",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.meta_robots)),
        flat_shared: true,
    },
    ExportField {
        id: "body_sha256",
        csv: Some(CsvSpec {
            name: "body_sha256",
            extract: |row| row.main.body_sha256.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "body_sha256",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.body_sha256)),
        flat_shared: true,
    },
    ExportField {
        id: "content_length",
        csv: Some(CsvSpec {
            name: "content_length",
            extract: |row| {
                row.main
                    .content_length
                    .map_or(String::new(), |v| v.to_string())
            },
        }),
        parquet: Some(ParquetSpec {
            name: "content_length",
            data_type: int64,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.content_length)),
        flat_shared: true,
    },
    ExportField {
        id: "http_version",
        csv: Some(CsvSpec {
            name: "http_version",
            extract: |row| row.main.http_version.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "http_version",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.http_version)),
        flat_shared: true,
    },
    ExportField {
        id: "content_type",
        csv: Some(CsvSpec {
            name: "content_type",
            extract: |row| row.main.content_type.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "content_type",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.content_type)),
        flat_shared: true,
    },
    ExportField {
        id: "canonical_url",
        csv: Some(CsvSpec {
            name: "canonical_url",
            extract: |row| row.main.canonical_url.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "canonical_url",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.canonical_url)),
        flat_shared: true,
    },
    ExportField {
        id: "body_truncated",
        csv: Some(CsvSpec {
            name: "body_truncated",
            extract: |row| row.main.body_truncated.to_string(),
        }),
        parquet: Some(ParquetSpec {
            name: "body_truncated",
            data_type: boolean,
            nullable: false,
        }),
        jsonl_flat: Some(|row| json!(row.main.body_truncated)),
        flat_shared: true,
    },
    ExportField {
        id: "redirect_count",
        csv: Some(CsvSpec {
            name: "redirect_count",
            extract: |row| row.redirect_count.to_string(),
        }),
        parquet: Some(ParquetSpec {
            name: "redirect_count",
            data_type: int32,
            nullable: false,
        }),
        jsonl_flat: Some(|row| json!(row.redirect_count)),
        flat_shared: true,
    },
    ExportField {
        id: "final_redirect_url",
        csv: Some(CsvSpec {
            name: "final_redirect_url",
            extract: |row| row.final_redirect_url.clone(),
        }),
        parquet: Some(ParquetSpec {
            name: "final_redirect_url",
            data_type: utf8,
            nullable: false,
        }),
        jsonl_flat: Some(|row| json!(row.final_redirect_url)),
        flat_shared: true,
    },
    ExportField {
        id: "technologies",
        csv: Some(CsvSpec {
            name: "technologies",
            extract: |row| row.technologies_str.clone(),
        }),
        parquet: Some(ParquetSpec {
            name: "technologies",
            data_type: arrow_type_technologies,
            nullable: false,
        }),
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "technology_categories",
        csv: Some(CsvSpec {
            name: "technology_categories",
            extract: |row| row.technology_categories_str.clone(),
        }),
        parquet: None,
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "technology_count",
        csv: Some(CsvSpec {
            name: "technology_count",
            extract: |row| row.technology_count.to_string(),
        }),
        parquet: Some(ParquetSpec {
            name: "technology_count",
            data_type: int32,
            nullable: false,
        }),
        jsonl_flat: Some(|row| json!(row.technology_count)),
        flat_shared: true,
    },
    ExportField {
        id: "tls_version",
        csv: Some(CsvSpec {
            name: "tls_version",
            extract: |row| row.main.tls_version.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "tls_version",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "ssl_cert_subject",
        csv: Some(CsvSpec {
            name: "ssl_cert_subject",
            extract: |row| row.main.ssl_cert_subject.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "ssl_cert_subject",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "ssl_cert_issuer",
        csv: Some(CsvSpec {
            name: "ssl_cert_issuer",
            extract: |row| row.main.ssl_cert_issuer.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "ssl_cert_issuer",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "ssl_cert_valid_to",
        csv: Some(CsvSpec {
            name: "ssl_cert_valid_to",
            extract: |row| format_date(row.main.ssl_cert_valid_to_ms),
        }),
        parquet: Some(ParquetSpec {
            name: "ssl_cert_valid_to_ms",
            data_type: int64,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "cipher_suite",
        csv: Some(CsvSpec {
            name: "cipher_suite",
            extract: |row| row.main.cipher_suite.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "cipher_suite",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "key_algorithm",
        csv: Some(CsvSpec {
            name: "key_algorithm",
            extract: |row| row.main.key_algorithm.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "key_algorithm",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "cert_fingerprint_sha256",
        csv: Some(CsvSpec {
            name: "cert_fingerprint_sha256",
            extract: |row| row.main.cert_fingerprint_sha256.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "cert_fingerprint_sha256",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "certificate_sans",
        csv: Some(CsvSpec {
            name: "certificate_sans",
            extract: |row| row.certificate_sans_str.clone(),
        }),
        parquet: Some(ParquetSpec {
            name: "certificate_sans",
            data_type: arrow_type_certificate_sans,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "certificate_san_count",
        csv: Some(CsvSpec {
            name: "certificate_san_count",
            extract: |row| row.certificate_san_count.to_string(),
        }),
        parquet: None,
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "oids",
        csv: Some(CsvSpec {
            name: "oids",
            extract: |row| row.oids_str.clone(),
        }),
        parquet: Some(ParquetSpec {
            name: "certificate_oids",
            data_type: arrow_type_certificate_oids,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "oid_count",
        csv: Some(CsvSpec {
            name: "oid_count",
            extract: |row| row.oid_count.to_string(),
        }),
        parquet: None,
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "nameserver_count",
        csv: Some(CsvSpec {
            name: "nameserver_count",
            extract: |row| row.nameserver_count.to_string(),
        }),
        parquet: None,
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "txt_record_count",
        csv: Some(CsvSpec {
            name: "txt_record_count",
            extract: |row| row.txt_count.to_string(),
        }),
        parquet: None,
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "mx_record_count",
        csv: Some(CsvSpec {
            name: "mx_record_count",
            extract: |row| row.mx_count.to_string(),
        }),
        parquet: None,
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "cname_records",
        csv: Some(CsvSpec {
            name: "cname_records",
            extract: |row| row.cname_records.join(", "),
        }),
        parquet: Some(ParquetSpec {
            name: "cname_records",
            data_type: arrow_type_cname_records,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "cname_count",
        csv: Some(CsvSpec {
            name: "cname_count",
            extract: |row| row.cname_count.to_string(),
        }),
        parquet: None,
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "ipv6_addresses",
        csv: Some(CsvSpec {
            name: "ipv6_addresses",
            extract: |row| row.ipv6_addresses.join(", "),
        }),
        parquet: Some(ParquetSpec {
            name: "ipv6_addresses",
            data_type: arrow_type_ipv6_addresses,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "ipv6_count",
        csv: Some(CsvSpec {
            name: "ipv6_count",
            extract: |row| row.ipv6_count.to_string(),
        }),
        parquet: None,
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "caa_records",
        csv: Some(CsvSpec {
            name: "caa_records",
            extract: format_caa_records,
        }),
        parquet: Some(ParquetSpec {
            name: "caa_records",
            data_type: arrow_type_caa_records,
            nullable: false,
        }),
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "caa_count",
        csv: Some(CsvSpec {
            name: "caa_count",
            extract: |row| row.caa_count.to_string(),
        }),
        parquet: None,
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "spf_record",
        csv: Some(CsvSpec {
            name: "spf_record",
            extract: |row| row.main.spf_record.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "spf_record",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.spf_record)),
        flat_shared: true,
    },
    ExportField {
        id: "dmarc_record",
        csv: Some(CsvSpec {
            name: "dmarc_record",
            extract: |row| row.main.dmarc_record.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "dmarc_record",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.dmarc_record)),
        flat_shared: true,
    },
    ExportField {
        id: "mta_sts_record",
        csv: Some(CsvSpec {
            name: "mta_sts_record",
            extract: |row| row.main.mta_sts_record.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "mta_sts_record",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.mta_sts_record)),
        flat_shared: true,
    },
    ExportField {
        id: "tls_rpt_record",
        csv: Some(CsvSpec {
            name: "tls_rpt_record",
            extract: |row| row.main.tls_rpt_record.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "tls_rpt_record",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.tls_rpt_record)),
        flat_shared: true,
    },
    ExportField {
        id: "bimi_record",
        csv: Some(CsvSpec {
            name: "bimi_record",
            extract: |row| row.main.bimi_record.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "bimi_record",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.bimi_record)),
        flat_shared: true,
    },
    ExportField {
        id: "hsts_max_age",
        csv: Some(CsvSpec {
            name: "hsts_max_age",
            extract: |row| {
                row.main
                    .hsts_max_age
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            },
        }),
        parquet: Some(ParquetSpec {
            name: "hsts_max_age",
            data_type: int64,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.hsts_max_age)),
        flat_shared: true,
    },
    ExportField {
        id: "hsts_include_subdomains",
        csv: Some(CsvSpec {
            name: "hsts_include_subdomains",
            extract: |row| {
                row.main
                    .hsts_include_subdomains
                    .map(|v| i32::from(v).to_string())
                    .unwrap_or_default()
            },
        }),
        parquet: Some(ParquetSpec {
            name: "hsts_include_subdomains",
            data_type: boolean,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.hsts_include_subdomains)),
        flat_shared: true,
    },
    ExportField {
        id: "hsts_preload",
        csv: Some(CsvSpec {
            name: "hsts_preload",
            extract: |row| {
                row.main
                    .hsts_preload
                    .map(|v| i32::from(v).to_string())
                    .unwrap_or_default()
            },
        }),
        parquet: Some(ParquetSpec {
            name: "hsts_preload",
            data_type: boolean,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.hsts_preload)),
        flat_shared: true,
    },
    ExportField {
        id: "cdn_provider",
        csv: Some(CsvSpec {
            name: "cdn_provider",
            extract: |row| row.main.cdn_provider.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "cdn_provider",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.cdn_provider)),
        flat_shared: true,
    },
    ExportField {
        id: "script_hosts",
        csv: Some(CsvSpec {
            name: "script_hosts",
            extract: |row| row.script_hosts_str.clone(),
        }),
        parquet: Some(ParquetSpec {
            name: "script_hosts",
            data_type: arrow_type_script_hosts,
            nullable: false,
        }),
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "analytics_ids",
        csv: Some(CsvSpec {
            name: "analytics_ids",
            extract: |row| row.analytics_ids_str.clone(),
        }),
        parquet: Some(ParquetSpec {
            name: "analytics_ids",
            data_type: arrow_type_analytics_ids,
            nullable: false,
        }),
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "analytics_count",
        csv: Some(CsvSpec {
            name: "analytics_count",
            extract: |row| row.analytics_count.to_string(),
        }),
        parquet: None,
        jsonl_flat: Some(|row| json!(row.analytics_count)),
        flat_shared: false,
    },
    ExportField {
        id: "social_media_links",
        csv: Some(CsvSpec {
            name: "social_media_links",
            extract: |row| row.social_media_links_str.clone(),
        }),
        parquet: Some(ParquetSpec {
            name: "social_media_links",
            data_type: arrow_type_social_media_links,
            nullable: false,
        }),
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "social_media_count",
        csv: Some(CsvSpec {
            name: "social_media_count",
            extract: |row| row.social_media_count.to_string(),
        }),
        parquet: None,
        jsonl_flat: Some(|row| json!(row.social_media_count)),
        flat_shared: false,
    },
    ExportField {
        id: "structured_data_types",
        csv: Some(CsvSpec {
            name: "structured_data_types",
            extract: |row| row.structured_data_types_str.clone(),
        }),
        parquet: None,
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "structured_data_count",
        csv: Some(CsvSpec {
            name: "structured_data_count",
            extract: |row| row.structured_data_count.to_string(),
        }),
        parquet: None,
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "http_headers",
        csv: Some(CsvSpec {
            name: "http_headers",
            extract: |row| row.http_headers_str.clone(),
        }),
        parquet: Some(ParquetSpec {
            name: "http_headers",
            data_type: arrow_type_http_headers,
            nullable: false,
        }),
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "http_header_count",
        csv: Some(CsvSpec {
            name: "http_header_count",
            extract: |row| row.http_header_count.to_string(),
        }),
        parquet: None,
        jsonl_flat: Some(|row| json!(row.http_header_count)),
        flat_shared: false,
    },
    ExportField {
        id: "security_headers",
        csv: Some(CsvSpec {
            name: "security_headers",
            extract: |row| row.security_headers_str.clone(),
        }),
        parquet: Some(ParquetSpec {
            name: "security_headers",
            data_type: arrow_type_security_headers,
            nullable: false,
        }),
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "security_header_count",
        csv: Some(CsvSpec {
            name: "security_header_count",
            extract: |row| row.security_header_count.to_string(),
        }),
        parquet: None,
        jsonl_flat: Some(|row| json!(row.security_header_count)),
        flat_shared: false,
    },
    ExportField {
        id: "geoip_country_code",
        csv: Some(CsvSpec {
            name: "geoip_country_code",
            extract: |row| row.geoip.country_code.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "geoip_country_code",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "geoip_country_name",
        csv: Some(CsvSpec {
            name: "geoip_country_name",
            extract: |row| row.geoip.country_name.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "geoip_country_name",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "geoip_region",
        csv: Some(CsvSpec {
            name: "geoip_region",
            extract: |row| row.geoip.region.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "geoip_region",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "geoip_city",
        csv: Some(CsvSpec {
            name: "geoip_city",
            extract: |row| row.geoip.city.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "geoip_city",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "geoip_latitude",
        csv: Some(CsvSpec {
            name: "geoip_latitude",
            extract: |row| {
                row.geoip
                    .latitude
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            },
        }),
        parquet: Some(ParquetSpec {
            name: "geoip_latitude",
            data_type: float64,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "geoip_longitude",
        csv: Some(CsvSpec {
            name: "geoip_longitude",
            extract: |row| {
                row.geoip
                    .longitude
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            },
        }),
        parquet: Some(ParquetSpec {
            name: "geoip_longitude",
            data_type: float64,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "geoip_asn",
        csv: Some(CsvSpec {
            name: "geoip_asn",
            extract: |row| row.geoip.asn.map(|v| v.to_string()).unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "geoip_asn",
            data_type: int64,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "geoip_asn_org",
        csv: Some(CsvSpec {
            name: "geoip_asn_org",
            extract: |row| row.geoip.asn_org.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "geoip_asn_org",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "whois_registrar",
        csv: Some(CsvSpec {
            name: "whois_registrar",
            extract: |row| row.whois.registrar.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "whois_registrar",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "whois_creation_date",
        csv: Some(CsvSpec {
            name: "whois_creation_date",
            extract: |row| format_date(row.whois.creation_date_ms),
        }),
        parquet: Some(ParquetSpec {
            name: "whois_creation_date_ms",
            data_type: int64,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "whois_expiration_date",
        csv: Some(CsvSpec {
            name: "whois_expiration_date",
            extract: |row| format_date(row.whois.expiration_date_ms),
        }),
        parquet: Some(ParquetSpec {
            name: "whois_expiration_date_ms",
            data_type: int64,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "whois_registrant_country",
        csv: Some(CsvSpec {
            name: "whois_registrant_country",
            extract: |row| row.whois.registrant_country.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "whois_registrant_country",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "favicon_hash",
        csv: Some(CsvSpec {
            name: "favicon_hash",
            extract: |row| row.favicon_hash.map(|h| h.to_string()).unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "favicon_hash",
            data_type: int32,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "favicon_url",
        csv: Some(CsvSpec {
            name: "favicon_url",
            extract: |row| row.favicon_url.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "favicon_url",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: true,
    },
    ExportField {
        id: "timestamp",
        csv: Some(CsvSpec {
            name: "timestamp",
            extract: |row| row.main.timestamp.to_string(),
        }),
        parquet: Some(ParquetSpec {
            name: "observed_at_ms",
            data_type: int64,
            nullable: false,
        }),
        jsonl_flat: Some(|row| json!(row.main.timestamp)),
        flat_shared: true,
    },
    ExportField {
        id: "run_id",
        csv: Some(CsvSpec {
            name: "run_id",
            extract: |row| row.main.run_id.clone().unwrap_or_default(),
        }),
        parquet: Some(ParquetSpec {
            name: "run_id",
            data_type: utf8,
            nullable: true,
        }),
        jsonl_flat: Some(|row| json!(row.main.run_id)),
        flat_shared: true,
    },
    ExportField {
        id: "nameservers",
        csv: Some(CsvSpec {
            name: "nameservers",
            extract: format_nameservers,
        }),
        parquet: Some(ParquetSpec {
            name: "nameservers",
            data_type: arrow_type_nameservers,
            nullable: true,
        }),
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "txt_records",
        csv: Some(CsvSpec {
            name: "txt_records",
            extract: format_txt_records,
        }),
        parquet: Some(ParquetSpec {
            name: "txt_records",
            data_type: arrow_type_txt_records,
            nullable: false,
        }),
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "mx_records",
        csv: Some(CsvSpec {
            name: "mx_records",
            extract: format_mx_records,
        }),
        parquet: Some(ParquetSpec {
            name: "mx_records",
            data_type: arrow_type_mx_records,
            nullable: false,
        }),
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "structured_data_entries",
        csv: Some(CsvSpec {
            name: "structured_data_entries",
            extract: format_structured_data_entries,
        }),
        parquet: Some(ParquetSpec {
            name: "structured_data",
            data_type: arrow_type_structured_data,
            nullable: false,
        }),
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "social_media_identifiers",
        csv: Some(CsvSpec {
            name: "social_media_identifiers",
            extract: format_social_media_identifiers,
        }),
        parquet: None,
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "partial_failure_count",
        csv: Some(CsvSpec {
            name: "partial_failure_count",
            extract: |row| row.partial_failures.len().to_string(),
        }),
        parquet: None,
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "partial_failures",
        csv: Some(CsvSpec {
            name: "partial_failures",
            extract: format_partial_failures,
        }),
        parquet: Some(ParquetSpec {
            name: "partial_failures",
            data_type: arrow_type_partial_failures,
            nullable: false,
        }),
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "contact_links",
        csv: Some(CsvSpec {
            name: "contact_links",
            extract: format_contact_links,
        }),
        parquet: Some(ParquetSpec {
            name: "contact_links",
            data_type: arrow_type_contact_links,
            nullable: false,
        }),
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "contact_link_count",
        csv: Some(CsvSpec {
            name: "contact_link_count",
            extract: |row| row.contact_link_count.to_string(),
        }),
        parquet: Some(ParquetSpec {
            name: "contact_link_count",
            data_type: int32,
            nullable: false,
        }),
        jsonl_flat: Some(|row| json!(row.contact_link_count)),
        flat_shared: true,
    },
    ExportField {
        id: "exposed_secrets",
        csv: Some(CsvSpec {
            name: "exposed_secrets",
            extract: format_exposed_secrets,
        }),
        parquet: Some(ParquetSpec {
            name: "exposed_secrets",
            data_type: arrow_type_exposed_secrets,
            nullable: false,
        }),
        jsonl_flat: None,
        flat_shared: false,
    },
    ExportField {
        id: "exposed_secret_count",
        csv: Some(CsvSpec {
            name: "exposed_secret_count",
            extract: |row| row.exposed_secret_count.to_string(),
        }),
        parquet: Some(ParquetSpec {
            name: "exposed_secret_count",
            data_type: int32,
            nullable: false,
        }),
        jsonl_flat: Some(|row| json!(row.exposed_secret_count)),
        flat_shared: true,
    },
    ExportField {
        id: "redirect_chain",
        csv: None,
        parquet: Some(ParquetSpec {
            name: "redirect_chain",
            data_type: arrow_type_redirect_chain,
            nullable: false,
        }),
        jsonl_flat: None,
        flat_shared: false,
    },
];

/// CSV emission order (ids into [`EXPORT_FIELDS`]).
pub(crate) const CSV_FIELD_ORDER: &[&str] = &[
    "url",
    "initial_domain",
    "final_domain",
    "initial_url",
    "final_url",
    "ip_address",
    "reverse_dns",
    "status",
    "status_description",
    "response_time_ms",
    "title",
    "description",
    "meta_robots",
    "body_sha256",
    "content_length",
    "http_version",
    "content_type",
    "canonical_url",
    "body_truncated",
    "redirect_count",
    "final_redirect_url",
    "technologies",
    "technology_categories",
    "technology_count",
    "tls_version",
    "ssl_cert_subject",
    "ssl_cert_issuer",
    "ssl_cert_valid_to",
    "cipher_suite",
    "key_algorithm",
    "cert_fingerprint_sha256",
    "certificate_sans",
    "certificate_san_count",
    "oids",
    "oid_count",
    "nameserver_count",
    "txt_record_count",
    "mx_record_count",
    "cname_records",
    "cname_count",
    "ipv6_addresses",
    "ipv6_count",
    "caa_records",
    "caa_count",
    "spf_record",
    "dmarc_record",
    "mta_sts_record",
    "tls_rpt_record",
    "bimi_record",
    "hsts_max_age",
    "hsts_include_subdomains",
    "hsts_preload",
    "cdn_provider",
    "script_hosts",
    "analytics_ids",
    "analytics_count",
    "social_media_links",
    "social_media_count",
    "structured_data_types",
    "structured_data_count",
    "http_headers",
    "http_header_count",
    "security_headers",
    "security_header_count",
    "geoip_country_code",
    "geoip_country_name",
    "geoip_region",
    "geoip_city",
    "geoip_latitude",
    "geoip_longitude",
    "geoip_asn",
    "geoip_asn_org",
    "whois_registrar",
    "whois_creation_date",
    "whois_expiration_date",
    "whois_registrant_country",
    "favicon_hash",
    "favicon_url",
    "timestamp",
    "run_id",
    "nameservers",
    "txt_records",
    "mx_records",
    "structured_data_entries",
    "social_media_identifiers",
    "partial_failure_count",
    "partial_failures",
    "contact_links",
    "contact_link_count",
    "exposed_secrets",
    "exposed_secret_count",
];

/// Parquet column order (ids into [`EXPORT_FIELDS`]).
pub(crate) const PARQUET_FIELD_ORDER: &[&str] = &[
    "url",
    "initial_domain",
    "final_domain",
    "initial_url",
    "final_url",
    "ip_address",
    "reverse_dns",
    "status",
    "status_description",
    "response_time_ms",
    "title",
    "description",
    "meta_robots",
    "body_sha256",
    "content_length",
    "http_version",
    "content_type",
    "canonical_url",
    "body_truncated",
    "redirect_count",
    "final_redirect_url",
    "redirect_chain",
    "technology_count",
    "technologies",
    "tls_version",
    "ssl_cert_subject",
    "ssl_cert_issuer",
    "ssl_cert_valid_to",
    "cipher_suite",
    "key_algorithm",
    "cert_fingerprint_sha256",
    "certificate_sans",
    "oids",
    "cname_records",
    "ipv6_addresses",
    "caa_records",
    "spf_record",
    "dmarc_record",
    "mta_sts_record",
    "tls_rpt_record",
    "bimi_record",
    "hsts_max_age",
    "hsts_include_subdomains",
    "hsts_preload",
    "cdn_provider",
    "script_hosts",
    "nameservers",
    "txt_records",
    "mx_records",
    "analytics_ids",
    "social_media_links",
    "structured_data_entries",
    "http_headers",
    "security_headers",
    "partial_failures",
    "geoip_country_code",
    "geoip_country_name",
    "geoip_region",
    "geoip_city",
    "geoip_latitude",
    "geoip_longitude",
    "geoip_asn",
    "geoip_asn_org",
    "whois_registrar",
    "whois_creation_date",
    "whois_expiration_date",
    "whois_registrant_country",
    "favicon_hash",
    "favicon_url",
    "contact_link_count",
    "contact_links",
    "exposed_secret_count",
    "exposed_secrets",
    "timestamp",
    "run_id",
];

pub(crate) fn field_by_id(id: &str) -> &'static ExportField {
    EXPORT_FIELDS
        .iter()
        .find(|f| f.id == id)
        .unwrap_or_else(|| panic!("unknown export field id: {id}"))
}

pub(crate) fn csv_columns() -> impl Iterator<Item = (&'static str, fn(&ExportRow) -> String)> {
    CSV_FIELD_ORDER.iter().map(|id| {
        let f = field_by_id(id);
        let csv = f.csv.as_ref().expect("CSV_FIELD_ORDER entry missing csv");
        (csv.name, csv.extract)
    })
}

pub(crate) fn csv_column_names() -> impl Iterator<Item = &'static str> {
    csv_columns().map(|(name, _)| name)
}

pub(crate) fn csv_record_cells(row: &ExportRow) -> Vec<String> {
    csv_columns().map(|(_, extract)| extract(row)).collect()
}

pub(crate) fn build_parquet_schema() -> Schema {
    Schema::new(
        PARQUET_FIELD_ORDER
            .iter()
            .map(|id| {
                let f = field_by_id(id);
                let p = f
                    .parquet
                    .as_ref()
                    .expect("PARQUET_FIELD_ORDER entry missing parquet");
                Field::new(p.name, (p.data_type)(), p.nullable)
            })
            .collect::<Vec<_>>(),
    )
}

pub(crate) fn parquet_column_names() -> impl Iterator<Item = &'static str> {
    PARQUET_FIELD_ORDER.iter().map(|id| {
        field_by_id(id)
            .parquet
            .as_ref()
            .expect("PARQUET_FIELD_ORDER entry missing parquet")
            .name
    })
}

/// Insert registry-backed flat JSONL keys into `map`.
pub(crate) fn insert_jsonl_flat_fields(map: &mut serde_json::Map<String, Value>, row: &ExportRow) {
    for field in EXPORT_FIELDS {
        if let (Some(csv), Some(extract)) = (&field.csv, field.jsonl_flat) {
            map.insert(csv.name.to_string(), extract(row));
        } else if let Some(extract) = field.jsonl_flat {
            map.insert(field.id.to_string(), extract(row));
        }
    }
}

#[cfg(test)]
pub(crate) fn flat_shared_fields() -> impl Iterator<Item = &'static ExportField> {
    EXPORT_FIELDS.iter().filter(|f| f.flat_shared)
}
