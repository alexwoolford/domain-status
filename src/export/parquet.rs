//! Parquet export functionality.
//!
//! Exports domain_status data to Apache Parquet format (typed columnar format for analytics).
//! Multi-valued fields are stored as `List<Struct>` or `List<Utf8>` arrays.
//! This format is ideal for loading into DuckDB, Pandas, Spark, or any Arrow-compatible tool.

use anyhow::{bail, Context, Result};
use arrow::array::{
    ArrayRef, BooleanBuilder, Float64Builder, Int32Builder, Int64Builder, ListBuilder, RecordBatch,
    StringBuilder, StructBuilder,
};
use arrow::datatypes::{DataType, Field, Schema};
use futures::TryStreamExt;
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;
use std::fs::File;
use std::sync::Arc;

use crate::storage::init_db_pool_with_path;

use super::queries::build_export_query;
use super::row::{build_export_row, extract_main_row_data};

/// Batch size for collecting rows before writing a Parquet row group.
const BATCH_SIZE: usize = 10_000;

/// Build the Arrow schema for the Parquet file.
#[allow(clippy::too_many_lines)]
fn build_schema() -> Schema {
    Schema::new(vec![
        // Core identity
        Field::new("url", DataType::Utf8, false),
        Field::new("initial_domain", DataType::Utf8, false),
        Field::new("final_domain", DataType::Utf8, false),
        Field::new("ip_address", DataType::Utf8, false),
        Field::new("reverse_dns", DataType::Utf8, true),
        // HTTP response
        Field::new("http_status", DataType::Int32, false),
        Field::new("http_status_text", DataType::Utf8, false),
        Field::new("response_time_seconds", DataType::Float64, false),
        Field::new("title", DataType::Utf8, false),
        Field::new("keywords", DataType::Utf8, true),
        Field::new("description", DataType::Utf8, true),
        Field::new("is_mobile_friendly", DataType::Boolean, false),
        // Redirects
        Field::new("redirect_count", DataType::Int32, false),
        Field::new("final_redirect_url", DataType::Utf8, false),
        Field::new(
            "redirect_chain",
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
            ))),
            false,
        ),
        // Technologies
        Field::new("technology_count", DataType::Int32, false),
        Field::new(
            "technologies",
            DataType::List(Arc::new(Field::new(
                "item",
                DataType::Struct(
                    vec![
                        Field::new("name", DataType::Utf8, false),
                        Field::new("version", DataType::Utf8, true),
                    ]
                    .into(),
                ),
                true,
            ))),
            false,
        ),
        // TLS
        Field::new("tls_version", DataType::Utf8, true),
        Field::new("ssl_cert_subject", DataType::Utf8, true),
        Field::new("ssl_cert_issuer", DataType::Utf8, true),
        Field::new("ssl_cert_valid_to_ms", DataType::Int64, true),
        Field::new("cipher_suite", DataType::Utf8, true),
        Field::new("key_algorithm", DataType::Utf8, true),
        Field::new(
            "certificate_sans",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
            false,
        ),
        Field::new(
            "certificate_oids",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
            false,
        ),
        // DNS
        Field::new("spf_record", DataType::Utf8, true),
        Field::new("dmarc_record", DataType::Utf8, true),
        Field::new(
            "nameservers",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
            false,
        ),
        Field::new(
            "txt_records",
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
            ))),
            false,
        ),
        Field::new(
            "mx_records",
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
            ))),
            false,
        ),
        // Analytics
        Field::new(
            "analytics_ids",
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
            ))),
            false,
        ),
        // Social media
        Field::new(
            "social_media_links",
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
            ))),
            false,
        ),
        // Security
        Field::new(
            "security_warnings",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
            false,
        ),
        // Structured data
        Field::new(
            "structured_data",
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
            ))),
            false,
        ),
        // Headers
        Field::new(
            "http_headers",
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
            ))),
            false,
        ),
        Field::new(
            "security_headers",
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
            ))),
            false,
        ),
        // Partial failures
        Field::new(
            "partial_failures",
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
            ))),
            false,
        ),
        // GeoIP
        Field::new("geoip_country_code", DataType::Utf8, true),
        Field::new("geoip_country_name", DataType::Utf8, true),
        Field::new("geoip_region", DataType::Utf8, true),
        Field::new("geoip_city", DataType::Utf8, true),
        Field::new("geoip_latitude", DataType::Float64, true),
        Field::new("geoip_longitude", DataType::Float64, true),
        Field::new("geoip_asn", DataType::Int64, true),
        Field::new("geoip_asn_org", DataType::Utf8, true),
        // WHOIS
        Field::new("whois_registrar", DataType::Utf8, true),
        Field::new("whois_creation_date_ms", DataType::Int64, true),
        Field::new("whois_expiration_date_ms", DataType::Int64, true),
        Field::new("whois_registrant_country", DataType::Utf8, true),
        // Favicon
        Field::new("favicon_hash", DataType::Int32, true),
        Field::new("favicon_url", DataType::Utf8, true),
        // Contact links
        Field::new("contact_link_count", DataType::Int32, false),
        Field::new(
            "contact_links",
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
            ))),
            false,
        ),
        // Exposed secrets
        Field::new("exposed_secret_count", DataType::Int32, false),
        Field::new(
            "exposed_secrets",
            DataType::List(Arc::new(Field::new(
                "item",
                DataType::Struct(
                    vec![
                        Field::new("secret_type", DataType::Utf8, false),
                        Field::new("matched_value", DataType::Utf8, false),
                        Field::new("severity", DataType::Utf8, false),
                        Field::new("location", DataType::Utf8, false),
                        Field::new("context", DataType::Utf8, true),
                    ]
                    .into(),
                ),
                true,
            ))),
            false,
        ),
        // Metadata
        Field::new("observed_at_ms", DataType::Int64, false),
        Field::new("run_id", DataType::Utf8, true),
    ])
}

/// Helper to create a ListBuilder for List<Struct{Utf8, Utf8}> (two string fields).
fn new_two_string_list_builder(f1: &str, f2: &str) -> ListBuilder<StructBuilder> {
    let fields = vec![
        Field::new(f1, DataType::Utf8, false),
        Field::new(f2, DataType::Utf8, false),
    ];
    let builder = StructBuilder::new(
        fields.clone(),
        vec![
            Box::new(StringBuilder::new()),
            Box::new(StringBuilder::new()),
        ],
    );
    ListBuilder::new(builder)
}

/// Helper to create a ListBuilder for List<Struct{Utf8, Utf8, Utf8}> (three string fields).
fn new_three_string_list_builder(f1: &str, f2: &str, f3: &str) -> ListBuilder<StructBuilder> {
    let fields = vec![
        Field::new(f1, DataType::Utf8, false),
        Field::new(f2, DataType::Utf8, false),
        Field::new(f3, DataType::Utf8, false),
    ];
    let builder = StructBuilder::new(
        fields.clone(),
        vec![
            Box::new(StringBuilder::new()),
            Box::new(StringBuilder::new()),
            Box::new(StringBuilder::new()),
        ],
    );
    ListBuilder::new(builder)
}

use super::row::ExportRow;

/// Append an optional string to a StringBuilder.
fn append_opt_str(builder: &mut StringBuilder, value: &Option<String>) {
    match value {
        Some(v) => builder.append_value(v),
        None => builder.append_null(),
    }
}

/// Append an optional i64 to an Int64Builder.
fn append_opt_i64(builder: &mut Int64Builder, value: Option<i64>) {
    match value {
        Some(v) => builder.append_value(v),
        None => builder.append_null(),
    }
}

/// Append an optional f64 to a Float64Builder.
fn append_opt_f64(builder: &mut Float64Builder, value: Option<f64>) {
    match value {
        Some(v) => builder.append_value(v),
        None => builder.append_null(),
    }
}

/// Append an optional i32 to an Int32Builder.
fn append_opt_i32(builder: &mut Int32Builder, value: Option<i32>) {
    match value {
        Some(v) => builder.append_value(v),
        None => builder.append_null(),
    }
}

/// Write a batch of ExportRows as a RecordBatch to the Parquet writer.
#[allow(clippy::too_many_lines)]
fn write_batch(
    writer: &mut ArrowWriter<File>,
    schema: &Arc<Schema>,
    rows: &[ExportRow],
) -> Result<()> {
    // Scalar builders
    let mut url_b = StringBuilder::new();
    let mut initial_domain_b = StringBuilder::new();
    let mut final_domain_b = StringBuilder::new();
    let mut ip_address_b = StringBuilder::new();
    let mut reverse_dns_b = StringBuilder::new();
    let mut http_status_b = Int32Builder::new();
    let mut http_status_text_b = StringBuilder::new();
    let mut response_time_b = Float64Builder::new();
    let mut title_b = StringBuilder::new();
    let mut keywords_b = StringBuilder::new();
    let mut description_b = StringBuilder::new();
    let mut is_mobile_friendly_b = BooleanBuilder::new();
    let mut redirect_count_b = Int32Builder::new();
    let mut final_redirect_url_b = StringBuilder::new();
    let mut technology_count_b = Int32Builder::new();
    let mut tls_version_b = StringBuilder::new();
    let mut ssl_cert_subject_b = StringBuilder::new();
    let mut ssl_cert_issuer_b = StringBuilder::new();
    let mut ssl_cert_valid_to_b = Int64Builder::new();
    let mut cipher_suite_b = StringBuilder::new();
    let mut key_algorithm_b = StringBuilder::new();
    let mut spf_record_b = StringBuilder::new();
    let mut dmarc_record_b = StringBuilder::new();
    let mut geoip_cc_b = StringBuilder::new();
    let mut geoip_cn_b = StringBuilder::new();
    let mut geoip_region_b = StringBuilder::new();
    let mut geoip_city_b = StringBuilder::new();
    let mut geoip_lat_b = Float64Builder::new();
    let mut geoip_lon_b = Float64Builder::new();
    let mut geoip_asn_b = Int64Builder::new();
    let mut geoip_asn_org_b = StringBuilder::new();
    let mut whois_registrar_b = StringBuilder::new();
    let mut whois_creation_b = Int64Builder::new();
    let mut whois_expiration_b = Int64Builder::new();
    let mut whois_country_b = StringBuilder::new();
    let mut favicon_hash_b = Int32Builder::new();
    let mut favicon_url_b = StringBuilder::new();
    let mut contact_link_count_b = Int32Builder::new();
    let mut contact_links_b = new_two_string_list_builder("contact_type", "contact_value");
    let mut exposed_secret_count_b = Int32Builder::new();
    // 5-field struct: secret_type, matched_value, severity, location (non-nullable), context (nullable)
    let mut exposed_secrets_b = {
        let fields = vec![
            Field::new("secret_type", DataType::Utf8, false),
            Field::new("matched_value", DataType::Utf8, false),
            Field::new("severity", DataType::Utf8, false),
            Field::new("location", DataType::Utf8, false),
            Field::new("context", DataType::Utf8, true),
        ];
        let builder = StructBuilder::new(
            fields.clone(),
            vec![
                Box::new(StringBuilder::new()),
                Box::new(StringBuilder::new()),
                Box::new(StringBuilder::new()),
                Box::new(StringBuilder::new()),
                Box::new(StringBuilder::new()),
            ],
        );
        ListBuilder::new(builder)
    };
    let mut observed_at_b = Int64Builder::new();
    let mut run_id_b = StringBuilder::new();

    // List builders: redirect_chain List<Struct{Utf8, Int64}>
    let redirect_struct_fields = vec![
        Field::new("redirect_url", DataType::Utf8, false),
        Field::new("sequence_order", DataType::Int64, false),
    ];
    let redirect_struct_builder = StructBuilder::new(
        redirect_struct_fields,
        vec![
            Box::new(StringBuilder::new()),
            Box::new(Int64Builder::new()),
        ],
    );
    let mut redirect_chain_b = ListBuilder::new(redirect_struct_builder);

    // technologies List<Struct{Utf8, Utf8 nullable}>
    let tech_fields = vec![
        Field::new("name", DataType::Utf8, false),
        Field::new("version", DataType::Utf8, true),
    ];
    let tech_struct_builder = StructBuilder::new(
        tech_fields,
        vec![
            Box::new(StringBuilder::new()),
            Box::new(StringBuilder::new()),
        ],
    );
    let mut technologies_b = ListBuilder::new(tech_struct_builder);

    // Simple string lists
    let mut cert_sans_b = ListBuilder::new(StringBuilder::new());
    let mut cert_oids_b = ListBuilder::new(StringBuilder::new());
    let mut nameservers_b = ListBuilder::new(StringBuilder::new());
    let mut security_warnings_b = ListBuilder::new(StringBuilder::new());

    // txt_records List<Struct{Utf8, Utf8}>
    let mut txt_records_b = new_two_string_list_builder("record_type", "content");
    // mx_records List<Struct{Int64, Utf8}>
    let mx_fields = vec![
        Field::new("priority", DataType::Int64, false),
        Field::new("mail_exchange", DataType::Utf8, false),
    ];
    let mx_struct_builder = StructBuilder::new(
        mx_fields,
        vec![
            Box::new(Int64Builder::new()),
            Box::new(StringBuilder::new()),
        ],
    );
    let mut mx_records_b = ListBuilder::new(mx_struct_builder);

    // analytics_ids
    let mut analytics_ids_b = new_two_string_list_builder("provider", "tracking_id");
    // social_media_links List<Struct{Utf8, Utf8, Utf8 nullable}>
    let social_fields = vec![
        Field::new("platform", DataType::Utf8, false),
        Field::new("url", DataType::Utf8, false),
        Field::new("identifier", DataType::Utf8, true),
    ];
    let social_struct_builder = StructBuilder::new(
        social_fields,
        vec![
            Box::new(StringBuilder::new()),
            Box::new(StringBuilder::new()),
            Box::new(StringBuilder::new()),
        ],
    );
    let mut social_media_b = ListBuilder::new(social_struct_builder);

    // structured_data
    let mut structured_data_b =
        new_three_string_list_builder("data_type", "property_name", "property_value");
    // http_headers / security_headers
    let mut http_headers_b = new_two_string_list_builder("name", "value");
    let mut security_headers_b = new_two_string_list_builder("name", "value");
    // partial_failures
    let mut partial_failures_b = new_two_string_list_builder("error_type", "error_message");

    for row in rows {
        let url = super::row::build_url(&row.main.final_domain);
        url_b.append_value(&url);
        initial_domain_b.append_value(&row.main.initial_domain);
        final_domain_b.append_value(&row.main.final_domain);
        ip_address_b.append_value(&row.main.ip_address);
        append_opt_str(&mut reverse_dns_b, &row.main.reverse_dns);

        // SAFETY: HTTP status codes fit in i32 (max 599)
        #[allow(clippy::cast_possible_wrap)]
        http_status_b.append_value(row.main.status as i32);
        http_status_text_b.append_value(&row.main.status_desc);
        response_time_b.append_value(row.main.response_time);
        title_b.append_value(&row.main.title);
        append_opt_str(&mut keywords_b, &row.main.keywords);
        append_opt_str(&mut description_b, &row.main.description);
        is_mobile_friendly_b.append_value(row.main.is_mobile_friendly);

        // SAFETY: redirect_count is a small Vec length that fits in i32
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        redirect_count_b.append_value(row.redirect_count as i32);
        final_redirect_url_b.append_value(&row.final_redirect_url);

        // Redirect chain
        for r in &row.redirects {
            redirect_chain_b
                .values()
                .field_builder::<StringBuilder>(0)
                .unwrap()
                .append_value(&r.redirect_url);
            redirect_chain_b
                .values()
                .field_builder::<Int64Builder>(1)
                .unwrap()
                .append_value(r.sequence_order);
            redirect_chain_b.values().append(true);
        }
        redirect_chain_b.append(true);

        // Technologies
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        technology_count_b.append_value(row.technology_count as i32);
        let techs = super::row::parse_technologies(&row.technologies_str);
        for (name, version) in &techs {
            technologies_b
                .values()
                .field_builder::<StringBuilder>(0)
                .unwrap()
                .append_value(name);
            append_opt_str(
                technologies_b
                    .values()
                    .field_builder::<StringBuilder>(1)
                    .unwrap(),
                &version.clone(),
            );
            technologies_b.values().append(true);
        }
        technologies_b.append(true);

        // TLS
        append_opt_str(&mut tls_version_b, &row.main.tls_version);
        append_opt_str(&mut ssl_cert_subject_b, &row.main.ssl_cert_subject);
        append_opt_str(&mut ssl_cert_issuer_b, &row.main.ssl_cert_issuer);
        append_opt_i64(&mut ssl_cert_valid_to_b, row.main.ssl_cert_valid_to_ms);
        append_opt_str(&mut cipher_suite_b, &row.main.cipher_suite);
        append_opt_str(&mut key_algorithm_b, &row.main.key_algorithm);

        // Certificate SANs
        for san in super::row::parse_string_list(&row.certificate_sans_str) {
            cert_sans_b.values().append_value(&san);
        }
        cert_sans_b.append(true);

        // Certificate OIDs
        for oid in super::row::parse_string_list(&row.oids_str) {
            cert_oids_b.values().append_value(&oid);
        }
        cert_oids_b.append(true);

        // DNS
        append_opt_str(&mut spf_record_b, &row.main.spf_record);
        append_opt_str(&mut dmarc_record_b, &row.main.dmarc_record);

        // Nameservers
        for ns in &row.nameservers {
            nameservers_b.values().append_value(&ns.nameserver);
        }
        nameservers_b.append(true);

        // TXT records
        for txt in &row.txt_records {
            txt_records_b
                .values()
                .field_builder::<StringBuilder>(0)
                .unwrap()
                .append_value(&txt.record_type);
            txt_records_b
                .values()
                .field_builder::<StringBuilder>(1)
                .unwrap()
                .append_value(&txt.record_value);
            txt_records_b.values().append(true);
        }
        txt_records_b.append(true);

        // MX records
        for mx in &row.mx_records {
            mx_records_b
                .values()
                .field_builder::<Int64Builder>(0)
                .unwrap()
                .append_value(mx.priority);
            mx_records_b
                .values()
                .field_builder::<StringBuilder>(1)
                .unwrap()
                .append_value(&mx.mail_exchange);
            mx_records_b.values().append(true);
        }
        mx_records_b.append(true);

        // Analytics IDs
        let analytics = super::row::parse_key_value_pairs(&row.analytics_ids_str);
        for (provider, tracking_id) in &analytics {
            analytics_ids_b
                .values()
                .field_builder::<StringBuilder>(0)
                .unwrap()
                .append_value(provider);
            analytics_ids_b
                .values()
                .field_builder::<StringBuilder>(1)
                .unwrap()
                .append_value(tracking_id);
            analytics_ids_b.values().append(true);
        }
        analytics_ids_b.append(true);

        // Social media links
        for link in &row.social_media_links {
            social_media_b
                .values()
                .field_builder::<StringBuilder>(0)
                .unwrap()
                .append_value(&link.platform);
            social_media_b
                .values()
                .field_builder::<StringBuilder>(1)
                .unwrap()
                .append_value(&link.profile_url);
            append_opt_str(
                social_media_b
                    .values()
                    .field_builder::<StringBuilder>(2)
                    .unwrap(),
                &link.identifier,
            );
            social_media_b.values().append(true);
        }
        social_media_b.append(true);

        // Security warnings
        for w in super::row::parse_string_list(&row.security_warnings_str) {
            security_warnings_b.values().append_value(&w);
        }
        security_warnings_b.append(true);

        // Structured data
        for entry in &row.structured_data_entries {
            structured_data_b
                .values()
                .field_builder::<StringBuilder>(0)
                .unwrap()
                .append_value(&entry.data_type);
            structured_data_b
                .values()
                .field_builder::<StringBuilder>(1)
                .unwrap()
                .append_value(&entry.property_name);
            structured_data_b
                .values()
                .field_builder::<StringBuilder>(2)
                .unwrap()
                .append_value(&entry.property_value);
            structured_data_b.values().append(true);
        }
        structured_data_b.append(true);

        // HTTP headers
        for h in &row.all_http_headers {
            http_headers_b
                .values()
                .field_builder::<StringBuilder>(0)
                .unwrap()
                .append_value(&h.name);
            http_headers_b
                .values()
                .field_builder::<StringBuilder>(1)
                .unwrap()
                .append_value(&h.value);
            http_headers_b.values().append(true);
        }
        http_headers_b.append(true);

        // Security headers
        for h in &row.all_security_headers {
            security_headers_b
                .values()
                .field_builder::<StringBuilder>(0)
                .unwrap()
                .append_value(&h.name);
            security_headers_b
                .values()
                .field_builder::<StringBuilder>(1)
                .unwrap()
                .append_value(&h.value);
            security_headers_b.values().append(true);
        }
        security_headers_b.append(true);

        // Partial failures
        for f in &row.partial_failures {
            partial_failures_b
                .values()
                .field_builder::<StringBuilder>(0)
                .unwrap()
                .append_value(&f.error_type);
            partial_failures_b
                .values()
                .field_builder::<StringBuilder>(1)
                .unwrap()
                .append_value(&f.error_message);
            partial_failures_b.values().append(true);
        }
        partial_failures_b.append(true);

        // GeoIP
        append_opt_str(&mut geoip_cc_b, &row.geoip.country_code);
        append_opt_str(&mut geoip_cn_b, &row.geoip.country_name);
        append_opt_str(&mut geoip_region_b, &row.geoip.region);
        append_opt_str(&mut geoip_city_b, &row.geoip.city);
        append_opt_f64(&mut geoip_lat_b, row.geoip.latitude);
        append_opt_f64(&mut geoip_lon_b, row.geoip.longitude);
        append_opt_i64(&mut geoip_asn_b, row.geoip.asn);
        append_opt_str(&mut geoip_asn_org_b, &row.geoip.asn_org);

        // WHOIS
        append_opt_str(&mut whois_registrar_b, &row.whois.registrar);
        append_opt_i64(&mut whois_creation_b, row.whois.creation_date_ms);
        append_opt_i64(&mut whois_expiration_b, row.whois.expiration_date_ms);
        append_opt_str(&mut whois_country_b, &row.whois.registrant_country);

        // Favicon
        append_opt_i32(&mut favicon_hash_b, row.favicon_hash);
        append_opt_str(&mut favicon_url_b, &row.favicon_url);

        // Contact links
        #[allow(clippy::cast_possible_truncation)]
        contact_link_count_b.append_value(row.contact_link_count as i32);
        for c in &row.contact_links {
            contact_links_b
                .values()
                .field_builder::<StringBuilder>(0)
                .unwrap()
                .append_value(&c.contact_type);
            contact_links_b
                .values()
                .field_builder::<StringBuilder>(1)
                .unwrap()
                .append_value(&c.contact_value);
            contact_links_b.values().append(true);
        }
        contact_links_b.append(true);

        // Exposed secrets
        #[allow(clippy::cast_possible_truncation)]
        exposed_secret_count_b.append_value(row.exposed_secret_count as i32);
        for s in &row.exposed_secrets {
            exposed_secrets_b
                .values()
                .field_builder::<StringBuilder>(0)
                .unwrap()
                .append_value(&s.secret_type);
            exposed_secrets_b
                .values()
                .field_builder::<StringBuilder>(1)
                .unwrap()
                .append_value(&s.matched_value);
            exposed_secrets_b
                .values()
                .field_builder::<StringBuilder>(2)
                .unwrap()
                .append_value(&s.severity);
            exposed_secrets_b
                .values()
                .field_builder::<StringBuilder>(3)
                .unwrap()
                .append_value(&s.location);
            append_opt_str(
                exposed_secrets_b
                    .values()
                    .field_builder::<StringBuilder>(4)
                    .unwrap(),
                &s.context,
            );
            exposed_secrets_b.values().append(true);
        }
        exposed_secrets_b.append(true);

        // Metadata
        observed_at_b.append_value(row.main.timestamp);
        append_opt_str(&mut run_id_b, &row.main.run_id);
    }

    // Build arrays in schema order
    let columns: Vec<ArrayRef> = vec![
        Arc::new(url_b.finish()),
        Arc::new(initial_domain_b.finish()),
        Arc::new(final_domain_b.finish()),
        Arc::new(ip_address_b.finish()),
        Arc::new(reverse_dns_b.finish()),
        Arc::new(http_status_b.finish()),
        Arc::new(http_status_text_b.finish()),
        Arc::new(response_time_b.finish()),
        Arc::new(title_b.finish()),
        Arc::new(keywords_b.finish()),
        Arc::new(description_b.finish()),
        Arc::new(is_mobile_friendly_b.finish()),
        Arc::new(redirect_count_b.finish()),
        Arc::new(final_redirect_url_b.finish()),
        Arc::new(redirect_chain_b.finish()),
        Arc::new(technology_count_b.finish()),
        Arc::new(technologies_b.finish()),
        Arc::new(tls_version_b.finish()),
        Arc::new(ssl_cert_subject_b.finish()),
        Arc::new(ssl_cert_issuer_b.finish()),
        Arc::new(ssl_cert_valid_to_b.finish()),
        Arc::new(cipher_suite_b.finish()),
        Arc::new(key_algorithm_b.finish()),
        Arc::new(cert_sans_b.finish()),
        Arc::new(cert_oids_b.finish()),
        Arc::new(spf_record_b.finish()),
        Arc::new(dmarc_record_b.finish()),
        Arc::new(nameservers_b.finish()),
        Arc::new(txt_records_b.finish()),
        Arc::new(mx_records_b.finish()),
        Arc::new(analytics_ids_b.finish()),
        Arc::new(social_media_b.finish()),
        Arc::new(security_warnings_b.finish()),
        Arc::new(structured_data_b.finish()),
        Arc::new(http_headers_b.finish()),
        Arc::new(security_headers_b.finish()),
        Arc::new(partial_failures_b.finish()),
        Arc::new(geoip_cc_b.finish()),
        Arc::new(geoip_cn_b.finish()),
        Arc::new(geoip_region_b.finish()),
        Arc::new(geoip_city_b.finish()),
        Arc::new(geoip_lat_b.finish()),
        Arc::new(geoip_lon_b.finish()),
        Arc::new(geoip_asn_b.finish()),
        Arc::new(geoip_asn_org_b.finish()),
        Arc::new(whois_registrar_b.finish()),
        Arc::new(whois_creation_b.finish()),
        Arc::new(whois_expiration_b.finish()),
        Arc::new(whois_country_b.finish()),
        Arc::new(favicon_hash_b.finish()),
        Arc::new(favicon_url_b.finish()),
        Arc::new(contact_link_count_b.finish()),
        Arc::new(contact_links_b.finish()),
        Arc::new(exposed_secret_count_b.finish()),
        Arc::new(exposed_secrets_b.finish()),
        Arc::new(observed_at_b.finish()),
        Arc::new(run_id_b.finish()),
    ];

    let batch = RecordBatch::try_new(Arc::clone(schema), columns)
        .context("Failed to create RecordBatch")?;

    writer
        .write(&batch)
        .context("Failed to write RecordBatch to Parquet")?;

    Ok(())
}

/// Exports data to Parquet format.
///
/// Parquet preserves typed columns and nested arrays, making it the preferred
/// export when the downstream consumer is an analytics engine rather than a
/// spreadsheet.
///
/// # Arguments
///
/// * `opts` - Export options including database path, output, and filters
///
/// # Returns
///
/// Returns the number of records exported, or an error if export fails.
///
/// # Examples
///
/// ```no_run
/// use domain_status::export::{export_parquet, ExportFormat, ExportOptions};
/// use std::path::PathBuf;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let count = export_parquet(&ExportOptions {
///     db_path: PathBuf::from("./domain_status.db"),
///     output: Some(PathBuf::from("domains.parquet")),
///     format: ExportFormat::Parquet,
///     run_id: None,
///     domain: Some("example.com".to_string()),
///     status: None,
///     since: None,
/// })
/// .await?;
///
/// println!("exported {count} Parquet rows");
/// # Ok(())
/// # }
/// ```
pub async fn export_parquet(opts: &super::ExportOptions) -> Result<usize> {
    let output_path = opts.output.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Parquet is a binary format and cannot be written to stdout. Use --output <path> to specify a file."
        )
    })?;

    if output_path.as_os_str() == "-" {
        bail!("Parquet is a binary format and cannot be written to stdout. Use --output <path> to specify a file.");
    }

    let pool = init_db_pool_with_path(&opts.db_path, 5)
        .await
        .context("Failed to initialize database pool")?;

    let mut query_builder = build_export_query(
        opts.run_id.as_deref(),
        opts.domain.as_deref(),
        opts.status,
        opts.since,
    );

    let schema = Arc::new(build_schema());

    let props = WriterProperties::builder()
        .set_compression(Compression::SNAPPY)
        .build();

    let file =
        File::create(output_path).context(format!("Failed to create {}", output_path.display()))?;

    let mut writer = ArrowWriter::try_new(file, Arc::clone(&schema), Some(props))
        .context("Failed to create Parquet writer")?;

    let query = query_builder.build();
    let mut rows_stream = query.fetch(pool.as_ref());

    let mut batch_rows: Vec<ExportRow> = Vec::with_capacity(BATCH_SIZE);
    let mut record_count: usize = 0;

    while let Some(row) = rows_stream.try_next().await? {
        let main = extract_main_row_data(&row);
        let export_row = build_export_row(&pool, main).await?;
        batch_rows.push(export_row);

        if batch_rows.len() >= BATCH_SIZE {
            record_count += batch_rows.len();
            write_batch(&mut writer, &schema, &batch_rows)?;
            batch_rows.clear();
        }
    }

    // Flush remaining rows
    if !batch_rows.is_empty() {
        record_count += batch_rows.len();
        write_batch(&mut writer, &schema, &batch_rows)?;
    }

    writer.close().context("Failed to finalize Parquet file")?;

    Ok(record_count)
}

#[cfg(test)]
mod tests {
    use super::super::types::{ExportFormat, ExportOptions};
    use super::export_parquet;
    use crate::storage::migrations::run_migrations;
    use arrow::array::Array;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use sqlx::{Row, SqlitePool};
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

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

    async fn create_test_url_status(pool: &SqlitePool, domain: &str) -> i64 {
        create_test_run(pool, "test-run-1").await;
        sqlx::query(
            "INSERT INTO url_status (
                initial_domain, final_domain, ip_address, http_status, http_status_text,
                response_time_seconds, title, observed_at_ms, is_mobile_friendly, run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id",
        )
        .bind(domain)
        .bind(domain)
        .bind("192.0.2.1")
        .bind(200)
        .bind("OK")
        .bind(1.5f64)
        .bind("Test Page")
        .bind(1704067200000i64)
        .bind(true)
        .bind("test-run-1")
        .fetch_one(pool)
        .await
        .expect("Failed to insert test URL status")
        .get::<i64, _>(0)
    }

    #[tokio::test]
    async fn test_parquet_export_rejects_stdout() {
        let temp_db = NamedTempFile::new().expect("temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .unwrap();
        run_migrations(&pool).await.unwrap();
        drop(pool);

        let result = export_parquet(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: None, // stdout
            format: ExportFormat::Parquet,
            run_id: None,
            domain: None,
            status: None,
            since: None,
        })
        .await;

        assert!(result.is_err(), "Parquet to stdout should fail");
        assert!(
            result.unwrap_err().to_string().contains("binary format"),
            "Error should mention binary format"
        );
    }

    #[tokio::test]
    async fn test_parquet_export_rejects_dash_stdout() {
        let temp_db = NamedTempFile::new().expect("temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .unwrap();
        run_migrations(&pool).await.unwrap();
        drop(pool);

        let result = export_parquet(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: Some(PathBuf::from("-")),
            format: ExportFormat::Parquet,
            run_id: None,
            domain: None,
            status: None,
            since: None,
        })
        .await;

        assert!(result.is_err(), "Parquet to '-' (stdout) should fail");
    }

    #[tokio::test]
    async fn test_parquet_export_empty_database() {
        let temp_db = NamedTempFile::new().expect("temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .unwrap();
        run_migrations(&pool).await.unwrap();
        drop(pool);

        let temp_file = NamedTempFile::new().expect("temp output");
        let output_path = temp_file.path().to_path_buf();

        let count = export_parquet(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: Some(output_path.clone()),
            format: ExportFormat::Parquet,
            run_id: None,
            domain: None,
            status: None,
            since: None,
        })
        .await
        .expect("Should succeed on empty database");

        assert_eq!(count, 0, "Should export 0 records");

        // File should still be a valid (empty) Parquet file
        let file = std::fs::File::open(&output_path).expect("open");
        let reader =
            ParquetRecordBatchReaderBuilder::try_new(file).expect("Should parse as valid Parquet");
        let schema = reader.schema();
        assert!(
            schema.field_with_name("url").is_ok(),
            "Schema should contain 'url' column"
        );
        assert!(
            schema.field_with_name("nameservers").is_ok(),
            "Schema should contain 'nameservers' column"
        );
    }

    #[tokio::test]
    async fn test_parquet_export_round_trip() {
        let temp_db = NamedTempFile::new().expect("temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .unwrap();
        run_migrations(&pool).await.unwrap();

        let url_id = create_test_url_status(&pool, "example.com").await;

        // Add some satellite data
        sqlx::query("INSERT INTO url_nameservers (url_status_id, nameserver) VALUES (?, ?)")
            .bind(url_id)
            .bind("ns1.example.com")
            .execute(&pool)
            .await
            .unwrap();

        sqlx::query(
            "INSERT INTO url_technologies (url_status_id, technology_name, technology_version) VALUES (?, ?, ?)",
        )
        .bind(url_id)
        .bind("WordPress")
        .bind(Some("6.8"))
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO url_partial_failures (url_status_id, error_type, error_message, observed_at_ms, run_id) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(url_id)
        .bind("DNS error")
        .bind("NS timeout")
        .bind(1704067200000i64)
        .bind("test-run-1")
        .execute(&pool)
        .await
        .unwrap();

        drop(pool);

        let temp_file = NamedTempFile::new().expect("temp output");
        let output_path = temp_file.path().to_path_buf();

        let count = export_parquet(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: Some(output_path.clone()),
            format: ExportFormat::Parquet,
            run_id: None,
            domain: None,
            status: None,
            since: None,
        })
        .await
        .expect("Should export successfully");

        assert_eq!(count, 1, "Should export 1 record");

        // Read back and verify
        let file = std::fs::File::open(&output_path).expect("open");
        let builder = ParquetRecordBatchReaderBuilder::try_new(file).expect("parse Parquet");
        let mut reader = builder.build().expect("build reader");

        let batch = reader
            .next()
            .expect("Should have a batch")
            .expect("batch ok");
        assert_eq!(batch.num_rows(), 1);
        assert_eq!(
            batch.num_columns(),
            57,
            "Should have 57 columns matching schema"
        );

        // Verify the 'url' column
        let url_col = batch.column_by_name("url").expect("Should have url column");
        let url_arr = url_col
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .expect("url should be StringArray");
        assert_eq!(url_arr.value(0), "https://example.com");

        // Verify a nullable field
        let tls_col = batch
            .column_by_name("tls_version")
            .expect("Should have tls_version column");
        let tls_arr = tls_col
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .expect("tls_version should be StringArray");
        assert!(
            tls_arr.is_null(0),
            "tls_version should be null for our test data"
        );
    }

    #[tokio::test]
    async fn test_parquet_export_with_filter() {
        let temp_db = NamedTempFile::new().expect("temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .unwrap();
        run_migrations(&pool).await.unwrap();

        create_test_url_status(&pool, "example.com").await;
        create_test_url_status(&pool, "other.com").await;
        drop(pool);

        let temp_file = NamedTempFile::new().expect("temp output");
        let output_path = temp_file.path().to_path_buf();

        let count = export_parquet(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: Some(output_path.clone()),
            format: ExportFormat::Parquet,
            run_id: None,
            domain: Some("example.com".to_string()),
            status: None,
            since: None,
        })
        .await
        .expect("Should export with filter");

        assert_eq!(count, 1, "Filter should select only 1 record");
    }
}
