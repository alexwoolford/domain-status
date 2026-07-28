//! CSV export functionality.
//!
//! Exports `domain_status` data to CSV format (simplified, flattened view).
//! One row per URL with all related data flattened into columns.

use anyhow::{Context, Result};
use csv::Writer;
use futures::TryStreamExt;
use std::io::{self, Write};

use crate::storage::init_db_pool_with_path;
use crate::utils::IoErrorContext;

use super::queries::{build_export_query, IgnoreBrokenPipe};
use super::row::{build_export_row, build_url, extract_main_row_data, ExportRow};

/// One flat CSV column: name paired with its cell extractor.
///
/// Header and cell values are derived from the same table so adding/removing a
/// column is a single edit — order cannot drift between header and row writer.
pub(crate) struct CsvColumn {
    pub name: &'static str,
    pub extract: fn(&ExportRow) -> String,
}

/// Flat CSV columns (single source of truth for header + cells + inventory tests).
#[allow(clippy::too_many_lines)] // One entry per export column; intentional registry
pub(crate) const CSV_COLUMN_DEFS: &[CsvColumn] = &[
    CsvColumn {
        name: "url",
        extract: |row| build_url(&row.main.final_domain),
    },
    CsvColumn {
        name: "initial_domain",
        extract: |row| row.main.initial_domain.clone(),
    },
    CsvColumn {
        name: "final_domain",
        extract: |row| row.main.final_domain.clone(),
    },
    CsvColumn {
        name: "initial_url",
        extract: |row| row.main.initial_url.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "final_url",
        extract: |row| row.main.final_url.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "ip_address",
        extract: |row| row.main.ip_address.clone(),
    },
    CsvColumn {
        name: "reverse_dns",
        extract: |row| row.main.reverse_dns.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "status",
        extract: |row| row.main.status.to_string(),
    },
    CsvColumn {
        name: "status_description",
        extract: |row| row.main.status_desc.clone(),
    },
    CsvColumn {
        name: "response_time_ms",
        extract: |row| format!("{:.2}", row.main.response_time),
    },
    CsvColumn {
        name: "title",
        extract: |row| row.main.title.clone(),
    },
    CsvColumn {
        name: "keywords",
        extract: |row| row.main.keywords.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "description",
        extract: |row| row.main.description.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "meta_robots",
        extract: |row| row.main.meta_robots.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "is_mobile_friendly",
        extract: |row| row.main.is_mobile_friendly.to_string(),
    },
    CsvColumn {
        name: "body_sha256",
        extract: |row| row.main.body_sha256.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "content_length",
        extract: |row| {
            row.main
                .content_length
                .map_or(String::new(), |v| v.to_string())
        },
    },
    CsvColumn {
        name: "http_version",
        extract: |row| row.main.http_version.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "body_word_count",
        extract: |row| {
            row.main
                .body_word_count
                .map_or(String::new(), |v| v.to_string())
        },
    },
    CsvColumn {
        name: "body_line_count",
        extract: |row| {
            row.main
                .body_line_count
                .map_or(String::new(), |v| v.to_string())
        },
    },
    CsvColumn {
        name: "content_type",
        extract: |row| row.main.content_type.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "canonical_url",
        extract: |row| row.main.canonical_url.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "body_truncated",
        extract: |row| row.main.body_truncated.to_string(),
    },
    CsvColumn {
        name: "redirect_count",
        extract: |row| row.redirect_count.to_string(),
    },
    CsvColumn {
        name: "final_redirect_url",
        extract: |row| row.final_redirect_url.clone(),
    },
    CsvColumn {
        name: "technologies",
        extract: |row| row.technologies_str.clone(),
    },
    CsvColumn {
        name: "technology_categories",
        extract: |row| row.technology_categories_str.clone(),
    },
    CsvColumn {
        name: "technology_count",
        extract: |row| row.technology_count.to_string(),
    },
    CsvColumn {
        name: "tls_version",
        extract: |row| row.main.tls_version.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "ssl_cert_subject",
        extract: |row| row.main.ssl_cert_subject.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "ssl_cert_issuer",
        extract: |row| row.main.ssl_cert_issuer.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "ssl_cert_valid_to",
        extract: |row| format_date(row.main.ssl_cert_valid_to_ms),
    },
    CsvColumn {
        name: "cipher_suite",
        extract: |row| row.main.cipher_suite.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "key_algorithm",
        extract: |row| row.main.key_algorithm.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "cert_fingerprint_sha256",
        extract: |row| row.main.cert_fingerprint_sha256.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "certificate_sans",
        extract: |row| row.certificate_sans_str.clone(),
    },
    CsvColumn {
        name: "certificate_san_count",
        extract: |row| row.certificate_san_count.to_string(),
    },
    CsvColumn {
        name: "oids",
        extract: |row| row.oids_str.clone(),
    },
    CsvColumn {
        name: "oid_count",
        extract: |row| row.oid_count.to_string(),
    },
    CsvColumn {
        name: "nameserver_count",
        extract: |row| row.nameserver_count.to_string(),
    },
    CsvColumn {
        name: "txt_record_count",
        extract: |row| row.txt_count.to_string(),
    },
    CsvColumn {
        name: "mx_record_count",
        extract: |row| row.mx_count.to_string(),
    },
    CsvColumn {
        name: "cname_records",
        extract: |row| row.cname_records.join(", "),
    },
    CsvColumn {
        name: "cname_count",
        extract: |row| row.cname_count.to_string(),
    },
    CsvColumn {
        name: "ipv6_addresses",
        extract: |row| row.ipv6_addresses.join(", "),
    },
    CsvColumn {
        name: "ipv6_count",
        extract: |row| row.ipv6_count.to_string(),
    },
    CsvColumn {
        name: "caa_records",
        extract: format_caa_records,
    },
    CsvColumn {
        name: "caa_count",
        extract: |row| row.caa_count.to_string(),
    },
    CsvColumn {
        name: "spf_record",
        extract: |row| row.main.spf_record.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "dmarc_record",
        extract: |row| row.main.dmarc_record.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "analytics_ids",
        extract: |row| row.analytics_ids_str.clone(),
    },
    CsvColumn {
        name: "analytics_count",
        extract: |row| row.analytics_count.to_string(),
    },
    CsvColumn {
        name: "social_media_links",
        extract: |row| row.social_media_links_str.clone(),
    },
    CsvColumn {
        name: "social_media_count",
        extract: |row| row.social_media_count.to_string(),
    },
    CsvColumn {
        name: "security_warnings",
        extract: |row| row.security_warnings_str.clone(),
    },
    CsvColumn {
        name: "security_warning_count",
        extract: |row| row.security_warning_count.to_string(),
    },
    CsvColumn {
        name: "structured_data_types",
        extract: |row| row.structured_data_types_str.clone(),
    },
    CsvColumn {
        name: "structured_data_count",
        extract: |row| row.structured_data_count.to_string(),
    },
    CsvColumn {
        name: "http_headers",
        extract: |row| row.http_headers_str.clone(),
    },
    CsvColumn {
        name: "http_header_count",
        extract: |row| row.http_header_count.to_string(),
    },
    CsvColumn {
        name: "security_headers",
        extract: |row| row.security_headers_str.clone(),
    },
    CsvColumn {
        name: "security_header_count",
        extract: |row| row.security_header_count.to_string(),
    },
    CsvColumn {
        name: "geoip_country_code",
        extract: |row| row.geoip.country_code.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "geoip_country_name",
        extract: |row| row.geoip.country_name.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "geoip_region",
        extract: |row| row.geoip.region.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "geoip_city",
        extract: |row| row.geoip.city.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "geoip_latitude",
        extract: |row| {
            row.geoip
                .latitude
                .map(|v| v.to_string())
                .unwrap_or_default()
        },
    },
    CsvColumn {
        name: "geoip_longitude",
        extract: |row| {
            row.geoip
                .longitude
                .map(|v| v.to_string())
                .unwrap_or_default()
        },
    },
    CsvColumn {
        name: "geoip_asn",
        extract: |row| row.geoip.asn.map(|v| v.to_string()).unwrap_or_default(),
    },
    CsvColumn {
        name: "geoip_asn_org",
        extract: |row| row.geoip.asn_org.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "whois_registrar",
        extract: |row| row.whois.registrar.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "whois_creation_date",
        extract: |row| format_date(row.whois.creation_date_ms),
    },
    CsvColumn {
        name: "whois_expiration_date",
        extract: |row| format_date(row.whois.expiration_date_ms),
    },
    CsvColumn {
        name: "whois_registrant_country",
        extract: |row| row.whois.registrant_country.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "favicon_hash",
        extract: |row| row.favicon_hash.map(|h| h.to_string()).unwrap_or_default(),
    },
    CsvColumn {
        name: "favicon_url",
        extract: |row| row.favicon_url.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "timestamp",
        extract: |row| row.main.timestamp.to_string(),
    },
    CsvColumn {
        name: "run_id",
        extract: |row| row.main.run_id.clone().unwrap_or_default(),
    },
    CsvColumn {
        name: "nameservers",
        extract: format_nameservers,
    },
    CsvColumn {
        name: "txt_records",
        extract: format_txt_records,
    },
    CsvColumn {
        name: "mx_records",
        extract: format_mx_records,
    },
    CsvColumn {
        name: "structured_data_entries",
        extract: format_structured_data_entries,
    },
    CsvColumn {
        name: "social_media_identifiers",
        extract: format_social_media_identifiers,
    },
    CsvColumn {
        name: "partial_failure_count",
        extract: |row| row.partial_failures.len().to_string(),
    },
    CsvColumn {
        name: "partial_failures",
        extract: format_partial_failures,
    },
    CsvColumn {
        name: "contact_links",
        extract: format_contact_links,
    },
    CsvColumn {
        name: "contact_link_count",
        extract: |row| row.contact_link_count.to_string(),
    },
    CsvColumn {
        name: "exposed_secrets",
        extract: format_exposed_secrets,
    },
    CsvColumn {
        name: "exposed_secret_count",
        extract: |row| row.exposed_secret_count.to_string(),
    },
];

/// Column names derived from [`CSV_COLUMN_DEFS`] (same order as cell extractors).
pub(crate) fn csv_column_names() -> impl Iterator<Item = &'static str> {
    CSV_COLUMN_DEFS.iter().map(|c| c.name)
}

fn csv_record_cells(row: &ExportRow) -> Vec<String> {
    CSV_COLUMN_DEFS.iter().map(|c| (c.extract)(row)).collect()
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

/// Exports data to CSV format.
///
/// CSV output flattens multi-valued relationships into delimited string columns so
/// the result is easy to open in spreadsheet tools.
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
/// use domain_status::export::{export_csv, ExportFormat, ExportOptions};
/// use std::path::PathBuf;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let count = export_csv(&ExportOptions {
///     db_path: PathBuf::from("./domain_status.db"),
///     output: Some(PathBuf::from("domains.csv")),
///     format: ExportFormat::Csv,
///     run_id: None,
///     domain: None,
///     status: Some(200),
///     since: None,
///     include_implied_tech: false,
/// })
/// .await?;
///
/// println!("exported {count} CSV rows");
/// # Ok(())
/// # }
/// ```
///
/// # Errors
/// Returns `Err` when the database pool cannot be created, the query fails, or writing the output fails.
pub async fn export_csv(opts: &super::ExportOptions) -> Result<usize> {
    let pool = init_db_pool_with_path(&opts.db_path, 5)
        .await
        .context("Failed to initialize database pool")?;

    let mut query_builder = build_export_query(
        opts.run_id.as_deref(),
        opts.domain.as_deref(),
        opts.status,
        opts.since,
    );

    let mut writer: Writer<Box<dyn Write>> = if let Some(output_path) = opts.output.as_ref() {
        let file = tokio::fs::File::create(output_path)
            .await
            .with_path(output_path)?
            .into_std()
            .await;
        Writer::from_writer(Box::new(file) as Box<dyn Write>)
    } else {
        Writer::from_writer(Box::new(IgnoreBrokenPipe::new(io::stdout())) as Box<dyn Write>)
    };

    writer.write_record(csv_column_names().collect::<Vec<_>>())?;

    let query = query_builder.build();
    let mut rows = query.fetch(pool.as_ref());

    let mut record_count = 0;

    while let Some(row) = rows.try_next().await? {
        let main = extract_main_row_data(&row);
        let export_row = build_export_row(&pool, main, opts.include_implied_tech).await?;
        writer.write_record(csv_record_cells(&export_row))?;
        record_count += 1;
    }

    writer.flush()?;

    Ok(record_count)
}

#[cfg(test)]
mod tests {
    use super::super::queries::{
        fetch_count_query, fetch_filtered_http_headers, fetch_key_value_list, fetch_string_list,
        HttpHeadersTable,
    };
    use crate::storage::{migrations::run_migrations, DbPool};
    use sqlx::{Row, SqlitePool};
    use std::sync::Arc;
    use tempfile::NamedTempFile;

    async fn create_test_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");
        pool
    }

    async fn create_test_url_status_default(pool: &SqlitePool) -> i64 {
        sqlx::query(
            "INSERT INTO url_status (
                initial_domain, final_domain, ip_address, http_status, http_status_text,
                response_time_seconds, title, observed_at_ms, is_mobile_friendly
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id",
        )
        .bind("example.com")
        .bind("example.com")
        .bind("192.0.2.1")
        .bind(200)
        .bind("OK")
        .bind(1.5f64)
        .bind("Test Page")
        .bind(1704067200000i64)
        .bind(true)
        .fetch_one(pool)
        .await
        .expect("Failed to insert test URL status")
        .get::<i64, _>(0)
    }

    #[tokio::test]
    async fn test_fetch_string_list_empty() {
        let pool = create_test_pool().await;
        let pool_arc: DbPool = Arc::new(pool);
        let url_id = create_test_url_status_default(pool_arc.as_ref()).await;

        // Query with no results
        let (joined, count) = fetch_string_list(
            &pool_arc,
            "SELECT technology_name FROM url_technologies WHERE url_status_id = ?",
            url_id + 999, // Non-existent ID
        )
        .await
        .expect("Should not error on empty result");

        assert_eq!(joined, "", "Empty result should return empty string");
        assert_eq!(count, 0, "Empty result should return count 0");
    }

    #[tokio::test]
    async fn test_fetch_string_list_single() {
        let pool = create_test_pool().await;
        let pool_arc: DbPool = Arc::new(pool);
        let url_id = create_test_url_status_default(pool_arc.as_ref()).await;

        sqlx::query("INSERT INTO url_technologies (url_status_id, technology_name, technology_version) VALUES (?, ?, ?)")
            .bind(url_id)
            .bind("nginx")
            .bind::<Option<String>>(None)
            .execute(pool_arc.as_ref())
            .await
            .expect("Failed to insert technology");

        let (joined, count) = fetch_string_list(
            &pool_arc,
            "SELECT CASE WHEN technology_version IS NOT NULL THEN technology_name || ':' || technology_version ELSE technology_name END as technology_name FROM url_technologies WHERE url_status_id = ? ORDER BY technology_name, technology_version",
            url_id,
        )
        .await
        .expect("Should fetch single item");

        assert_eq!(joined, "nginx", "Single item should be returned as-is");
        assert_eq!(count, 1, "Should return count 1");
    }

    #[tokio::test]
    async fn test_fetch_string_list_multiple() {
        let pool = create_test_pool().await;
        let pool_arc: DbPool = Arc::new(pool);
        let url_id = create_test_url_status_default(pool_arc.as_ref()).await;

        for tech in ["nginx", "PHP", "WordPress"] {
            sqlx::query(
                "INSERT INTO url_technologies (url_status_id, technology_name, technology_version) VALUES (?, ?, ?)",
            )
            .bind(url_id)
            .bind(tech)
            .bind::<Option<String>>(None)
            .execute(pool_arc.as_ref())
            .await
            .expect("Failed to insert technology");
        }

        let (joined, count) = fetch_string_list(
            &pool_arc,
            "SELECT CASE WHEN technology_version IS NOT NULL THEN technology_name || ':' || technology_version ELSE technology_name END as technology_name FROM url_technologies WHERE url_status_id = ? ORDER BY technology_name, technology_version",
            url_id,
        )
        .await
        .expect("Should fetch multiple items");

        assert_eq!(count, 3, "Should return count 3");
        // Order should be alphabetical: nginx, PHP, WordPress
        // But SQLite string comparison may differ, so just verify all items are present
        assert!(joined.contains("nginx"), "Should contain nginx");
        assert!(joined.contains("PHP"), "Should contain PHP");
        assert!(joined.contains("WordPress"), "Should contain WordPress");
        assert_eq!(
            joined.matches(',').count(),
            2,
            "Should have 2 commas (3 items)"
        );
    }

    #[tokio::test]
    async fn test_fetch_string_list_special_characters() {
        let pool = create_test_pool().await;
        let pool_arc: DbPool = Arc::new(pool);
        let url_id = create_test_url_status_default(pool_arc.as_ref()).await;

        // Test with commas, quotes, and other special characters
        sqlx::query("INSERT INTO url_technologies (url_status_id, technology_name, technology_version) VALUES (?, ?, ?)")
            .bind(url_id)
            .bind("Tech, with \"quotes\"")
            .bind::<Option<String>>(None)
            .execute(pool_arc.as_ref())
            .await
            .expect("Failed to insert technology");

        let (joined, count) = fetch_string_list(
            &pool_arc,
            "SELECT technology_name FROM url_technologies WHERE url_status_id = ?",
            url_id,
        )
        .await
        .expect("Should handle special characters");

        assert_eq!(count, 1, "Should return count 1");
        assert_eq!(
            joined, "Tech, with \"quotes\"",
            "Special characters should be preserved"
        );
    }

    #[tokio::test]
    async fn test_fetch_count_query_zero() {
        let pool = create_test_pool().await;
        let pool_arc: DbPool = Arc::new(pool);
        let url_id = create_test_url_status_default(pool_arc.as_ref()).await;

        let count = fetch_count_query(
            &pool_arc,
            "SELECT COUNT(*) FROM url_technologies WHERE url_status_id = ?",
            url_id + 999, // Non-existent ID
        )
        .await
        .expect("Should not error on zero count");

        assert_eq!(count, 0, "Non-existent ID should return count 0");
    }

    #[tokio::test]
    async fn test_fetch_count_query_multiple() {
        let pool = create_test_pool().await;
        let pool_arc: DbPool = Arc::new(pool);
        let url_id = create_test_url_status_default(pool_arc.as_ref()).await;

        for i in 0..5 {
            sqlx::query(
                "INSERT INTO url_technologies (url_status_id, technology_name, technology_version) VALUES (?, ?, ?)",
            )
            .bind(url_id)
            .bind(format!("tech_{}", i))
            .bind::<Option<String>>(None)
            .execute(pool_arc.as_ref())
            .await
            .expect("Failed to insert technology");
        }

        let count = fetch_count_query(
            &pool_arc,
            "SELECT COUNT(*) FROM url_technologies WHERE url_status_id = ?",
            url_id,
        )
        .await
        .expect("Should count multiple items");

        assert_eq!(count, 5, "Should return count 5");
    }

    #[tokio::test]
    async fn test_fetch_key_value_list_empty() {
        let pool = create_test_pool().await;
        let pool_arc: DbPool = Arc::new(pool);
        let url_id = create_test_url_status_default(pool_arc.as_ref()).await;

        let (joined, count) = fetch_key_value_list(
            &pool_arc,
            "SELECT provider, tracking_id FROM url_analytics_ids WHERE url_status_id = ?",
            "provider",
            "tracking_id",
            url_id + 999, // Non-existent ID
        )
        .await
        .expect("Should not error on empty result");

        assert_eq!(joined, "", "Empty result should return empty string");
        assert_eq!(count, 0, "Empty result should return count 0");
    }

    #[tokio::test]
    async fn test_fetch_key_value_list_multiple() {
        let pool = create_test_pool().await;
        let pool_arc: DbPool = Arc::new(pool);
        let url_id = create_test_url_status_default(pool_arc.as_ref()).await;

        sqlx::query(
            "INSERT INTO url_analytics_ids (url_status_id, provider, tracking_id) VALUES (?, ?, ?)",
        )
        .bind(url_id)
        .bind("Google Analytics")
        .bind("UA-123-1")
        .execute(pool_arc.as_ref())
        .await
        .expect("Failed to insert analytics ID");

        sqlx::query(
            "INSERT INTO url_analytics_ids (url_status_id, provider, tracking_id) VALUES (?, ?, ?)",
        )
        .bind(url_id)
        .bind("Google Tag Manager")
        .bind("GTM-XXXXX")
        .execute(pool_arc.as_ref())
        .await
        .expect("Failed to insert analytics ID");

        let (joined, count) = fetch_key_value_list(
            &pool_arc,
            "SELECT provider, tracking_id FROM url_analytics_ids WHERE url_status_id = ? ORDER BY provider",
            "provider",
            "tracking_id",
            url_id,
        )
        .await
        .expect("Should fetch key-value pairs");

        assert_eq!(count, 2, "Should return count 2");
        // Order should be Google Analytics, Google Tag Manager (alphabetical)
        assert!(
            joined.contains("Google Analytics:UA-123-1"),
            "Should contain first pair"
        );
        assert!(
            joined.contains("Google Tag Manager:GTM-XXXXX"),
            "Should contain second pair"
        );
        assert!(joined.contains(","), "Pairs should be comma-separated");
    }

    #[tokio::test]
    async fn test_fetch_filtered_http_headers_empty() {
        let pool = create_test_pool().await;
        let pool_arc: DbPool = Arc::new(pool);
        let url_id = create_test_url_status_default(pool_arc.as_ref()).await;

        let (joined, total_count) = fetch_filtered_http_headers(
            &pool_arc,
            HttpHeadersTable::Standard,
            url_id + 999, // Non-existent ID
            &["Content-Type", "Server"],
        )
        .await
        .expect("Should not error on empty result");

        assert_eq!(joined, "", "Empty result should return empty string");
        assert_eq!(total_count, 0, "Empty result should return total count 0");
    }

    #[tokio::test]
    async fn test_fetch_filtered_http_headers_filtering() {
        let pool = create_test_pool().await;
        let pool_arc: DbPool = Arc::new(pool);
        let url_id = create_test_url_status_default(pool_arc.as_ref()).await;

        // Insert headers (some filtered, some not)
        sqlx::query("INSERT INTO url_http_headers (url_status_id, header_name, header_value) VALUES (?, ?, ?)")
            .bind(url_id)
            .bind("Content-Type")
            .bind("text/html")
            .execute(pool_arc.as_ref())
            .await
            .expect("Failed to insert header");

        sqlx::query("INSERT INTO url_http_headers (url_status_id, header_name, header_value) VALUES (?, ?, ?)")
            .bind(url_id)
            .bind("Server")
            .bind("nginx/1.18.0")
            .execute(pool_arc.as_ref())
            .await
            .expect("Failed to insert header");

        sqlx::query("INSERT INTO url_http_headers (url_status_id, header_name, header_value) VALUES (?, ?, ?)")
            .bind(url_id)
            .bind("X-Custom-Header")
            .bind("custom-value")
            .execute(pool_arc.as_ref())
            .await
            .expect("Failed to insert header");

        let (joined, total_count) = fetch_filtered_http_headers(
            &pool_arc,
            HttpHeadersTable::Standard,
            url_id,
            &["Content-Type", "Server"],
        )
        .await
        .expect("Should filter headers");

        // Should contain only filtered headers (semicolon-separated)
        assert!(
            joined.contains("Content-Type:text/html"),
            "Should contain Content-Type"
        );
        assert!(
            joined.contains("Server:nginx/1.18.0"),
            "Should contain Server"
        );
        assert!(
            !joined.contains("X-Custom-Header"),
            "Should not contain unfiltered header"
        );
        assert!(
            joined.contains(";"),
            "Headers should be semicolon-separated"
        );

        // Total count should include all headers
        assert_eq!(total_count, 3, "Total count should include all headers");
    }

    #[tokio::test]
    async fn test_fetch_filtered_http_headers_no_matches() {
        let pool = create_test_pool().await;
        let pool_arc: DbPool = Arc::new(pool);
        let url_id = create_test_url_status_default(pool_arc.as_ref()).await;

        // Insert header that doesn't match filter
        sqlx::query("INSERT INTO url_http_headers (url_status_id, header_name, header_value) VALUES (?, ?, ?)")
            .bind(url_id)
            .bind("X-Custom-Header")
            .bind("custom-value")
            .execute(pool_arc.as_ref())
            .await
            .expect("Failed to insert header");

        let (joined, total_count) = fetch_filtered_http_headers(
            &pool_arc,
            HttpHeadersTable::Standard,
            url_id,
            &["Content-Type", "Server"],
        )
        .await
        .expect("Should handle no matches");

        assert_eq!(joined, "", "No matches should return empty string");
        assert_eq!(total_count, 1, "Total count should still count all headers");
    }

    #[tokio::test]
    async fn test_csv_export_new_columns_populated() {
        use super::super::csv::export_csv;
        use super::super::types::{ExportFormat, ExportOptions};
        use std::io::Read;

        let temp_db = NamedTempFile::new().expect("temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .expect("Failed to create pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");
        let url_id = create_test_url_status_default(&pool).await;

        // Insert nameservers
        sqlx::query("INSERT INTO url_nameservers (url_status_id, nameserver) VALUES (?, ?)")
            .bind(url_id)
            .bind("ns1.test.com")
            .execute(&pool)
            .await
            .unwrap();

        // Insert MX record
        sqlx::query(
            "INSERT INTO url_mx_records (url_status_id, priority, mail_exchange) VALUES (?, ?, ?)",
        )
        .bind(url_id)
        .bind(10)
        .bind("mail.test.com")
        .execute(&pool)
        .await
        .unwrap();

        // Insert social media with identifier
        sqlx::query("INSERT INTO url_social_media_links (url_status_id, platform, profile_url, identifier) VALUES (?, ?, ?, ?)")
            .bind(url_id)
            .bind("GitHub")
            .bind("https://github.com/testuser")
            .bind("testuser")
            .execute(&pool)
            .await
            .unwrap();

        // Insert partial failure
        sqlx::query("INSERT INTO url_partial_failures (url_status_id, error_type, error_message, observed_at_ms) VALUES (?, ?, ?, ?)")
            .bind(url_id)
            .bind("DNS error")
            .bind("timeout")
            .bind(1704067200000i64)
            .execute(&pool)
            .await
            .unwrap();

        drop(pool);

        let temp_file = NamedTempFile::new().expect("temp output");
        let output_path = temp_file.path().to_path_buf();

        let count = export_csv(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: Some(output_path.clone()),
            format: ExportFormat::Csv,
            run_id: None,
            domain: None,
            status: None,
            since: None,
            include_implied_tech: false,
        })
        .await
        .expect("Should export CSV");

        assert_eq!(count, 1);

        let mut contents = String::new();
        std::fs::File::open(&output_path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();

        let lines: Vec<&str> = contents.trim().split('\n').collect();
        assert_eq!(lines.len(), 2, "Should have header + 1 data row");

        // Parse CSV to find new columns by header name
        let headers: Vec<&str> = lines[0].split(',').collect();
        let data: Vec<&str> = lines[1].split(',').collect();

        // Find the nameservers column index
        let ns_idx = headers
            .iter()
            .position(|h| *h == "nameservers")
            .expect("Should have nameservers column");
        assert!(data.len() > ns_idx, "Data row should have enough columns");
        assert!(
            data[ns_idx].contains("ns1.test.com"),
            "nameservers column should contain ns1.test.com, got: {}",
            data[ns_idx]
        );

        // Find partial_failure_count column
        let pfc_idx = headers
            .iter()
            .position(|h| *h == "partial_failure_count")
            .expect("Should have partial_failure_count column");
        assert_eq!(data[pfc_idx], "1", "Should have 1 partial failure");
    }
}
