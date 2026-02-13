//! CSV export functionality.
//!
//! Exports domain_status data to CSV format (simplified, flattened view).
//! One row per URL with all related data flattened into columns.

use anyhow::{Context, Result};
use csv::Writer;
use futures::TryStreamExt;
use std::io::{self, Write};

use crate::storage::init_db_pool_with_path;

use super::queries::{build_where_clause, IgnoreBrokenPipe};
use super::row::{build_export_row, build_url, extract_main_row_data};

/// Format a timestamp (milliseconds since epoch) as a date string.
fn format_date(ts_ms: Option<i64>) -> String {
    ts_ms
        .and_then(|ts| chrono::DateTime::from_timestamp(ts / 1000, 0))
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

/// Exports data to CSV format.
///
/// # Arguments
///
/// * `opts` - Export options including database path, output, and filters
///
/// # Returns
///
/// Returns the number of records exported, or an error if export fails.
#[allow(clippy::too_many_lines)]
pub async fn export_csv(opts: &super::ExportOptions) -> Result<usize> {
    let pool = init_db_pool_with_path(&opts.db_path)
        .await
        .context("Failed to initialize database pool")?;

    let mut query_builder = sqlx::QueryBuilder::new(
        "SELECT us.id, us.initial_domain, us.final_domain, us.ip_address, us.reverse_dns_name,
                us.http_status, us.http_status_text, us.response_time_seconds, us.title, us.keywords,
                us.description, us.is_mobile_friendly, us.tls_version, us.ssl_cert_subject,
                us.ssl_cert_issuer, us.ssl_cert_valid_to_ms, us.cipher_suite, us.key_algorithm,
                us.spf_record, us.dmarc_record, us.observed_at_ms, us.run_id
         FROM url_status us",
    );

    build_where_clause(
        &mut query_builder,
        opts.run_id.as_deref(),
        opts.domain.as_deref(),
        opts.status,
        opts.since,
    );

    query_builder.push(" ORDER BY us.observed_at_ms DESC");

    let mut writer: Writer<Box<dyn Write>> = if let Some(output_path) = opts.output.as_ref() {
        let file = tokio::fs::File::create(output_path)
            .await
            .context(format!(
                "Failed to create output file: {}",
                output_path.display()
            ))?
            .into_std()
            .await;
        Writer::from_writer(Box::new(file) as Box<dyn Write>)
    } else {
        Writer::from_writer(Box::new(IgnoreBrokenPipe::new(io::stdout())) as Box<dyn Write>)
    };

    // Write CSV header
    writer.write_record([
        "url",
        "initial_domain",
        "final_domain",
        "ip_address",
        "reverse_dns",
        "status",
        "status_description",
        "response_time_ms",
        "title",
        "keywords",
        "description",
        "is_mobile_friendly",
        "redirect_count",
        "final_redirect_url",
        "technologies",
        "technology_count",
        "tls_version",
        "ssl_cert_subject",
        "ssl_cert_issuer",
        "ssl_cert_valid_to",
        "cipher_suite",
        "key_algorithm",
        "certificate_sans",
        "certificate_san_count",
        "oids",
        "oid_count",
        "nameserver_count",
        "txt_record_count",
        "mx_record_count",
        "spf_record",
        "dmarc_record",
        "analytics_ids",
        "analytics_count",
        "social_media_links",
        "social_media_count",
        "security_warnings",
        "security_warning_count",
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
        "timestamp",
        "run_id",
    ])?;

    let query = query_builder.build();
    let mut rows = query.fetch(pool.as_ref());

    let mut record_count = 0;

    while let Some(row) = rows.try_next().await? {
        // Extract main row data and build the complete export row
        let main = extract_main_row_data(&row);
        let export_row = build_export_row(&pool, main).await?;

        // Build URL and final redirect URL (use final_domain if no redirects)
        let url = build_url(&export_row.main.final_domain);
        let final_redirect_url = if export_row.final_redirect_url.is_empty() {
            export_row.main.final_domain.clone()
        } else {
            export_row.final_redirect_url.clone()
        };

        // Write CSV row
        writer.write_record(&[
            url,
            export_row.main.initial_domain.clone(),
            export_row.main.final_domain.clone(),
            export_row.main.ip_address.clone(),
            export_row.main.reverse_dns.clone().unwrap_or_default(),
            export_row.main.status.to_string(),
            export_row.main.status_desc.clone(),
            format!("{:.2}", export_row.main.response_time),
            export_row.main.title.clone(),
            export_row.main.keywords.clone().unwrap_or_default(),
            export_row.main.description.clone().unwrap_or_default(),
            if export_row.main.is_mobile_friendly {
                "true"
            } else {
                "false"
            }
            .to_string(),
            export_row.redirect_count.to_string(),
            final_redirect_url,
            export_row.technologies_str.clone(),
            export_row.technology_count.to_string(),
            export_row.main.tls_version.clone().unwrap_or_default(),
            export_row.main.ssl_cert_subject.clone().unwrap_or_default(),
            export_row.main.ssl_cert_issuer.clone().unwrap_or_default(),
            format_date(export_row.main.ssl_cert_valid_to_ms),
            export_row.main.cipher_suite.clone().unwrap_or_default(),
            export_row.main.key_algorithm.clone().unwrap_or_default(),
            export_row.certificate_sans_str.clone(),
            export_row.certificate_san_count.to_string(),
            export_row.oids_str.clone(),
            export_row.oid_count.to_string(),
            export_row.nameserver_count.to_string(),
            export_row.txt_count.to_string(),
            export_row.mx_count.to_string(),
            export_row.main.spf_record.clone().unwrap_or_default(),
            export_row.main.dmarc_record.clone().unwrap_or_default(),
            export_row.analytics_ids_str.clone(),
            export_row.analytics_count.to_string(),
            export_row.social_media_links_str.clone(),
            export_row.social_media_count.to_string(),
            export_row.security_warnings_str.clone(),
            export_row.security_warning_count.to_string(),
            export_row.structured_data_types_str.clone(),
            export_row.structured_data_count.to_string(),
            export_row.http_headers_str.clone(),
            export_row.http_header_count.to_string(),
            export_row.security_headers_str.clone(),
            export_row.security_header_count.to_string(),
            export_row.geoip.country_code.clone().unwrap_or_default(),
            export_row.geoip.country_name.clone().unwrap_or_default(),
            export_row.geoip.region.clone().unwrap_or_default(),
            export_row.geoip.city.clone().unwrap_or_default(),
            export_row
                .geoip
                .latitude
                .map(|v| v.to_string())
                .unwrap_or_default(),
            export_row
                .geoip
                .longitude
                .map(|v| v.to_string())
                .unwrap_or_default(),
            export_row
                .geoip
                .asn
                .map(|v| v.to_string())
                .unwrap_or_default(),
            export_row.geoip.asn_org.clone().unwrap_or_default(),
            export_row.whois.registrar.clone().unwrap_or_default(),
            format_date(export_row.whois.creation_date_ms),
            format_date(export_row.whois.expiration_date_ms),
            export_row
                .whois
                .registrant_country
                .clone()
                .unwrap_or_default(),
            export_row.main.timestamp.to_string(),
            export_row.main.run_id.clone().unwrap_or_default(),
        ])?;

        record_count += 1;
    }

    writer.flush()?;

    Ok(record_count)
}

#[cfg(test)]
mod tests {
    use super::super::queries::{
        fetch_count_query, fetch_filtered_http_headers, fetch_key_value_list, fetch_string_list,
    };
    use crate::storage::{migrations::run_migrations, DbPool};
    use sqlx::{Row, SqlitePool};
    use std::sync::Arc;

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
            "url_http_headers",
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
            "url_http_headers",
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
            "url_http_headers",
            url_id,
            &["Content-Type", "Server"],
        )
        .await
        .expect("Should handle no matches");

        assert_eq!(joined, "", "No matches should return empty string");
        assert_eq!(total_count, 1, "Total count should still count all headers");
    }
}
