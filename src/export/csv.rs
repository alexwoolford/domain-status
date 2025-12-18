//! CSV export functionality.
//!
//! Exports domain_status data to CSV format (simplified, flattened view).
//! One row per URL with all related data flattened into columns.

use anyhow::{Context, Result};
use csv::Writer;
use futures::TryStreamExt;
use sqlx::Row;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::storage::init_db_pool_with_path;

// Import shared helper functions and utilities
use super::queries::{
    build_where_clause, fetch_count_query, fetch_filtered_http_headers, fetch_key_value_list,
    fetch_string_list, IgnoreBrokenPipe,
};

/// Exports data to CSV format.
///
/// # Arguments
///
/// * `db_path` - Path to the SQLite database
/// * `output` - Output file path (or stdout if None)
/// * `run_id` - Optional filter by run ID
/// * `domain` - Optional filter by domain
/// * `status` - Optional filter by HTTP status code
/// * `since` - Optional filter by timestamp (milliseconds since epoch)
///
/// # Returns
///
/// Returns the number of records exported, or an error if export fails.
pub async fn export_csv(
    db_path: &Path,
    output: Option<&PathBuf>,
    run_id: Option<&str>,
    domain: Option<&str>,
    status: Option<u16>,
    since: Option<i64>,
) -> Result<usize> {
    let pool = init_db_pool_with_path(db_path)
        .await
        .context("Failed to initialize database pool")?;

    let mut query_builder = sqlx::QueryBuilder::new(
        "SELECT us.id, us.domain, us.final_domain, us.ip_address, us.reverse_dns_name,
                us.status, us.status_description, us.response_time, us.title, us.keywords,
                us.description, us.is_mobile_friendly, us.tls_version, us.ssl_cert_subject,
                us.ssl_cert_issuer, us.ssl_cert_valid_to, us.cipher_suite, us.key_algorithm,
                us.spf_record, us.dmarc_record, us.timestamp, us.run_id
         FROM url_status us",
    );

    // Use shared WHERE clause builder
    build_where_clause(&mut query_builder, run_id, domain, status, since);

    query_builder.push(" ORDER BY us.timestamp DESC");

    let mut writer: Writer<Box<dyn Write>> = if let Some(output_path) = output {
        let file = std::fs::File::create(output_path).context(format!(
            "Failed to create output file: {}",
            output_path.display()
        ))?;
        Writer::from_writer(Box::new(file) as Box<dyn Write>)
    } else {
        // Wrap stdout to ignore broken pipe errors (e.g., when piped to jq that exits early)
        Writer::from_writer(Box::new(IgnoreBrokenPipe::new(io::stdout())) as Box<dyn Write>)
    };

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
        let url_status_id: i64 = row.get("id");
        let initial_domain: String = row.get("domain");
        let final_domain: String = row.get("final_domain");
        let ip_address: String = row.get("ip_address");
        let reverse_dns: Option<String> = row.get("reverse_dns_name");
        let status: u16 = row.get("status");
        let status_desc: String = row.get("status_description");
        let response_time: f64 = row.get("response_time");
        let title: String = row.get("title");
        let keywords: Option<String> = row.get("keywords");
        let description: Option<String> = row.get("description");
        let is_mobile_friendly: bool = row.get("is_mobile_friendly");
        let tls_version: Option<String> = row.get("tls_version");
        let ssl_cert_subject: Option<String> = row.get("ssl_cert_subject");
        let ssl_cert_issuer: Option<String> = row.get("ssl_cert_issuer");
        let ssl_cert_valid_to: Option<i64> = row.get("ssl_cert_valid_to");
        let cipher_suite: Option<String> = row.get("cipher_suite");
        let key_algorithm: Option<String> = row.get("key_algorithm");
        let spf_record: Option<String> = row.get("spf_record");
        let dmarc_record: Option<String> = row.get("dmarc_record");
        let timestamp: i64 = row.get("timestamp");
        let run_id: Option<String> = row.get("run_id");

        let redirect_rows = sqlx::query(
            "SELECT url, sequence_order FROM url_redirect_chain
             WHERE url_status_id = ? ORDER BY sequence_order",
        )
        .bind(url_status_id)
        .fetch_all(pool.as_ref())
        .await?;

        let redirect_count = redirect_rows.len();
        let final_redirect_url = redirect_rows
            .last()
            .map(|r| r.get::<String, _>("url"))
            .unwrap_or_else(|| final_domain.clone());

        // Format technologies as "Technology:version" or "Technology" for backward compatibility
        let (technologies_str, technology_count) = fetch_string_list(
            &pool,
            "SELECT CASE WHEN technology_version IS NOT NULL THEN technology_name || ':' || technology_version ELSE technology_name END as technology_name FROM url_technologies WHERE url_status_id = ? ORDER BY technology_name, technology_version",
            url_status_id,
        ).await?;

        let nameserver_count = fetch_count_query(
            &pool,
            "SELECT COUNT(*) FROM url_nameservers WHERE url_status_id = ?",
            url_status_id,
        )
        .await?;

        let txt_count = fetch_count_query(
            &pool,
            "SELECT COUNT(*) FROM url_txt_records WHERE url_status_id = ?",
            url_status_id,
        )
        .await?;

        let mx_count = fetch_count_query(
            &pool,
            "SELECT COUNT(*) FROM url_mx_records WHERE url_status_id = ?",
            url_status_id,
        )
        .await?;

        let (certificate_sans_str, certificate_san_count) = fetch_string_list(
            &pool,
            "SELECT domain_name FROM url_certificate_sans WHERE url_status_id = ? ORDER BY domain_name",
            url_status_id,
        ).await?;

        let (oids_str, oid_count) = fetch_string_list(
            &pool,
            "SELECT oid FROM url_oids WHERE url_status_id = ? ORDER BY oid",
            url_status_id,
        )
        .await?;

        let (analytics_ids_str, analytics_count) = fetch_key_value_list(
            &pool,
            "SELECT provider, tracking_id FROM url_analytics_ids WHERE url_status_id = ? ORDER BY provider, tracking_id",
            "provider",
            "tracking_id",
            url_status_id,
        ).await?;

        let (social_media_links_str, social_media_count) = fetch_key_value_list(
            &pool,
            "SELECT platform, url FROM url_social_media_links WHERE url_status_id = ? ORDER BY platform, url",
            "platform",
            "url",
            url_status_id,
        ).await?;

        let (security_warnings_str, security_warning_count) = fetch_string_list(
            &pool,
            "SELECT warning_code FROM url_security_warnings WHERE url_status_id = ? ORDER BY warning_code",
            url_status_id,
        ).await?;

        let (structured_data_types_str, _) = fetch_string_list(
            &pool,
            "SELECT DISTINCT data_type FROM url_structured_data WHERE url_status_id = ? ORDER BY data_type",
            url_status_id,
        ).await?;
        let structured_data_count = fetch_count_query(
            &pool,
            "SELECT COUNT(*) FROM url_structured_data WHERE url_status_id = ?",
            url_status_id,
        )
        .await?;

        const HTTP_KEY_HEADERS: &[&str] = &[
            "Content-Type",
            "Server",
            "X-Powered-By",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Content-Security-Policy",
        ];
        let (http_headers_str, http_header_count) =
            fetch_filtered_http_headers(&pool, "url_http_headers", url_status_id, HTTP_KEY_HEADERS)
                .await?;

        const SECURITY_KEY_HEADERS: &[&str] = &[
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Referrer-Policy",
            "Permissions-Policy",
        ];
        let (security_headers_str, security_header_count) = fetch_filtered_http_headers(
            &pool,
            "url_security_headers",
            url_status_id,
            SECURITY_KEY_HEADERS,
        )
        .await?;

        let geoip_row = sqlx::query(
            "SELECT country_code, country_name, region, city, latitude, longitude, asn, asn_org
             FROM url_geoip WHERE url_status_id = ?",
        )
        .bind(url_status_id)
        .fetch_optional(pool.as_ref())
        .await?;

        let (
            geoip_country_code,
            geoip_country_name,
            geoip_region,
            geoip_city,
            geoip_latitude,
            geoip_longitude,
            geoip_asn,
            geoip_asn_org,
        ) = if let Some(row) = geoip_row {
            (
                row.get::<Option<String>, _>("country_code"),
                row.get::<Option<String>, _>("country_name"),
                row.get::<Option<String>, _>("region"),
                row.get::<Option<String>, _>("city"),
                row.get::<Option<f64>, _>("latitude"),
                row.get::<Option<f64>, _>("longitude"),
                row.get::<Option<i32>, _>("asn"),
                row.get::<Option<String>, _>("asn_org"),
            )
        } else {
            (None, None, None, None, None, None, None, None)
        };

        let whois_row = sqlx::query(
            "SELECT registrar, creation_date, expiration_date, registrant_country
             FROM url_whois WHERE url_status_id = ?",
        )
        .bind(url_status_id)
        .fetch_optional(pool.as_ref())
        .await?;

        let (whois_registrar, whois_creation_date, whois_expiration_date, whois_registrant_country) =
            if let Some(row) = whois_row {
                (
                    row.get::<Option<String>, _>("registrar"),
                    row.get::<Option<i64>, _>("creation_date"),
                    row.get::<Option<i64>, _>("expiration_date"),
                    row.get::<Option<String>, _>("registrant_country"),
                )
            } else {
                (None, None, None, None)
            };

        let url = format!("https://{}", final_domain);

        let ssl_cert_valid_to_str = ssl_cert_valid_to
            .map(|ts| {
                chrono::DateTime::from_timestamp(ts / 1000, 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| ts.to_string())
            })
            .unwrap_or_default();

        let whois_creation_str = whois_creation_date
            .map(|ts| {
                chrono::DateTime::from_timestamp(ts, 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string())
                    .unwrap_or_default()
            })
            .unwrap_or_default();

        let whois_expiration_str = whois_expiration_date
            .map(|ts| {
                chrono::DateTime::from_timestamp(ts, 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string())
                    .unwrap_or_default()
            })
            .unwrap_or_default();

        writer.write_record(&[
            url,
            initial_domain,
            final_domain,
            ip_address,
            reverse_dns.unwrap_or_default(),
            status.to_string(),
            status_desc,
            format!("{:.2}", response_time),
            title,
            keywords.unwrap_or_default(),
            description.unwrap_or_default(),
            if is_mobile_friendly { "true" } else { "false" }.to_string(),
            redirect_count.to_string(),
            final_redirect_url,
            technologies_str,
            technology_count.to_string(),
            tls_version.unwrap_or_default(),
            ssl_cert_subject.unwrap_or_default(),
            ssl_cert_issuer.unwrap_or_default(),
            ssl_cert_valid_to_str,
            cipher_suite.unwrap_or_default(),
            key_algorithm.unwrap_or_default(),
            certificate_sans_str,
            certificate_san_count.to_string(),
            oids_str,
            oid_count.to_string(),
            nameserver_count.to_string(),
            txt_count.to_string(),
            mx_count.to_string(),
            spf_record.unwrap_or_default(),
            dmarc_record.unwrap_or_default(),
            analytics_ids_str,
            analytics_count.to_string(),
            social_media_links_str,
            social_media_count.to_string(),
            security_warnings_str,
            security_warning_count.to_string(),
            structured_data_types_str,
            structured_data_count.to_string(),
            http_headers_str,
            http_header_count.to_string(),
            security_headers_str,
            security_header_count.to_string(),
            geoip_country_code.unwrap_or_default(),
            geoip_country_name.unwrap_or_default(),
            geoip_region.unwrap_or_default(),
            geoip_city.unwrap_or_default(),
            geoip_latitude.map(|v| v.to_string()).unwrap_or_default(),
            geoip_longitude.map(|v| v.to_string()).unwrap_or_default(),
            geoip_asn.map(|v| v.to_string()).unwrap_or_default(),
            geoip_asn_org.unwrap_or_default(),
            whois_registrar.unwrap_or_default(),
            whois_creation_str,
            whois_expiration_str,
            whois_registrant_country.unwrap_or_default(),
            timestamp.to_string(),
            run_id.unwrap_or_default(),
        ])?;

        record_count += 1;
    }

    writer.flush()?;

    Ok(record_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{migrations::run_migrations, DbPool};
    use sqlx::SqlitePool;
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
                domain, final_domain, ip_address, status, status_description,
                response_time, title, timestamp, is_mobile_friendly
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
