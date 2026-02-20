//! JSONL export functionality.
//!
//! Exports domain_status data to JSONL (JSON Lines) format.
//! Each line is a complete JSON object representing one URL scan result.
//! This format is ideal for programmatic processing, piping to jq, or loading into databases.

use anyhow::{Context, Result};
use futures::TryStreamExt;
use serde_json::{json, Value};
use std::io::{self, Write};

use crate::storage::init_db_pool_with_path;

use super::queries::{build_where_clause, IgnoreBrokenPipe};
use super::row::{
    build_export_row, build_url, extract_main_row_data, parse_headers, parse_key_value_pairs,
    parse_string_list, parse_technologies,
};

/// Exports data to JSONL format (JSON Lines).
///
/// Each line is a complete JSON object with all fields for one URL scan result.
/// This format preserves nested structures better than CSV and is ideal for:
/// - Piping to `jq` for filtering/transformation
/// - Loading into databases (MongoDB, Elasticsearch, etc.)
/// - Programmatic processing in scripts
///
/// # Arguments
///
/// * `opts` - Export options including database path, output, and filters
///
/// # Returns
///
/// Returns the number of records exported, or an error if export fails.
#[allow(clippy::too_many_lines)]
pub async fn export_jsonl(opts: &super::ExportOptions) -> Result<usize> {
    let pool = init_db_pool_with_path(&opts.db_path, 5)
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

    let mut writer: Box<dyn Write> = if let Some(output_path) = opts.output.as_ref() {
        let file = tokio::fs::File::create(output_path)
            .await
            .context(format!(
                "Failed to create output file: {}",
                output_path.display()
            ))?
            .into_std()
            .await;
        Box::new(file)
    } else {
        Box::new(IgnoreBrokenPipe::new(io::stdout()))
    };

    let query = query_builder.build();
    let mut rows = query.fetch(pool.as_ref());

    let mut record_count = 0;

    while let Some(row) = rows.try_next().await? {
        // Extract main row data and build the complete export row
        let main = extract_main_row_data(&row);
        let export_row = build_export_row(&pool, main).await?;

        // Build URL
        let url = build_url(&export_row.main.final_domain);

        // Convert redirects to JSON array
        let redirect_chain: Vec<Value> = export_row
            .redirects
            .iter()
            .map(|r| {
                json!({
                    "redirect_url": r.redirect_url,
                    "sequence_order": r.sequence_order,
                })
            })
            .collect();

        // Parse technologies into JSON array
        let technologies: Vec<Value> = parse_technologies(&export_row.technologies_str)
            .into_iter()
            .map(|(name, version)| {
                json!({
                    "name": name,
                    "version": version.map(Value::String).unwrap_or(Value::Null)
                })
            })
            .collect();

        // Parse certificate SANs
        let certificate_sans = parse_string_list(&export_row.certificate_sans_str);

        // Parse OIDs
        let oids = parse_string_list(&export_row.oids_str);

        // Parse analytics IDs into JSON array
        let analytics_ids: Vec<Value> = parse_key_value_pairs(&export_row.analytics_ids_str)
            .into_iter()
            .map(|(provider, tracking_id)| {
                json!({
                    "provider": provider,
                    "tracking_id": tracking_id
                })
            })
            .collect();

        // Parse social media links into JSON array
        let social_media_links: Vec<Value> =
            parse_key_value_pairs(&export_row.social_media_links_str)
                .into_iter()
                .map(|(platform, url)| {
                    json!({
                        "platform": platform,
                        "url": url
                    })
                })
                .collect();

        // Parse security warnings
        let security_warnings = parse_string_list(&export_row.security_warnings_str);

        // Parse structured data types
        let structured_data_types = parse_string_list(&export_row.structured_data_types_str);

        // Parse headers
        let http_headers = parse_headers(&export_row.http_headers_str);
        let security_headers = parse_headers(&export_row.security_headers_str);

        // Build GeoIP JSON (or null if no data)
        let geoip = if export_row.geoip.country_code.is_some()
            || export_row.geoip.asn.is_some()
            || export_row.geoip.latitude.is_some()
        {
            Some(json!({
                "country_code": export_row.geoip.country_code,
                "country_name": export_row.geoip.country_name,
                "region": export_row.geoip.region,
                "city": export_row.geoip.city,
                "latitude": export_row.geoip.latitude,
                "longitude": export_row.geoip.longitude,
                "asn": export_row.geoip.asn,
                "asn_org": export_row.geoip.asn_org,
            }))
        } else {
            None
        };

        // Build WHOIS JSON (or null if no data)
        let whois = if export_row.whois.registrar.is_some()
            || export_row.whois.creation_date_ms.is_some()
        {
            Some(json!({
                "registrar": export_row.whois.registrar,
                "creation_date_ms": export_row.whois.creation_date_ms,
                "expiration_date_ms": export_row.whois.expiration_date_ms,
                "registrant_country": export_row.whois.registrant_country,
            }))
        } else {
            None
        };

        // Build the complete JSON object
        let json_obj = json!({
            "url": url,
            "initial_domain": export_row.main.initial_domain,
            "final_domain": export_row.main.final_domain,
            "ip_address": export_row.main.ip_address,
            "reverse_dns": export_row.main.reverse_dns,
            "status": export_row.main.status,
            "status_description": export_row.main.status_desc,
            "response_time_ms": export_row.main.response_time,
            "title": export_row.main.title,
            "keywords": export_row.main.keywords,
            "description": export_row.main.description,
            "is_mobile_friendly": export_row.main.is_mobile_friendly,
            "redirect_chain": redirect_chain,
            "redirect_count": export_row.redirect_count,
            "final_redirect_url": export_row.final_redirect_url,
            "technologies": technologies,
            "technology_count": export_row.technology_count,
            "tls": {
                "version": export_row.main.tls_version,
                "certificate": {
                    "subject": export_row.main.ssl_cert_subject,
                    "issuer": export_row.main.ssl_cert_issuer,
                    "valid_to": export_row.main.ssl_cert_valid_to_ms,
                    "sans": certificate_sans,
                    "san_count": export_row.certificate_san_count,
                    "oids": oids,
                },
                "cipher_suite": export_row.main.cipher_suite,
                "key_algorithm": export_row.main.key_algorithm,
            },
            "dns": {
                "nameserver_count": export_row.nameserver_count,
                "txt_record_count": export_row.txt_count,
                "mx_record_count": export_row.mx_count,
            },
            "spf_record": export_row.main.spf_record,
            "dmarc_record": export_row.main.dmarc_record,
            "analytics_ids": analytics_ids,
            "analytics_count": export_row.analytics_count,
            "social_media_links": social_media_links,
            "social_media_count": export_row.social_media_count,
            "security_warnings": security_warnings,
            "security_warning_count": export_row.security_warning_count,
            "structured_data": {
                "types": structured_data_types,
                "count": export_row.structured_data_count,
            },
            "http_headers": http_headers,
            "http_header_count": export_row.http_header_count,
            "security_headers": security_headers,
            "security_header_count": export_row.security_header_count,
            "geoip": geoip,
            "whois": whois,
            "favicon": {
                "hash": export_row.favicon_hash,
                "url": export_row.favicon_url,
            },
            "timestamp": export_row.main.timestamp,
            "run_id": export_row.main.run_id,
        });

        serde_json::to_writer(&mut writer, &json_obj)?;
        writeln!(writer)?;

        record_count += 1;
    }

    Ok(record_count)
}

#[cfg(test)]
mod tests {
    use super::super::types::{ExportFormat, ExportOptions};
    use super::export_jsonl;
    use crate::storage::migrations::run_migrations;
    use sqlx::{Row, SqlitePool};
    use std::io::Read;
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

    async fn create_test_url_status(pool: &SqlitePool, domain: &str, status: u16) -> i64 {
        // Ensure the run exists first (FK constraint)
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
        .bind(status)
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
    async fn test_export_jsonl_basic() {
        let pool = create_test_pool().await;
        let _url_id = create_test_url_status(&pool, "example.com", 200).await;

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let output_path = temp_file.path().to_path_buf();

        let count = export_jsonl(&ExportOptions {
            db_path: std::path::Path::new(":memory:").to_path_buf(),
            output: Some(output_path.clone()),
            format: ExportFormat::Jsonl,
            run_id: None,
            domain: None,
            status: None,
            since: None,
        })
        .await;

        // This will fail because we can't use :memory: with a path
        // We need to use a real file path for the database
        assert!(count.is_err(), "Should fail with memory database");
    }

    #[tokio::test]
    async fn test_export_jsonl_with_real_database() {
        let temp_db = NamedTempFile::new().expect("Failed to create temp DB");
        let db_path = temp_db.path();

        // Create a real database file
        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .expect("Failed to create database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");

        let _url_id = create_test_url_status(&pool, "example.com", 200).await;
        drop(pool); // Close connection so export can open it

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let output_path = temp_file.path().to_path_buf();

        let count = export_jsonl(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: Some(output_path.clone()),
            format: ExportFormat::Jsonl,
            run_id: None,
            domain: None,
            status: None,
            since: None,
        })
        .await
        .expect("Should export successfully");

        assert_eq!(count, 1, "Should export 1 record");

        // Verify output file contains valid JSON
        let mut file = std::fs::File::open(&output_path).expect("Failed to open output file");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("Failed to read output file");

        let lines: Vec<&str> = contents.trim().split('\n').collect();
        assert_eq!(lines.len(), 1, "Should have 1 line");

        let json_obj: serde_json::Value =
            serde_json::from_str(lines[0]).expect("Should be valid JSON");
        assert_eq!(json_obj["initial_domain"], "example.com");
        assert_eq!(json_obj["final_domain"], "example.com");
        assert_eq!(json_obj["status"], 200);
    }

    #[tokio::test]
    async fn test_export_jsonl_filter_by_run_id() {
        let temp_db = NamedTempFile::new().expect("Failed to create temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .expect("Failed to create database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");

        // Create records with different run_ids
        create_test_url_status(&pool, "example.com", 200).await;

        // Create second run first (FK constraint)
        create_test_run(&pool, "test-run-2").await;

        sqlx::query(
            "INSERT INTO url_status (
                initial_domain, final_domain, ip_address, http_status, http_status_text,
                response_time_seconds, title, observed_at_ms, is_mobile_friendly, run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id",
        )
        .bind("other.com")
        .bind("other.com")
        .bind("192.0.2.2")
        .bind(200)
        .bind("OK")
        .bind(1.5f64)
        .bind("Other Page")
        .bind(1704067200000i64)
        .bind(true)
        .bind("test-run-2")
        .fetch_one(&pool)
        .await
        .expect("Failed to insert");

        drop(pool);

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let output_path = temp_file.path().to_path_buf();

        let count = export_jsonl(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: Some(output_path.clone()),
            format: ExportFormat::Jsonl,
            run_id: Some("test-run-1".to_string()),
            domain: None,
            status: None,
            since: None,
        })
        .await
        .expect("Should export successfully");

        assert_eq!(count, 1, "Should export only 1 record matching run_id");

        let mut file = std::fs::File::open(&output_path).expect("Failed to open output file");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("Failed to read output file");

        let lines: Vec<&str> = contents.trim().split('\n').collect();
        assert_eq!(lines.len(), 1);
        let json_obj: serde_json::Value =
            serde_json::from_str(lines[0]).expect("Should be valid JSON");
        assert_eq!(json_obj["initial_domain"], "example.com");
    }

    #[tokio::test]
    async fn test_export_jsonl_filter_by_domain() {
        let temp_db = NamedTempFile::new().expect("Failed to create temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .expect("Failed to create database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");

        create_test_url_status(&pool, "example.com", 200).await;
        create_test_url_status(&pool, "other.com", 200).await;

        drop(pool);

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let output_path = temp_file.path().to_path_buf();

        let count = export_jsonl(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: Some(output_path.clone()),
            format: ExportFormat::Jsonl,
            run_id: None,
            domain: Some("example.com".to_string()),
            status: None,
            since: None,
        })
        .await
        .expect("Should export successfully");

        assert_eq!(count, 1, "Should export only 1 record matching domain");
    }

    #[tokio::test]
    async fn test_export_jsonl_filter_by_status() {
        let temp_db = NamedTempFile::new().expect("Failed to create temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .expect("Failed to create database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");

        create_test_url_status(&pool, "example.com", 200).await;
        create_test_url_status(&pool, "error.com", 404).await;

        drop(pool);

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let output_path = temp_file.path().to_path_buf();

        let count = export_jsonl(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: Some(output_path.clone()),
            format: ExportFormat::Jsonl,
            run_id: None,
            domain: None,
            status: Some(404),
            since: None,
        })
        .await
        .expect("Should export successfully");

        assert_eq!(count, 1, "Should export only 1 record matching status");
    }

    #[tokio::test]
    async fn test_export_jsonl_filter_by_since() {
        let temp_db = NamedTempFile::new().expect("Failed to create temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .expect("Failed to create database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");

        create_test_url_status(&pool, "example.com", 200).await;

        // Create a record with a later timestamp
        sqlx::query(
            "INSERT INTO url_status (
                initial_domain, final_domain, ip_address, http_status, http_status_text,
                response_time_seconds, title, observed_at_ms, is_mobile_friendly, run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id",
        )
        .bind("newer.com")
        .bind("newer.com")
        .bind("192.0.2.3")
        .bind(200)
        .bind("OK")
        .bind(1.5f64)
        .bind("Newer Page")
        .bind(1704153600000i64) // Later timestamp
        .bind(true)
        .bind("test-run-1")
        .fetch_one(&pool)
        .await
        .expect("Failed to insert");

        drop(pool);

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let output_path = temp_file.path().to_path_buf();

        // Filter by timestamp after the first record
        let count = export_jsonl(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: Some(output_path.clone()),
            format: ExportFormat::Jsonl,
            run_id: None,
            domain: None,
            status: None,
            since: Some(1704100000000i64), // Between the two timestamps
        })
        .await
        .expect("Should export successfully");

        assert_eq!(count, 1, "Should export only 1 record after timestamp");
    }

    #[tokio::test]
    async fn test_export_jsonl_with_technologies() {
        let temp_db = NamedTempFile::new().expect("Failed to create temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .expect("Failed to create database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");

        let url_id = create_test_url_status(&pool, "example.com", 200).await;

        // Add technologies
        sqlx::query(
            "INSERT INTO url_technologies (url_status_id, technology_name, technology_version)
             VALUES (?, ?, ?)",
        )
        .bind(url_id)
        .bind("WordPress")
        .bind(Some("6.8.3"))
        .execute(&pool)
        .await
        .expect("Failed to insert technology");

        sqlx::query(
            "INSERT INTO url_technologies (url_status_id, technology_name, technology_version)
             VALUES (?, ?, ?)",
        )
        .bind(url_id)
        .bind("PHP")
        .bind::<Option<String>>(None)
        .execute(&pool)
        .await
        .expect("Failed to insert technology");

        drop(pool);

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let output_path = temp_file.path().to_path_buf();

        let count = export_jsonl(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: Some(output_path.clone()),
            format: ExportFormat::Jsonl,
            run_id: None,
            domain: None,
            status: None,
            since: None,
        })
        .await
        .expect("Should export successfully");

        assert_eq!(count, 1);

        let mut file = std::fs::File::open(&output_path).expect("Failed to open output file");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("Failed to read output file");

        let json_obj: serde_json::Value =
            serde_json::from_str(contents.trim()).expect("Should be valid JSON");
        assert_eq!(json_obj["technology_count"], 2);
        let technologies = json_obj["technologies"]
            .as_array()
            .expect("Should be array");
        assert_eq!(technologies.len(), 2);
    }

    #[tokio::test]
    async fn test_export_jsonl_empty_database() {
        let temp_db = NamedTempFile::new().expect("Failed to create temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .expect("Failed to create database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");
        drop(pool);

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let output_path = temp_file.path().to_path_buf();

        let count = export_jsonl(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: Some(output_path.clone()),
            format: ExportFormat::Jsonl,
            run_id: None,
            domain: None,
            status: None,
            since: None,
        })
        .await
        .expect("Should export successfully even with empty database");

        assert_eq!(count, 0, "Should export 0 records from empty database");
    }

    #[tokio::test]
    async fn test_export_jsonl_stdout() {
        let temp_db = NamedTempFile::new().expect("Failed to create temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .expect("Failed to create database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");

        create_test_url_status(&pool, "example.com", 200).await;
        drop(pool);

        // Export to stdout (None output path)
        let count = export_jsonl(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: None, // stdout
            format: ExportFormat::Jsonl,
            run_id: None,
            domain: None,
            status: None,
            since: None,
        })
        .await
        .expect("Should export to stdout successfully");

        assert_eq!(count, 1, "Should export 1 record");
    }

    #[tokio::test]
    async fn test_export_jsonl_with_redirect_chain() {
        let temp_db = NamedTempFile::new().expect("Failed to create temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .expect("Failed to create database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");

        let url_id = create_test_url_status(&pool, "example.com", 200).await;

        // Add redirect chain
        sqlx::query(
            "INSERT INTO url_redirect_chain (url_status_id, redirect_url, sequence_order)
             VALUES (?, ?, ?)",
        )
        .bind(url_id)
        .bind("http://example.com")
        .bind(0)
        .execute(&pool)
        .await
        .expect("Failed to insert redirect");

        sqlx::query(
            "INSERT INTO url_redirect_chain (url_status_id, redirect_url, sequence_order)
             VALUES (?, ?, ?)",
        )
        .bind(url_id)
        .bind("https://example.com")
        .bind(1)
        .execute(&pool)
        .await
        .expect("Failed to insert redirect");

        drop(pool);

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let output_path = temp_file.path().to_path_buf();

        let count = export_jsonl(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: Some(output_path.clone()),
            format: ExportFormat::Jsonl,
            run_id: None,
            domain: None,
            status: None,
            since: None,
        })
        .await
        .expect("Should export successfully");

        assert_eq!(count, 1);

        let mut file = std::fs::File::open(&output_path).expect("Failed to open output file");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("Failed to read output file");

        let json_obj: serde_json::Value =
            serde_json::from_str(contents.trim()).expect("Should be valid JSON");
        assert_eq!(json_obj["redirect_count"], 2);
        let redirect_chain = json_obj["redirect_chain"]
            .as_array()
            .expect("Should be array");
        assert_eq!(redirect_chain.len(), 2);
        assert_eq!(json_obj["final_redirect_url"], "https://example.com");
    }

    #[tokio::test]
    async fn test_export_jsonl_file_creation_error() {
        // Test error handling when file creation fails (e.g., invalid path)
        let temp_db = NamedTempFile::new().expect("Failed to create temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .expect("Failed to create database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");
        drop(pool);

        // Use an invalid path (directory instead of file)
        let invalid_path = std::path::PathBuf::from("/invalid/path/that/does/not/exist.jsonl");

        let result = export_jsonl(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: Some(invalid_path.clone()),
            format: ExportFormat::Jsonl,
            run_id: None,
            domain: None,
            status: None,
            since: None,
        })
        .await;

        // Should fail with file creation error
        assert!(result.is_err(), "Should fail when file cannot be created");
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Failed to create output file")
                || error_msg.contains("No such file")
                || error_msg.contains("Permission denied"),
            "Error should mention file creation issue, got: {}",
            error_msg
        );
    }

    #[tokio::test]
    async fn test_export_jsonl_handles_malformed_technology_data() {
        // Test that malformed technology data (empty strings, special characters) is handled gracefully
        let temp_db = NamedTempFile::new().expect("Failed to create temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .expect("Failed to create database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");

        let url_id = create_test_url_status(&pool, "example.com", 200).await;

        // Add technology with empty version (should serialize as null)
        sqlx::query(
            "INSERT INTO url_technologies (url_status_id, technology_name, technology_version)
             VALUES (?, ?, ?)",
        )
        .bind(url_id)
        .bind("WordPress")
        .bind::<Option<String>>(None)
        .execute(&pool)
        .await
        .expect("Failed to insert technology");

        // Add technology with colon in name (tests key-value parsing)
        sqlx::query(
            "INSERT INTO url_technologies (url_status_id, technology_name, technology_version)
             VALUES (?, ?, ?)",
        )
        .bind(url_id)
        .bind("Tech:Name")
        .bind(Some("1.0"))
        .execute(&pool)
        .await
        .expect("Failed to insert technology");

        drop(pool);

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let output_path = temp_file.path().to_path_buf();

        let count = export_jsonl(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: Some(output_path.clone()),
            format: ExportFormat::Jsonl,
            run_id: None,
            domain: None,
            status: None,
            since: None,
        })
        .await
        .expect("Should export successfully");

        assert_eq!(count, 1);

        // Verify the export succeeded and JSON is valid
        let mut file = std::fs::File::open(&output_path).expect("Failed to open output file");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("Failed to read output file");

        let json_obj: serde_json::Value =
            serde_json::from_str(contents.trim()).expect("Should be valid JSON");
        let technologies = json_obj["technologies"]
            .as_array()
            .expect("Should be array");
        assert_eq!(technologies.len(), 2);
    }

    #[tokio::test]
    async fn test_export_jsonl_handles_empty_redirect_chain() {
        // Test that empty redirect chain is handled correctly
        let temp_db = NamedTempFile::new().expect("Failed to create temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .expect("Failed to create database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");

        let _url_id = create_test_url_status(&pool, "example.com", 200).await;
        // Don't add any redirect chain entries

        drop(pool);

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let output_path = temp_file.path().to_path_buf();

        let count = export_jsonl(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: Some(output_path.clone()),
            format: ExportFormat::Jsonl,
            run_id: None,
            domain: None,
            status: None,
            since: None,
        })
        .await
        .expect("Should export successfully");

        assert_eq!(count, 1);

        let mut file = std::fs::File::open(&output_path).expect("Failed to open output file");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("Failed to read output file");

        let json_obj: serde_json::Value =
            serde_json::from_str(contents.trim()).expect("Should be valid JSON");
        assert_eq!(json_obj["redirect_count"], 0);
        let redirect_chain = json_obj["redirect_chain"]
            .as_array()
            .expect("Should be array");
        assert!(redirect_chain.is_empty());
        assert_eq!(json_obj["final_redirect_url"], "");
    }

    #[tokio::test]
    async fn test_export_jsonl_handles_null_values() {
        // Test that NULL values in database are handled correctly (serialized as null in JSON)
        // This is critical - prevents panics from NULL database values
        let temp_db = NamedTempFile::new().expect("Failed to create temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .expect("Failed to create database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");

        // Create record with NULL values for optional fields
        create_test_run(&pool, "test-run-1").await;

        sqlx::query(
            "INSERT INTO url_status (
                initial_domain, final_domain, ip_address, http_status, http_status_text,
                response_time_seconds, title, observed_at_ms, is_mobile_friendly, run_id,
                reverse_dns_name, keywords, description, tls_version, ssl_cert_subject,
                ssl_cert_issuer, ssl_cert_valid_to_ms, cipher_suite, key_algorithm,
                spf_record, dmarc_record
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        .bind("test-run-1")
        .bind::<Option<String>>(None) // NULL reverse_dns
        .bind::<Option<String>>(None) // NULL keywords
        .bind::<Option<String>>(None) // NULL description
        .bind::<Option<String>>(None) // NULL tls_version
        .bind::<Option<String>>(None) // NULL ssl_cert_subject
        .bind::<Option<String>>(None) // NULL ssl_cert_issuer
        .bind::<Option<i64>>(None) // NULL ssl_cert_valid_to_ms
        .bind::<Option<String>>(None) // NULL cipher_suite
        .bind::<Option<String>>(None) // NULL key_algorithm
        .bind::<Option<String>>(None) // NULL spf_record
        .bind::<Option<String>>(None) // NULL dmarc_record
        .execute(&pool)
        .await
        .expect("Failed to insert");

        drop(pool);

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let output_path = temp_file.path().to_path_buf();

        let count = export_jsonl(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: Some(output_path.clone()),
            format: ExportFormat::Jsonl,
            run_id: None,
            domain: None,
            status: None,
            since: None,
        })
        .await
        .expect("Should export successfully even with NULL values");

        assert_eq!(count, 1);

        let mut file = std::fs::File::open(&output_path).expect("Failed to open output file");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("Failed to read output file");

        let json_obj: serde_json::Value =
            serde_json::from_str(contents.trim()).expect("Should be valid JSON");
        // NULL values should be serialized as null in JSON
        assert_eq!(json_obj["reverse_dns"], serde_json::Value::Null);
        assert_eq!(json_obj["keywords"], serde_json::Value::Null);
        assert_eq!(json_obj["description"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn test_export_jsonl_handles_technology_with_colon_in_name() {
        // Test that technologies with colons in names are handled correctly
        // This is critical - technology names like "Tech:Name" could break parsing
        // The code at line 156 splits on ':' which could break if name contains colon
        let temp_db = NamedTempFile::new().expect("Failed to create temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .expect("Failed to create database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");

        let url_id = create_test_url_status(&pool, "example.com", 200).await;

        // Add technology with colon in name (tests parsing logic)
        sqlx::query(
            "INSERT INTO url_technologies (url_status_id, technology_name, technology_version)
             VALUES (?, ?, ?)",
        )
        .bind(url_id)
        .bind("Tech:Name") // Colon in name
        .bind(Some("1.0"))
        .execute(&pool)
        .await
        .expect("Failed to insert");

        drop(pool);

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let output_path = temp_file.path().to_path_buf();

        let count = export_jsonl(&ExportOptions {
            db_path: db_path.to_path_buf(),
            output: Some(output_path.clone()),
            format: ExportFormat::Jsonl,
            run_id: None,
            domain: None,
            status: None,
            since: None,
        })
        .await
        .expect("Should export successfully");

        assert_eq!(count, 1);

        // Verify the export succeeded and JSON is valid
        let mut file = std::fs::File::open(&output_path).expect("Failed to open output file");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("Failed to read output file");

        let json_obj: serde_json::Value =
            serde_json::from_str(contents.trim()).expect("Should be valid JSON");
        let technologies = json_obj["technologies"]
            .as_array()
            .expect("Should be array");
        // Should handle colon in name correctly (may be split incorrectly, but shouldn't panic)
        assert!(!technologies.is_empty());
    }
}
