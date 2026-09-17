//! Tests for CSV export functionality.

use domain_status::export::{export_csv, ExportFormat, ExportOptions};
use sqlx::SqlitePool;

#[path = "helpers.rs"]
mod helpers;

use helpers::{create_test_run, create_test_url_status, setup_export_fixture};

fn csv_headers_and_rows(csv_content: &str) -> (csv::StringRecord, Vec<csv::StringRecord>) {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(csv_content.as_bytes());
    let headers = reader.headers().expect("Should read CSV headers").clone();
    let rows = reader
        .records()
        .map(|r| r.expect("Should parse CSV row"))
        .collect();
    (headers, rows)
}

fn csv_named_field(headers: &csv::StringRecord, row: &csv::StringRecord, column: &str) -> String {
    let idx = headers
        .iter()
        .position(|h| h == column)
        .unwrap_or_else(|| panic!("missing CSV column {column}"));
    row.get(idx).unwrap_or("").to_string()
}

fn csv_only_row_field(csv_content: &str, column: &str) -> String {
    let (headers, rows) = csv_headers_and_rows(csv_content);
    assert_eq!(rows.len(), 1, "expected one data row");
    csv_named_field(&headers, &rows[0], column)
}

async fn insert_http_header(pool: &SqlitePool, url_id: i64, name: &str, value: &str) {
    sqlx::query(
        "INSERT INTO url_http_headers (url_status_id, header_name, header_value) VALUES (?, ?, ?)",
    )
    .bind(url_id)
    .bind(name)
    .bind(value)
    .execute(pool)
    .await
    .expect("insert http header");
}

async fn insert_security_header(pool: &SqlitePool, url_id: i64, name: &str, value: &str) {
    sqlx::query(
        "INSERT INTO url_security_headers (url_status_id, header_name, header_value) VALUES (?, ?, ?)",
    )
    .bind(url_id)
    .bind(name)
    .bind(value)
    .execute(pool)
    .await
    .expect("insert security header");
}

/// Creates test data: URL with technologies, `GeoIP`, WHOIS, etc.
async fn create_test_url_with_enrichment(
    pool: &SqlitePool,
    domain: &str,
    run_id: Option<&str>,
) -> i64 {
    let url_id = create_test_url_status(pool, domain, domain, 200, run_id, 1704067200000).await;

    // Add technologies
    sqlx::query("INSERT INTO url_technologies (url_status_id, technology_name) VALUES (?, ?)")
        .bind(url_id)
        .bind("nginx")
        .execute(pool)
        .await
        .expect("Failed to insert technology");
    sqlx::query("INSERT INTO url_technologies (url_status_id, technology_name) VALUES (?, ?)")
        .bind(url_id)
        .bind("PHP")
        .execute(pool)
        .await
        .expect("Failed to insert technology");

    // Add redirect chain
    sqlx::query(
        "INSERT INTO url_redirect_chain (url_status_id, sequence_order, redirect_url) VALUES (?, ?, ?)",
    )
    .bind(url_id)
    .bind(0)
    .bind(format!("https://{}", domain))
    .execute(pool)
    .await
    .expect("Failed to insert redirect");

    // Add GeoIP
    sqlx::query(
        "INSERT INTO url_geoip (
            url_status_id, country_code, country_name, city, latitude, longitude, asn, asn_org
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(url_id)
    .bind("US")
    .bind("United States")
    .bind("San Francisco")
    .bind(37.7749)
    .bind(-122.4194)
    .bind(15169)
    .bind("GOOGLE")
    .execute(pool)
    .await
    .expect("Failed to insert GeoIP");

    // Add WHOIS
    sqlx::query(
        "INSERT INTO url_whois (
            url_status_id, registrar, creation_date_ms, expiration_date_ms, registrant_country
        ) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(url_id)
    .bind("Test Registrar")
    .bind(1609459200000i64) // 2021-01-01 in ms
    .bind(1735689600000i64) // 2025-01-01 in ms
    .bind("US")
    .execute(pool)
    .await
    .expect("Failed to insert WHOIS");

    // Add analytics IDs
    sqlx::query(
        "INSERT INTO url_analytics_ids (url_status_id, provider, tracking_id) VALUES (?, ?, ?)",
    )
    .bind(url_id)
    .bind("Google Analytics")
    .bind("UA-123456-1")
    .execute(pool)
    .await
    .expect("Failed to insert analytics ID");

    // Add social media links
    sqlx::query(
        "INSERT INTO url_social_media_links (url_status_id, platform, profile_url) VALUES (?, ?, ?)",
    )
    .bind(url_id)
    .bind("LinkedIn")
    .bind("https://linkedin.com/company/test")
    .execute(pool)
    .await
    .expect("Failed to insert social media link");

    // Add certificate SANs
    sqlx::query("INSERT INTO url_certificate_sans (url_status_id, san_value) VALUES (?, ?)")
        .bind(url_id)
        .bind("example.com")
        .execute(pool)
        .await
        .expect("Failed to insert certificate SAN");

    // Add OIDs
    sqlx::query("INSERT INTO url_certificate_oids (url_status_id, oid) VALUES (?, ?)")
        .bind(url_id)
        .bind("1.3.6.1.4.1.11129.2.4.2")
        .execute(pool)
        .await
        .expect("Failed to insert OID");

    url_id
}

#[tokio::test]
async fn test_export_csv_basic() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;
    let output_path = temp_dir.path().join("output.csv");

    // Create test run first (required for foreign key)
    create_test_run(&pool, "test_run_1", 1704067200000).await;

    // Create test data
    create_test_url_with_enrichment(&pool, "example.com", Some("test_run_1")).await;
    create_test_url_status(
        &pool,
        "test.com",
        "test.com",
        200,
        Some("test_run_1"),
        1704067200000,
    )
    .await;

    drop(pool); // Close connection before export

    // Export CSV
    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: None,
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should succeed");

    assert_eq!(count, 2, "Should export 2 records");

    // Verify CSV file exists and has content
    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");
    let lines: Vec<&str> = csv_content.lines().collect();
    assert_eq!(lines.len(), 3, "Should have header + 2 data rows");

    // Verify header
    assert!(
        lines[0].contains("url") && lines[0].contains("technologies"),
        "Header should contain expected columns"
    );

    // Verify data rows contain expected data
    assert!(
        lines[1].contains("example.com") || lines[2].contains("example.com"),
        "CSV should contain example.com"
    );
    assert!(
        lines[1].contains("test.com") || lines[2].contains("test.com"),
        "CSV should contain test.com"
    );
}

#[tokio::test]
async fn test_export_csv_filter_by_run_id() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;
    let output_path = temp_dir.path().join("output.csv");

    // Create runs first (required for foreign key)
    create_test_run(&pool, "run_1", 1704067200000).await;
    create_test_run(&pool, "run_2", 1704067200000).await;

    // Create data with different run_ids
    create_test_url_status(
        &pool,
        "test1.com",
        "test1.com",
        200,
        Some("run_1"),
        1704067200000,
    )
    .await;
    create_test_url_status(
        &pool,
        "test2.com",
        "test2.com",
        200,
        Some("run_2"),
        1704067200000,
    )
    .await;

    drop(pool);

    // Export only run_1
    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path.clone()),
        format: ExportFormat::Csv,
        run_id: Some("run_1".to_string()),
        domain: None,
        status: None,
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should succeed");

    assert_eq!(count, 1, "Should export only 1 record for run_1");

    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");
    assert!(
        csv_content.contains("test1.com"),
        "CSV should contain test1.com"
    );
    assert!(
        !csv_content.contains("test2.com"),
        "CSV should not contain test2.com"
    );
}

#[tokio::test]
async fn test_export_csv_filter_by_domain() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;

    // Exact match on initial_domain or final_domain — not a substring.
    create_test_url_status(
        &pool,
        "example.com",
        "cdn.other.net",
        200,
        None,
        1704067200000,
    )
    .await;
    create_test_url_status(
        &pool,
        "start.other.net",
        "example.com",
        200,
        None,
        1704067200001,
    )
    .await;
    create_test_url_status(
        &pool,
        "example.org",
        "example.org",
        200,
        None,
        1704067200002,
    )
    .await;

    drop(pool);

    let exact_path = temp_dir.path().join("exact.csv");
    let exact_count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(exact_path.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: Some("example.com".to_string()),
        status: None,
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should succeed");
    assert_eq!(
        exact_count, 2,
        "exact --domain must match initial_domain or final_domain"
    );

    let csv_content = std::fs::read_to_string(&exact_path).expect("Should read CSV file");
    let (headers, rows) = csv_headers_and_rows(&csv_content);
    let pairs: Vec<(String, String)> = rows
        .iter()
        .map(|row| {
            (
                csv_named_field(&headers, row, "initial_domain"),
                csv_named_field(&headers, row, "final_domain"),
            )
        })
        .collect();
    assert!(pairs.contains(&("example.com".into(), "cdn.other.net".into())));
    assert!(pairs.contains(&("start.other.net".into(), "example.com".into())));
    assert!(
        !pairs
            .iter()
            .any(|(i, f)| i == "example.org" || f == "example.org"),
        "example.org must not match example.com"
    );

    let substr_path = temp_dir.path().join("substr.csv");
    let substr_count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(substr_path),
        format: ExportFormat::Csv,
        run_id: None,
        domain: Some("example".to_string()),
        status: None,
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should succeed");
    assert_eq!(
        substr_count, 0,
        "--domain is exact equality, not a substring match"
    );
}

#[tokio::test]
async fn test_export_csv_filter_by_status() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;
    let output_path = temp_dir.path().join("output.csv");

    create_test_url_status(&pool, "ok.com", "ok.com", 200, None, 1704067200000).await;
    create_test_url_status(&pool, "error.com", "error.com", 404, None, 1704067200000).await;

    drop(pool);

    // Filter by status 200
    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: Some(200),
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should succeed");

    assert_eq!(count, 1, "Should export only 1 record with status 200");

    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");
    assert!(csv_content.contains("ok.com"), "CSV should contain ok.com");
    assert!(
        !csv_content.contains("error.com"),
        "CSV should not contain error.com"
    );
}

#[tokio::test]
async fn test_export_csv_empty_database() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;
    let output_path = temp_dir.path().join("output.csv");
    drop(pool);

    // Export from empty database
    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: None,
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should succeed even with empty database");

    assert_eq!(count, 0, "Should export 0 records from empty database");

    // Verify CSV has only header
    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");
    let lines: Vec<&str> = csv_content.lines().collect();
    assert_eq!(lines.len(), 1, "Should have only header row");
    assert!(lines[0].contains("url"), "Header should be present");
}

#[tokio::test]
async fn test_export_csv_missing_relationships() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;
    let output_path = temp_dir.path().join("output.csv");

    // Create URL with NO enrichment data (no GeoIP, no WHOIS, no technologies)
    create_test_url_status(&pool, "bare.com", "bare.com", 200, None, 1704067200000).await;

    drop(pool);

    // Export should handle missing relationships gracefully
    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: None,
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should succeed even with missing relationships");

    assert_eq!(count, 1, "Should export 1 record");

    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");
    // Should have empty values for missing data, not crash
    assert!(
        csv_content.contains("bare.com"),
        "CSV should contain bare.com"
    );
}

#[tokio::test]
async fn test_export_csv_all_enrichment_data() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;
    let output_path = temp_dir.path().join("output.csv");

    // Create URL with all enrichment data
    create_test_url_with_enrichment(&pool, "full.com", None).await;

    drop(pool);

    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: None,
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should succeed");

    assert_eq!(count, 1, "Should export 1 record");

    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");
    let tech = csv_only_row_field(&csv_content, "technologies");
    assert!(tech.contains("nginx"), "technologies column: {tech}");
    assert!(tech.contains("PHP"), "technologies column: {tech}");
    assert_eq!(csv_only_row_field(&csv_content, "geoip_country_code"), "US");
    assert_eq!(
        csv_only_row_field(&csv_content, "whois_registrar"),
        "Test Registrar"
    );
    assert_eq!(
        csv_only_row_field(&csv_content, "analytics_ids"),
        "Google Analytics:UA-123456-1"
    );
    assert!(
        csv_only_row_field(&csv_content, "social_media_links").contains("LinkedIn:"),
        "social_media_links should include LinkedIn"
    );
}

#[tokio::test]
async fn test_export_csv_filter_combinations() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;
    let output_path = temp_dir.path().join("output.csv");

    // Create run first (required for foreign key)
    create_test_run(&pool, "run_1", 1704067200000).await;
    create_test_run(&pool, "run_2", 1704067200000).await;

    // Create data with different attributes
    create_test_url_status(
        &pool,
        "match.com",
        "match.com",
        200,
        Some("run_1"),
        1704067200000,
    )
    .await;
    create_test_url_status(
        &pool,
        "nomatch.com",
        "nomatch.com",
        404,
        Some("run_1"),
        1704067200000,
    )
    .await;
    create_test_url_status(
        &pool,
        "other.com",
        "other.com",
        200,
        Some("run_2"),
        1704067200000,
    )
    .await;

    drop(pool);

    // Filter by run_id AND status
    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path.clone()),
        format: ExportFormat::Csv,
        run_id: Some("run_1".to_string()),
        domain: None,
        status: Some(200),
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should succeed");

    assert_eq!(
        count, 1,
        "Should export only 1 record matching both filters"
    );

    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");
    assert!(
        csv_content.contains("match.com"),
        "CSV should contain match.com"
    );
    assert!(
        !csv_content.contains("nomatch.com"),
        "CSV should not contain nomatch.com (wrong status)"
    );
    assert!(
        !csv_content.contains("other.com"),
        "CSV should not contain other.com (wrong run_id)"
    );
}

#[tokio::test]
async fn test_export_csv_filter_by_since() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;
    let output_path = temp_dir.path().join("output.csv");

    // Create data with different timestamps
    create_test_url_status(&pool, "old.com", "old.com", 200, None, 1609459200000).await; // 2021-01-01
    create_test_url_status(&pool, "new.com", "new.com", 200, None, 1704067200000).await; // 2024-01-01

    drop(pool);

    // Filter by since (after 2022-01-01)
    let since_timestamp = 1640995200000i64; // 2022-01-01
    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: None,
        since: Some(since_timestamp),
        include_implied_tech: false,
    })
    .await
    .expect("Export should succeed");

    assert_eq!(count, 1, "Should export only 1 record after timestamp");

    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");
    assert!(
        csv_content.contains("new.com"),
        "CSV should contain new.com"
    );
    assert!(
        !csv_content.contains("old.com"),
        "CSV should not contain old.com (too old)"
    );
}

#[tokio::test]
async fn test_export_csv_stdout() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;

    create_test_url_status(&pool, "stdout.com", "stdout.com", 200, None, 1704067200000).await;

    drop(pool);

    // Use a temporary file instead of stdout to avoid polluting test output
    // This tests the same code path (writing to a file) without stdout pollution
    let stdout_test_path = temp_dir.path().join("stdout_test.csv");
    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(stdout_test_path.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: None,
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should succeed");

    assert_eq!(count, 1, "Should export 1 record");

    // Verify the output contains expected data (simulates stdout behavior)
    let content = std::fs::read_to_string(&stdout_test_path).expect("Should read output file");
    assert!(
        content.contains("stdout.com"),
        "Output should contain domain"
    );
    assert!(
        content.contains("url,initial_domain"),
        "Output should contain CSV header"
    );
}

#[tokio::test]
async fn test_export_csv_date_formatting() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;
    let output_path = temp_dir.path().join("output.csv");

    let url_id =
        create_test_url_status(&pool, "date.com", "date.com", 200, None, 1704067200000).await;

    // Add SSL cert with valid_to date
    sqlx::query("UPDATE url_status SET ssl_cert_valid_to_ms = ? WHERE id = ?")
        .bind(1735689600000i64) // 2025-01-01 in milliseconds
        .bind(url_id)
        .execute(&pool)
        .await
        .expect("Failed to update SSL cert date");

    // Add WHOIS with dates
    sqlx::query(
        "INSERT INTO url_whois (
            url_status_id, creation_date_ms, expiration_date_ms
        ) VALUES (?, ?, ?)",
    )
    .bind(url_id)
    .bind(1609459200000i64) // 2021-01-01 in milliseconds
    .bind(1735689600000i64) // 2025-01-01 in milliseconds
    .execute(&pool)
    .await
    .expect("Failed to insert WHOIS");

    drop(pool);

    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: None,
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should succeed");

    assert_eq!(count, 1, "Should export 1 record");

    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");

    // Verify dates are formatted correctly (YYYY-MM-DD format)
    assert!(
        csv_content.contains("2025-01-01"),
        "CSV should contain formatted SSL cert date"
    );
    assert!(
        csv_content.contains("2021-01-01"),
        "CSV should contain formatted WHOIS creation date"
    );
}

#[tokio::test]
async fn test_export_csv_comma_separated_lists() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;
    let output_path = temp_dir.path().join("output.csv");

    let url_id =
        create_test_url_status(&pool, "list.com", "list.com", 200, None, 1704067200000).await;

    // Add multiple technologies
    for tech in ["nginx", "PHP", "WordPress", "MySQL"] {
        sqlx::query("INSERT INTO url_technologies (url_status_id, technology_name) VALUES (?, ?)")
            .bind(url_id)
            .bind(tech)
            .execute(&pool)
            .await
            .expect("Failed to insert technology");
    }

    // Add multiple analytics IDs
    sqlx::query(
        "INSERT INTO url_analytics_ids (url_status_id, provider, tracking_id) VALUES (?, ?, ?)",
    )
    .bind(url_id)
    .bind("Google Analytics")
    .bind("UA-111-1")
    .execute(&pool)
    .await
    .expect("Failed to insert analytics ID");
    sqlx::query(
        "INSERT INTO url_analytics_ids (url_status_id, provider, tracking_id) VALUES (?, ?, ?)",
    )
    .bind(url_id)
    .bind("Google Tag Manager")
    .bind("GTM-XXXXX")
    .execute(&pool)
    .await
    .expect("Failed to insert analytics ID");

    drop(pool);

    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: None,
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should succeed");

    assert_eq!(count, 1, "Should export 1 record");

    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");
    let tech = csv_only_row_field(&csv_content, "technologies");
    for name in ["nginx", "PHP", "WordPress", "MySQL"] {
        assert!(
            tech.contains(name),
            "technologies should contain {name}: {tech}"
        );
    }
    assert_eq!(csv_only_row_field(&csv_content, "technology_count"), "4");
    let analytics = csv_only_row_field(&csv_content, "analytics_ids");
    assert!(
        analytics.contains("Google Analytics:UA-111-1"),
        "analytics_ids: {analytics}"
    );
    assert!(
        analytics.contains("Google Tag Manager:GTM-XXXXX"),
        "analytics_ids: {analytics}"
    );
}

#[tokio::test]
async fn test_export_csv_all_columns_present() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;
    let output_path = temp_dir.path().join("output.csv");
    create_test_url_with_enrichment(&pool, "full.com", None).await;
    drop(pool);

    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: None,
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should succeed");

    assert_eq!(count, 1, "Should export 1 record");

    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");
    let (headers, rows) = csv_headers_and_rows(&csv_content);
    assert_eq!(rows.len(), 1, "Should have header + 1 data row");
    assert_eq!(
        headers.len(),
        rows[0].len(),
        "Data row should have same number of fields as header ({} vs {})",
        headers.len(),
        rows[0].len()
    );
}

#[tokio::test]
async fn test_export_csv_null_handling() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;
    let output_path = temp_dir.path().join("output.csv");

    // Create URL with many NULL/empty fields
    let url_id = create_test_url_status(
        &pool,
        "nulltest.com",
        "nulltest.com",
        200,
        None,
        1704067200000,
    )
    .await;

    // Explicitly set some fields to NULL
    sqlx::query("UPDATE url_status SET reverse_dns_name = NULL, description = NULL, tls_version = NULL WHERE id = ?")
        .bind(url_id)
        .execute(&pool)
        .await
        .expect("Failed to update with NULLs");

    drop(pool);

    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: None,
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should handle NULL values");

    assert_eq!(count, 1, "Should export 1 record");

    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");
    let lines: Vec<&str> = csv_content.lines().collect();
    let data_row = lines[1];

    // NULL values should be exported as empty strings, not crash
    assert!(
        data_row.contains("nulltest.com"),
        "CSV should contain domain even with NULL fields"
    );
    // Verify row is valid CSV (has correct number of fields)
    // Use CSV parser to properly handle quoted fields
    use csv::ReaderBuilder;
    let mut reader = ReaderBuilder::new()
        .has_headers(false)
        .from_reader(data_row.as_bytes());
    let record = reader
        .records()
        .next()
        .expect("Should read data row")
        .expect("Should parse data row");
    assert!(
        record.len() >= 50,
        "Data row should have all fields even with NULLs (got {})",
        record.len()
    );
}

#[tokio::test]
async fn test_export_csv_no_redirects_still_exports_final_domain() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;
    let output_path = temp_dir.path().join("output.csv");
    let _url_id = create_test_url_status(
        &pool,
        "redirect.com",
        "final.com",
        200,
        None,
        1704067200000i64,
    )
    .await;
    drop(pool);

    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: None,
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should handle no redirects");

    assert_eq!(count, 1, "Should export 1 record");

    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");
    assert!(
        csv_content.contains("final.com"),
        "CSV should contain final_domain when no redirects"
    );
}

#[tokio::test]
async fn test_export_csv_redirect_chain_edge_cases() {
    let (temp_dir, db_path, pool2) = setup_export_fixture().await;
    let url_id2 =
        create_test_url_status(&pool2, "start.com", "end.com", 200, None, 1704067300000i64).await;

    for (i, url) in ["https://start.com", "https://middle.com", "https://end.com"]
        .iter()
        .enumerate()
    {
        sqlx::query(
            "INSERT INTO url_redirect_chain (url_status_id, sequence_order, redirect_url) VALUES (?, ?, ?)",
        )
        .bind(url_id2)
        .bind(i as i64)
        .bind(*url)
        .execute(&pool2)
        .await
        .expect("Failed to insert redirect");
    }

    drop(pool2);

    let output_path2 = temp_dir.path().join("output2.csv");
    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path2.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: None,
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should handle multiple redirects");

    assert_eq!(count, 1, "Should export 1 record");

    let csv_content = std::fs::read_to_string(&output_path2).expect("Should read CSV file");
    // Should contain final redirect URL
    assert!(
        csv_content.contains("https://end.com"),
        "CSV should contain final redirect URL"
    );
    // Redirect count should be 3
    // Use CSV parser to properly extract the redirect_count field, looking it up by
    // header name rather than a hardcoded ordinal (column order shifts as fields are added).
    use csv::ReaderBuilder;
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .from_reader(csv_content.as_bytes());
    let headers = reader.headers().expect("Should read headers").clone();
    let redirect_count_idx = headers
        .iter()
        .position(|h| h == "redirect_count")
        .expect("Should have redirect_count column");
    let final_redirect_url_idx = headers
        .iter()
        .position(|h| h == "final_redirect_url")
        .expect("Should have final_redirect_url column");

    let mut found_start = false;
    for result in reader.records() {
        let record = result.expect("Should parse CSV record");
        // Check if this row is for start.com (could be in url, initial_domain, or final_domain fields)
        let url = record.get(0).unwrap_or("");
        let initial_domain = record.get(1).unwrap_or("");
        let final_domain = record.get(2).unwrap_or("");
        if url.contains("start.com")
            || initial_domain.contains("start.com")
            || final_domain.contains("start.com")
        {
            let redirect_count = record
                .get(redirect_count_idx)
                .expect("Should have redirect_count field");
            assert_eq!(
                redirect_count, "3",
                "CSV should show redirect count of 3 for start.com"
            );
            let final_redirect_url = record
                .get(final_redirect_url_idx)
                .expect("Should have final_redirect_url field");
            assert_eq!(
                final_redirect_url, "https://end.com",
                "final_redirect_url should be the last redirect hop when redirect_count > 0"
            );
            found_start = true;
        }
    }
    assert!(found_start, "Should find start.com in CSV");
}

/// Contract: when `redirect_count == 0`, `final_redirect_url` must be empty — never a
/// fallback to `final_domain`. Callers that want the effective URL already have
/// `final_domain`; a non-empty `final_redirect_url` should mean "a redirect actually
/// happened". This matches JSONL's existing behavior (see `export_row.final_redirect_url`).
#[tokio::test]
async fn test_export_csv_final_redirect_url_empty_when_no_redirects() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;
    let output_path = temp_dir.path().join("output.csv");
    create_test_url_status(
        &pool,
        "noredirect.com",
        "noredirect.com",
        200,
        None,
        1704067200000,
    )
    .await;
    // No rows in url_redirect_chain: redirect_count must be 0.
    drop(pool);

    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: None,
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should succeed");
    assert_eq!(count, 1);

    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");
    use csv::ReaderBuilder;
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .from_reader(csv_content.as_bytes());
    let headers = reader.headers().expect("Should read headers").clone();
    let redirect_count_idx = headers
        .iter()
        .position(|h| h == "redirect_count")
        .expect("Should have redirect_count column");
    let final_redirect_url_idx = headers
        .iter()
        .position(|h| h == "final_redirect_url")
        .expect("Should have final_redirect_url column");

    let record = reader
        .records()
        .next()
        .expect("Should have one data row")
        .expect("Should parse CSV record");
    assert_eq!(record.get(redirect_count_idx), Some("0"));
    assert_eq!(
        record.get(final_redirect_url_idx),
        Some(""),
        "final_redirect_url must be empty when redirect_count is 0, not final_domain"
    );
}

/// Contract: `body_truncated` (scan-completeness signal from migration
/// `0009_secrets_scan_completeness.sql`) must be surfaced as a named CSV column.
#[tokio::test]
async fn test_export_csv_body_truncated_column_present() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;
    let output_path = temp_dir.path().join("output.csv");
    let url_id = create_test_url_status(
        &pool,
        "truncated.com",
        "truncated.com",
        200,
        None,
        1704067200000,
    )
    .await;
    sqlx::query("UPDATE url_status SET body_truncated = 1 WHERE id = ?")
        .bind(url_id)
        .execute(&pool)
        .await
        .expect("Failed to set body_truncated");
    drop(pool);

    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: None,
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should succeed");
    assert_eq!(count, 1);

    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");
    use csv::ReaderBuilder;
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .from_reader(csv_content.as_bytes());
    let headers = reader.headers().expect("Should read headers").clone();
    let body_truncated_idx = headers
        .iter()
        .position(|h| h == "body_truncated")
        .expect("Should have body_truncated column");

    let record = reader
        .records()
        .next()
        .expect("Should have one data row")
        .expect("Should parse CSV record");
    assert_eq!(record.get(body_truncated_idx), Some("true"));
}

#[tokio::test]
async fn test_export_csv_header_filtering() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;
    let output_path = temp_dir.path().join("output.csv");
    let url_id = create_test_url_status(
        &pool,
        "headers.com",
        "headers.com",
        200,
        None,
        1704067200000,
    )
    .await;

    for (name, value) in [
        ("Content-Type", "text/html; charset=utf-8"),
        ("Server", "nginx/1.18.0"),
        ("X-Custom-Header", "should-not-appear"),
    ] {
        insert_http_header(&pool, url_id, name, value).await;
    }
    for (name, value) in [
        ("Content-Security-Policy", "default-src 'self'"),
        ("X-Frame-Options", "DENY"),
        ("X-Other-Header", "should-not-appear"),
    ] {
        insert_security_header(&pool, url_id, name, value).await;
    }

    drop(pool);

    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: None,
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should filter headers");

    assert_eq!(count, 1, "Should export 1 record");

    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");
    let http = csv_only_row_field(&csv_content, "http_headers");
    assert!(
        http.contains("Content-Type:text/html; charset=utf-8"),
        "http_headers: {http}"
    );
    assert!(http.contains("Server:nginx/1.18.0"), "http_headers: {http}");
    assert!(
        !http.contains("X-Custom-Header"),
        "unfiltered header must not appear in http_headers: {http}"
    );
    let security = csv_only_row_field(&csv_content, "security_headers");
    assert!(
        security.contains("Content-Security-Policy:default-src 'self'"),
        "security_headers: {security}"
    );
    assert!(
        security.contains("X-Frame-Options:DENY"),
        "security_headers: {security}"
    );
    assert!(
        !security.contains("X-Other-Header"),
        "unfiltered header must not appear in security_headers: {security}"
    );
    assert_eq!(csv_only_row_field(&csv_content, "http_header_count"), "3");
    assert_eq!(
        csv_only_row_field(&csv_content, "security_header_count"),
        "3"
    );
}

#[tokio::test]
async fn test_export_csv_unicode_and_special_chars() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;
    let output_path = temp_dir.path().join("output.csv");
    let url_id = create_test_url_status(
        &pool,
        "unicode.com",
        "unicode.com",
        200,
        None,
        1704067200000,
    )
    .await;

    // Insert data with unicode and special characters
    sqlx::query("UPDATE url_status SET title = ? WHERE id = ?")
        .bind("Test Title with émojis 🚀 and \"quotes\"")
        .bind(url_id)
        .execute(&pool)
        .await
        .expect("Failed to update title");

    sqlx::query("INSERT INTO url_technologies (url_status_id, technology_name) VALUES (?, ?)")
        .bind(url_id)
        .bind("Tech with, commas & \"quotes\"")
        .execute(&pool)
        .await
        .expect("Failed to insert technology");

    drop(pool);

    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: None,
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("Export should handle unicode and special chars");

    assert_eq!(count, 1, "Should export 1 record");

    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");
    assert_eq!(
        csv_only_row_field(&csv_content, "title"),
        "Test Title with émojis 🚀 and \"quotes\""
    );
    assert!(
        csv_only_row_field(&csv_content, "technologies").contains("Tech with, commas & \"quotes\""),
        "quoted commas in technology names must round-trip"
    );
}

/// Default export omits `is_implied = 1` fingerprint rows; `--include-implied-tech` includes them.
#[tokio::test]
async fn test_export_csv_include_implied_tech_on_off() {
    let (temp_dir, db_path, pool) = setup_export_fixture().await;
    let url_id = create_test_url_status(
        &pool,
        "implied.com",
        "implied.com",
        200,
        None,
        1704067200000,
    )
    .await;
    sqlx::query(
        "INSERT INTO url_technologies (url_status_id, technology_name, is_implied) VALUES (?, ?, ?)",
    )
    .bind(url_id)
    .bind("nginx")
    .bind(0i64)
    .execute(&pool)
    .await
    .expect("insert observed tech");
    sqlx::query(
        "INSERT INTO url_technologies (url_status_id, technology_name, is_implied) VALUES (?, ?, ?)",
    )
    .bind(url_id)
    .bind("PHP")
    .bind(1i64)
    .execute(&pool)
    .await
    .expect("insert implied tech");
    drop(pool);

    let off_path = temp_dir.path().join("off.csv");
    export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(off_path.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: None,
        since: None,
        include_implied_tech: false,
    })
    .await
    .expect("export off");
    let off = std::fs::read_to_string(&off_path).expect("read off");
    let tech_off = csv_only_row_field(&off, "technologies");
    assert!(
        tech_off.contains("nginx"),
        "observed tech must export: {tech_off}"
    );
    assert!(
        !tech_off.contains("PHP"),
        "implied tech must be omitted by default: {tech_off}"
    );
    assert_eq!(csv_only_row_field(&off, "technology_count"), "1");

    let on_path = temp_dir.path().join("on.csv");
    export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(on_path.clone()),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: None,
        since: None,
        include_implied_tech: true,
    })
    .await
    .expect("export on");
    let on = std::fs::read_to_string(&on_path).expect("read on");
    let tech_on = csv_only_row_field(&on, "technologies");
    assert!(tech_on.contains("nginx"), "observed tech: {tech_on}");
    assert!(
        tech_on.contains("PHP"),
        "implied tech with flag on: {tech_on}"
    );
    assert_eq!(csv_only_row_field(&on, "technology_count"), "2");
}
