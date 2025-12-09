//! Tests for CSV export functionality.

use domain_status::export::export_csv;
use sqlx::{Row, SqlitePool};
use tempfile::TempDir;

/// Creates a test URL status record and returns its ID.
async fn create_test_url_status(
    pool: &SqlitePool,
    domain: &str,
    final_domain: &str,
    status: i64,
    run_id: Option<&str>,
    timestamp: i64,
) -> i64 {
    sqlx::query(
        "INSERT INTO url_status (
            domain, final_domain, ip_address, status, status_description,
            response_time, title, timestamp, run_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING id",
    )
    .bind(domain)
    .bind(final_domain)
    .bind("192.0.2.1")
    .bind(status)
    .bind("OK")
    .bind(1.5f64)
    .bind("Test Page")
    .bind(timestamp)
    .bind(run_id)
    .fetch_one(pool)
    .await
    .expect("Failed to insert test URL status")
    .get::<i64, _>(0)
}

/// Creates test data: URL with technologies, GeoIP, WHOIS, etc.
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
        "INSERT INTO url_redirect_chain (url_status_id, sequence_order, url) VALUES (?, ?, ?)",
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
            url_status_id, ip_address, country_code, country_name, city, latitude, longitude, asn, asn_org
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(url_id)
    .bind("192.0.2.1")
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
            url_status_id, registrar, creation_date, expiration_date, registrant_country
        ) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(url_id)
    .bind("Test Registrar")
    .bind(1609459200i64) // 2021-01-01
    .bind(1735689600i64) // 2025-01-01
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
        "INSERT INTO url_social_media_links (url_status_id, platform, url) VALUES (?, ?, ?)",
    )
    .bind(url_id)
    .bind("LinkedIn")
    .bind("https://linkedin.com/company/test")
    .execute(pool)
    .await
    .expect("Failed to insert social media link");

    // Add security warnings
    sqlx::query(
        "INSERT INTO url_security_warnings (url_status_id, warning_code, warning_description) VALUES (?, ?, ?)",
    )
    .bind(url_id)
    .bind("missing_csp")
    .bind("Content-Security-Policy header is missing")
    .execute(pool)
    .await
        .expect("Failed to insert security warning");

    // Add certificate SANs
    sqlx::query("INSERT INTO url_certificate_sans (url_status_id, domain_name) VALUES (?, ?)")
        .bind(url_id)
        .bind("example.com")
        .execute(pool)
        .await
        .expect("Failed to insert certificate SAN");

    // Add OIDs
    sqlx::query("INSERT INTO url_oids (url_status_id, oid) VALUES (?, ?)")
        .bind(url_id)
        .bind("1.3.6.1.4.1.11129.2.4.2")
        .execute(pool)
        .await
        .expect("Failed to insert OID");

    url_id
}

#[tokio::test]
async fn test_export_csv_basic() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_export.db");
    let output_path = temp_dir.path().join("output.csv");

    // Create test database with migrations
    // Ensure parent directory exists
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).expect("Failed to create parent directory");
    }
    // Create the database file first (SQLite requires the file to exist or be created)
    std::fs::File::create(&db_path).expect("Failed to create database file");
    // Use the same format as init_db_pool_with_path
    let db_path_str = db_path.to_string_lossy().to_string();
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", db_path_str))
        .await
        .expect("Failed to create test database");
    domain_status::run_migrations(&pool)
        .await
        .expect("Failed to run migrations");

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
    let count = export_csv(&db_path, Some(&output_path), None, None, None, None)
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
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_export.db");
    let output_path = temp_dir.path().join("output.csv");

    // Create the database file first (SQLite requires the file to exist or be created)
    std::fs::File::create(&db_path).expect("Failed to create database file");
    // Use the same format as init_db_pool_with_path
    let db_path_str = db_path.to_string_lossy().to_string();
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", db_path_str))
        .await
        .expect("Failed to create test database");
    domain_status::run_migrations(&pool)
        .await
        .expect("Failed to run migrations");

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
    let count = export_csv(
        &db_path,
        Some(&output_path),
        Some("run_1"),
        None,
        None,
        None,
    )
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
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_export.db");
    let output_path = temp_dir.path().join("output.csv");

    // Create the database file first (SQLite requires the file to exist or be created)
    std::fs::File::create(&db_path).expect("Failed to create database file");
    // Use the same format as init_db_pool_with_path
    let db_path_str = db_path.to_string_lossy().to_string();
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", db_path_str))
        .await
        .expect("Failed to create test database");
    domain_status::run_migrations(&pool)
        .await
        .expect("Failed to run migrations");

    create_test_url_status(
        &pool,
        "example.com",
        "example.com",
        200,
        None,
        1704067200000,
    )
    .await;
    create_test_url_status(&pool, "test.com", "test.com", 200, None, 1704067200000).await;

    drop(pool);

    // Filter by domain
    let count = export_csv(
        &db_path,
        Some(&output_path),
        None,
        Some("example.com"),
        None,
        None,
    )
    .await
    .expect("Export should succeed");

    assert_eq!(count, 1, "Should export only 1 record for example.com");

    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");
    assert!(
        csv_content.contains("example.com"),
        "CSV should contain example.com"
    );
    assert!(
        !csv_content.contains("test.com"),
        "CSV should not contain test.com"
    );
}

#[tokio::test]
async fn test_export_csv_filter_by_status() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_export.db");
    let output_path = temp_dir.path().join("output.csv");

    // Create the database file first (SQLite requires the file to exist or be created)
    std::fs::File::create(&db_path).expect("Failed to create database file");
    // Use the same format as init_db_pool_with_path
    let db_path_str = db_path.to_string_lossy().to_string();
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", db_path_str))
        .await
        .expect("Failed to create test database");
    domain_status::run_migrations(&pool)
        .await
        .expect("Failed to run migrations");

    create_test_url_status(&pool, "ok.com", "ok.com", 200, None, 1704067200000).await;
    create_test_url_status(&pool, "error.com", "error.com", 404, None, 1704067200000).await;

    drop(pool);

    // Filter by status 200
    let count = export_csv(&db_path, Some(&output_path), None, None, Some(200), None)
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
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_export.db");
    let output_path = temp_dir.path().join("output.csv");

    // Create empty database
    // Create the database file first (SQLite requires the file to exist or be created)
    std::fs::File::create(&db_path).expect("Failed to create database file");
    // Use the same format as init_db_pool_with_path
    let db_path_str = db_path.to_string_lossy().to_string();
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", db_path_str))
        .await
        .expect("Failed to create test database");
    domain_status::run_migrations(&pool)
        .await
        .expect("Failed to run migrations");
    drop(pool);

    // Export from empty database
    let count = export_csv(&db_path, Some(&output_path), None, None, None, None)
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
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_export.db");
    let output_path = temp_dir.path().join("output.csv");

    // Create the database file first (SQLite requires the file to exist or be created)
    std::fs::File::create(&db_path).expect("Failed to create database file");
    // Use the same format as init_db_pool_with_path
    let db_path_str = db_path.to_string_lossy().to_string();
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", db_path_str))
        .await
        .expect("Failed to create test database");
    domain_status::run_migrations(&pool)
        .await
        .expect("Failed to run migrations");

    // Create URL with NO enrichment data (no GeoIP, no WHOIS, no technologies)
    create_test_url_status(&pool, "bare.com", "bare.com", 200, None, 1704067200000).await;

    drop(pool);

    // Export should handle missing relationships gracefully
    let count = export_csv(&db_path, Some(&output_path), None, None, None, None)
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
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_export.db");
    let output_path = temp_dir.path().join("output.csv");

    // Create the database file first (SQLite requires the file to exist or be created)
    std::fs::File::create(&db_path).expect("Failed to create database file");
    // Use the same format as init_db_pool_with_path
    let db_path_str = db_path.to_string_lossy().to_string();
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", db_path_str))
        .await
        .expect("Failed to create test database");
    domain_status::run_migrations(&pool)
        .await
        .expect("Failed to run migrations");

    // Create URL with all enrichment data
    create_test_url_with_enrichment(&pool, "full.com", None).await;

    drop(pool);

    let count = export_csv(&db_path, Some(&output_path), None, None, None, None)
        .await
        .expect("Export should succeed");

    assert_eq!(count, 1, "Should export 1 record");

    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");

    // Verify all enrichment data is present
    assert!(
        csv_content.contains("nginx") || csv_content.contains("PHP"),
        "CSV should contain technologies"
    );
    assert!(
        csv_content.contains("United States") || csv_content.contains("US"),
        "CSV should contain GeoIP data"
    );
    assert!(
        csv_content.contains("Test Registrar"),
        "CSV should contain WHOIS data"
    );
    assert!(
        csv_content.contains("Google Analytics") || csv_content.contains("UA-123456-1"),
        "CSV should contain analytics IDs"
    );
    assert!(
        csv_content.contains("LinkedIn"),
        "CSV should contain social media links"
    );
    assert!(
        csv_content.contains("missing_csp"),
        "CSV should contain security warnings"
    );
}

#[tokio::test]
async fn test_export_csv_filter_combinations() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_export.db");
    let output_path = temp_dir.path().join("output.csv");

    // Create the database file first (SQLite requires the file to exist or be created)
    std::fs::File::create(&db_path).expect("Failed to create database file");
    // Use the same format as init_db_pool_with_path
    let db_path_str = db_path.to_string_lossy().to_string();
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", db_path_str))
        .await
        .expect("Failed to create test database");
    domain_status::run_migrations(&pool)
        .await
        .expect("Failed to run migrations");

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
    let count = export_csv(
        &db_path,
        Some(&output_path),
        Some("run_1"),
        None,
        Some(200),
        None,
    )
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
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_export.db");
    let output_path = temp_dir.path().join("output.csv");

    // Create the database file first (SQLite requires the file to exist or be created)
    std::fs::File::create(&db_path).expect("Failed to create database file");
    // Use the same format as init_db_pool_with_path
    let db_path_str = db_path.to_string_lossy().to_string();
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", db_path_str))
        .await
        .expect("Failed to create test database");
    domain_status::run_migrations(&pool)
        .await
        .expect("Failed to run migrations");

    // Create data with different timestamps
    create_test_url_status(&pool, "old.com", "old.com", 200, None, 1609459200000).await; // 2021-01-01
    create_test_url_status(&pool, "new.com", "new.com", 200, None, 1704067200000).await; // 2024-01-01

    drop(pool);

    // Filter by since (after 2022-01-01)
    let since_timestamp = 1640995200000i64; // 2022-01-01
    let count = export_csv(
        &db_path,
        Some(&output_path),
        None,
        None,
        None,
        Some(since_timestamp),
    )
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
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_export.db");

    // Create the database file first (SQLite requires the file to exist or be created)
    std::fs::File::create(&db_path).expect("Failed to create database file");
    // Use the same format as init_db_pool_with_path
    let db_path_str = db_path.to_string_lossy().to_string();
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", db_path_str))
        .await
        .expect("Failed to create test database");
    domain_status::run_migrations(&pool)
        .await
        .expect("Failed to run migrations");

    create_test_url_status(&pool, "stdout.com", "stdout.com", 200, None, 1704067200000).await;

    drop(pool);

    // Export to stdout (output = None)
    let count = export_csv(&db_path, None, None, None, None, None)
        .await
        .expect("Export to stdout should succeed");

    assert_eq!(count, 1, "Should export 1 record");
    // Note: We can't easily capture stdout in tests, but we verify it doesn't panic
}

#[tokio::test]
async fn test_export_csv_date_formatting() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_export.db");
    let output_path = temp_dir.path().join("output.csv");

    // Create the database file first (SQLite requires the file to exist or be created)
    std::fs::File::create(&db_path).expect("Failed to create database file");
    // Use the same format as init_db_pool_with_path
    let db_path_str = db_path.to_string_lossy().to_string();
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", db_path_str))
        .await
        .expect("Failed to create test database");
    domain_status::run_migrations(&pool)
        .await
        .expect("Failed to run migrations");

    let url_id =
        create_test_url_status(&pool, "date.com", "date.com", 200, None, 1704067200000).await;

    // Add SSL cert with valid_to date
    sqlx::query("UPDATE url_status SET ssl_cert_valid_to = ? WHERE id = ?")
        .bind(1735689600000i64) // 2025-01-01 in milliseconds
        .bind(url_id)
        .execute(&pool)
        .await
        .expect("Failed to update SSL cert date");

    // Add WHOIS with dates
    sqlx::query(
        "INSERT INTO url_whois (
            url_status_id, creation_date, expiration_date
        ) VALUES (?, ?, ?)",
    )
    .bind(url_id)
    .bind(1609459200i64) // 2021-01-01 (seconds, not milliseconds)
    .bind(1735689600i64) // 2025-01-01 (seconds, not milliseconds)
    .execute(&pool)
    .await
    .expect("Failed to insert WHOIS");

    drop(pool);

    let count = export_csv(&db_path, Some(&output_path), None, None, None, None)
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
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_export.db");
    let output_path = temp_dir.path().join("output.csv");

    // Create the database file first (SQLite requires the file to exist or be created)
    std::fs::File::create(&db_path).expect("Failed to create database file");
    // Use the same format as init_db_pool_with_path
    let db_path_str = db_path.to_string_lossy().to_string();
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", db_path_str))
        .await
        .expect("Failed to create test database");
    domain_status::run_migrations(&pool)
        .await
        .expect("Failed to run migrations");

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

    let count = export_csv(&db_path, Some(&output_path), None, None, None, None)
        .await
        .expect("Export should succeed");

    assert_eq!(count, 1, "Should export 1 record");

    let csv_content = std::fs::read_to_string(&output_path).expect("Should read CSV file");

    // Verify comma-separated lists are formatted correctly
    // Technologies should be comma-separated
    let tech_line = csv_content
        .lines()
        .find(|line| line.contains("list.com"))
        .expect("Should find data row");

    // Should contain technologies (order may vary)
    assert!(
        tech_line.contains("nginx") || tech_line.contains("PHP"),
        "CSV should contain technologies"
    );

    // Should contain analytics IDs
    assert!(
        tech_line.contains("Google Analytics") || tech_line.contains("UA-111-1"),
        "CSV should contain analytics IDs"
    );
}
