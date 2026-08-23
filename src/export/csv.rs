//! CSV export functionality.
//!
//! Exports `domain_status` data to CSV format (simplified, flattened view).
//! One row per URL with all related data flattened into columns.
//!
//! Column names and cell extractors come from the shared [`super::fields`] registry.

use anyhow::Result;
use csv::Writer;
use std::io::{self, Write};

use crate::utils::IoErrorContext;

use super::bootstrap::for_each_export_row;
use super::fields;
use super::queries::IgnoreBrokenPipe;

/// Column names derived from the shared registry (same order as cell extractors).
pub(crate) fn csv_column_names() -> impl Iterator<Item = &'static str> {
    fields::csv_column_names()
}

fn csv_record_cells(row: &super::row::ExportRow) -> Vec<String> {
    fields::csv_record_cells(row)
}

/// Exports data to CSV format.
///
/// CSV output flattens multi-valued relationships into delimited string columns so
/// the result is easy to open in spreadsheet tools.
///
/// # Errors
/// Returns `Err` when the database pool cannot be created, the query fails, or writing the output fails.
pub async fn export_csv(opts: &super::ExportOptions) -> Result<usize> {
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

    writer
        .write_record(csv_column_names().collect::<Vec<_>>())
        .map_err(anyhow::Error::from)?;

    let record_count = for_each_export_row(opts, |export_row| {
        writer
            .write_record(csv_record_cells(&export_row))
            .map_err(anyhow::Error::from)?;
        Ok(())
    })
    .await?;

    writer.flush()?;
    Ok(record_count)
}

#[cfg(test)]
mod tests {
    use super::super::queries::{
        fetch_count_query, fetch_filtered_http_headers, fetch_key_value_list, fetch_string_list,
        HttpHeadersTable,
    };
    use crate::storage::test_helpers::{create_test_pool, create_test_url_status_default};
    use crate::storage::{run_migrations, DbPool};
    use sqlx::SqlitePool;
    use std::sync::Arc;
    use tempfile::NamedTempFile;

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
