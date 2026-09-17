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
    use super::super::types::{ExportFormat, ExportOptions};
    use super::export_csv;
    use crate::storage::run_migrations;
    use crate::storage::test_helpers::create_test_url_status_default;
    use sqlx::SqlitePool;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_csv_export_new_columns_populated() {
        let temp_db = NamedTempFile::new().expect("temp DB");
        let db_path = temp_db.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .expect("Failed to create pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");
        let url_id = create_test_url_status_default(&pool).await;

        sqlx::query("INSERT INTO url_nameservers (url_status_id, nameserver) VALUES (?, ?)")
            .bind(url_id)
            .bind("ns1.test.com")
            .execute(&pool)
            .await
            .unwrap();

        sqlx::query(
            "INSERT INTO url_mx_records (url_status_id, priority, mail_exchange) VALUES (?, ?, ?)",
        )
        .bind(url_id)
        .bind(10)
        .bind("mail.test.com")
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query("INSERT INTO url_social_media_links (url_status_id, platform, profile_url, identifier) VALUES (?, ?, ?, ?)")
            .bind(url_id)
            .bind("GitHub")
            .bind("https://github.com/testuser")
            .bind("testuser")
            .execute(&pool)
            .await
            .unwrap();

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

        let contents = std::fs::read_to_string(&output_path).unwrap();
        let lines: Vec<&str> = contents.trim().split('\n').collect();
        assert_eq!(lines.len(), 2, "Should have header + 1 data row");

        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .from_reader(contents.as_bytes());
        let headers = reader.headers().expect("headers").clone();
        let record = reader.records().next().expect("row").expect("parse");
        let ns_idx = headers
            .iter()
            .position(|h| h == "nameservers")
            .expect("Should have nameservers column");
        assert!(
            record
                .get(ns_idx)
                .is_some_and(|v| v.contains("ns1.test.com")),
            "nameservers column should contain ns1.test.com, got: {:?}",
            record.get(ns_idx)
        );

        let pfc_idx = headers
            .iter()
            .position(|h| h == "partial_failure_count")
            .expect("Should have partial_failure_count column");
        assert_eq!(
            record.get(pfc_idx),
            Some("1"),
            "Should have 1 partial failure"
        );
    }
}
