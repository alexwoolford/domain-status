//! One inserted technology row, read back from CSV, JSONL, and Parquet.

use std::path::Path;

use arrow::array::{Array, BooleanArray, ListArray, StringArray, StructArray};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use sqlx::Row;
use tempfile::NamedTempFile;

use super::csv::export_csv;
use super::jsonl::export_jsonl;
use super::parquet::export_parquet;
use super::types::{ExportFormat, ExportOptions};
use crate::storage::run_migrations;

async fn insert_page(pool: &sqlx::SqlitePool) -> i64 {
    sqlx::query(
        "INSERT INTO runs (run_id, start_time_ms) VALUES (?, ?)
         ON CONFLICT(run_id) DO NOTHING",
    )
    .bind("test-run-1")
    .bind(1_704_067_200_000_i64)
    .execute(pool)
    .await
    .expect("insert run");

    let url_id = sqlx::query(
        "INSERT INTO url_status (
            initial_domain, final_domain, ip_address, http_status, http_status_text,
            response_time_seconds, title, observed_at_ms, run_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING id",
    )
    .bind("example.com")
    .bind("example.com")
    .bind("192.0.2.1")
    .bind(200_i64)
    .bind("OK")
    .bind(1.5_f64)
    .bind("Test Page")
    .bind(1_704_067_200_000_i64)
    .bind("test-run-1")
    .fetch_one(pool)
    .await
    .expect("insert url")
    .get::<i64, _>(0);

    for (name, version, category, source) in [
        ("AlphaMarker", Some("1.2"), Some("CMS"), "html"),
        ("BetaMarker", None, None, "scriptSrc"),
    ] {
        sqlx::query(
            "INSERT INTO url_technologies (
                url_status_id, technology_name, technology_version, technology_category,
                is_implied, detection_source
            ) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(url_id)
        .bind(name)
        .bind(version)
        .bind(category)
        .bind(0_i64)
        .bind(source)
        .execute(pool)
        .await
        .expect("insert technology");
    }
    url_id
}

fn options(db_path: &Path, output: &Path, format: ExportFormat) -> ExportOptions {
    ExportOptions {
        db_path: db_path.to_path_buf(),
        output: Some(output.to_path_buf()),
        format,
        run_id: None,
        domain: None,
        status: None,
        since: None,
        include_implied_tech: false,
    }
}

#[tokio::test]
async fn technology_columns_round_trip_every_export() {
    let db = NamedTempFile::new().expect("temp db");
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", db.path().display()))
        .await
        .expect("pool");
    run_migrations(&pool).await.expect("migrations");
    insert_page(&pool).await;
    drop(pool);

    let csv_out = NamedTempFile::new().expect("csv");
    let jsonl_out = NamedTempFile::new().expect("jsonl");
    let parquet_out = NamedTempFile::new().expect("parquet");

    let csv_count = export_csv(&options(db.path(), csv_out.path(), ExportFormat::Csv))
        .await
        .expect("csv");
    let jsonl_count = export_jsonl(&options(db.path(), jsonl_out.path(), ExportFormat::Jsonl))
        .await
        .expect("jsonl");
    let parquet_count = export_parquet(&options(
        db.path(),
        parquet_out.path(),
        ExportFormat::Parquet,
    ))
    .await
    .expect("parquet");
    assert_eq!((csv_count, jsonl_count, parquet_count), (1, 1, 1));

    assert_csv(csv_out.path());
    assert_jsonl(jsonl_out.path());
    assert_parquet(parquet_out.path());
}

fn assert_csv(path: &Path) {
    let mut reader = csv::Reader::from_path(path).expect("csv");
    let headers = reader.headers().expect("headers").clone();
    let row = reader.records().next().expect("row").expect("record");
    let cell = |name: &str| {
        let idx = headers.iter().position(|header| header == name).unwrap();
        row.get(idx).unwrap().to_string()
    };
    assert_eq!(cell("technologies"), "AlphaMarker:1.2,BetaMarker:");
    assert_eq!(cell("technology_count"), "2");
    assert_eq!(cell("technology_categories"), "CMS");
}

fn assert_jsonl(path: &Path) {
    let contents = std::fs::read_to_string(path).expect("jsonl");
    let row: serde_json::Value = serde_json::from_str(contents.trim()).expect("json");
    assert_eq!(row["technology_count"], 2);
    let techs = row["technologies"].as_array().expect("technologies");
    assert_eq!(techs.len(), 2);
    assert_eq!(techs[0]["name"], "AlphaMarker");
    assert_eq!(techs[0]["version"], "1.2");
    assert_eq!(techs[0]["category"], "CMS");
    assert_eq!(techs[0]["is_implied"], false);
    assert_eq!(techs[0]["detection_source"], "html");
    assert_eq!(techs[1]["name"], "BetaMarker");
    assert_eq!(techs[1]["version"], serde_json::Value::Null);
    assert_eq!(techs[1]["category"], serde_json::Value::Null);
    assert_eq!(techs[1]["is_implied"], false);
    assert_eq!(techs[1]["detection_source"], "scriptSrc");
}

fn assert_parquet(path: &Path) {
    let file = std::fs::File::open(path).expect("open");
    let builder = ParquetRecordBatchReaderBuilder::try_new(file).expect("parse");
    let mut reader = builder.build().expect("reader");
    let batch = reader.next().expect("batch").expect("batch ok");
    let list = batch
        .column_by_name("technologies")
        .expect("technologies")
        .as_any()
        .downcast_ref::<ListArray>()
        .expect("list");
    let values = list.value(0);
    let row = values
        .as_any()
        .downcast_ref::<StructArray>()
        .expect("struct");
    let names = row
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    let versions = row
        .column(1)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    let categories = row
        .column(2)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    let implied = row
        .column(3)
        .as_any()
        .downcast_ref::<BooleanArray>()
        .unwrap();
    let sources = row
        .column(4)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(names.value(0), "AlphaMarker");
    assert_eq!(versions.value(0), "1.2");
    assert_eq!(categories.value(0), "CMS");
    assert!(!implied.value(0));
    assert_eq!(sources.value(0), "html");
    assert_eq!(names.value(1), "BetaMarker");
    assert!(versions.is_null(1));
    assert!(categories.is_null(1));
    assert!(!implied.value(1));
    assert_eq!(sources.value(1), "scriptSrc");
}
