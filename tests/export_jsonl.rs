//! Tests for JSONL export functionality.

use domain_status::export::{export_jsonl, ExportFormat, ExportOptions};

// helpers.rs is a shared fixture module; this binary only needs a subset of its
// functions, so unused ones (e.g. create_test_run) must not fail the crate's build.
#[path = "helpers.rs"]
#[allow(dead_code)]
mod helpers;

use helpers::{create_test_pool_with_path, create_test_url_status};

/// Contract: `body_truncated` is on `url_status` (see migration
/// `0009_secrets_scan_completeness.sql`) and must be surfaced as a top-level boolean
/// field in every exported JSONL object, not silently dropped.
#[tokio::test]
async fn test_export_jsonl_body_truncated_field_present() {
    let temp_dir = tempfile::TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_export.db");
    let output_path = temp_dir.path().join("output.jsonl");

    let pool = create_test_pool_with_path(&db_path).await;
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

    let count = export_jsonl(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path.clone()),
        format: ExportFormat::Jsonl,
        run_id: None,
        domain: None,
        status: None,
        since: None,
    })
    .await
    .expect("Export should succeed");
    assert_eq!(count, 1);

    let jsonl_content = std::fs::read_to_string(&output_path).expect("Should read JSONL file");
    let line = jsonl_content
        .lines()
        .next()
        .expect("Should have one JSONL line");
    let value: serde_json::Value = serde_json::from_str(line).expect("Should parse JSON line");
    assert_eq!(
        value.get("body_truncated"),
        Some(&serde_json::Value::Bool(true)),
        "body_truncated must round-trip as a JSON boolean, got: {value}"
    );
}

/// Contract: `body_truncated` defaults to `false` (not omitted) when the response body
/// was never truncated, mirroring the CSV export's `body_truncated` behavior.
#[tokio::test]
async fn test_export_jsonl_body_truncated_false_by_default() {
    let temp_dir = tempfile::TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_export.db");
    let output_path = temp_dir.path().join("output.jsonl");

    let pool = create_test_pool_with_path(&db_path).await;
    create_test_url_status(
        &pool,
        "nottruncated.com",
        "nottruncated.com",
        200,
        None,
        1704067200000,
    )
    .await;
    drop(pool);

    let count = export_jsonl(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(output_path.clone()),
        format: ExportFormat::Jsonl,
        run_id: None,
        domain: None,
        status: None,
        since: None,
    })
    .await
    .expect("Export should succeed");
    assert_eq!(count, 1);

    let jsonl_content = std::fs::read_to_string(&output_path).expect("Should read JSONL file");
    let line = jsonl_content
        .lines()
        .next()
        .expect("Should have one JSONL line");
    let value: serde_json::Value = serde_json::from_str(line).expect("Should parse JSON line");
    assert_eq!(
        value.get("body_truncated"),
        Some(&serde_json::Value::Bool(false))
    );
}
