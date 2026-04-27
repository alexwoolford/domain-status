//! Snapshot tests for export output and CLI help.
//!
//! Uses fixed `run_id` and timestamps so export output is deterministic and suitable for insta.

use domain_status::export::{export_csv, export_jsonl, ExportFormat, ExportOptions};
use tempfile::NamedTempFile;

#[path = "helpers.rs"]
mod helpers;

use helpers::{create_test_pool_with_path, create_test_run, create_test_url_status};

/// Fixed `run_id` and timestamp for reproducible export snapshots.
const SNAPSHOT_RUN_ID: &str = "run_snapshot_1704067200000";
const SNAPSHOT_TIMESTAMP_MS: i64 = 1704067200000;

/// Normalizes variable parts of export output for stable snapshots (e.g. absolute paths).
fn normalize_for_snapshot(s: &str) -> String {
    // Replace absolute temp paths with a placeholder so snapshots are portable
    let re = regex::Regex::new(r"/var/folders/[^\s]+|/tmp/[^\s]+|\\\\[?]\\[^\\]+").unwrap();
    re.replace_all(s, "<TEMP_PATH>").to_string()
}

#[tokio::test]
async fn snapshot_csv_export_minimal() {
    let temp_db = NamedTempFile::new().expect("temp DB");
    let db_path = temp_db.path().to_path_buf();
    let pool = create_test_pool_with_path(&db_path).await;
    create_test_run(&pool, SNAPSHOT_RUN_ID, SNAPSHOT_TIMESTAMP_MS).await;
    create_test_url_status(
        &pool,
        "snapshot.example.com",
        "snapshot.example.com",
        200,
        Some(SNAPSHOT_RUN_ID),
        SNAPSHOT_TIMESTAMP_MS,
    )
    .await;
    drop(pool);

    let out_file = NamedTempFile::new().expect("temp out");
    let out_path = out_file.path().to_path_buf();

    let count = export_csv(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(out_path.clone()),
        format: ExportFormat::Csv,
        run_id: Some(SNAPSHOT_RUN_ID.to_string()),
        domain: None,
        status: None,
        since: None,
    })
    .await
    .expect("export_csv");

    assert_eq!(count, 1);
    let contents = std::fs::read_to_string(&out_path).unwrap();
    let normalized = normalize_for_snapshot(&contents);
    insta::assert_snapshot!(normalized);
}

#[tokio::test]
async fn snapshot_jsonl_export_minimal() {
    let temp_db = NamedTempFile::new().expect("temp DB");
    let db_path = temp_db.path().to_path_buf();
    let pool = create_test_pool_with_path(&db_path).await;
    create_test_run(&pool, SNAPSHOT_RUN_ID, SNAPSHOT_TIMESTAMP_MS).await;
    create_test_url_status(
        &pool,
        "snapshot.example.com",
        "snapshot.example.com",
        200,
        Some(SNAPSHOT_RUN_ID),
        SNAPSHOT_TIMESTAMP_MS,
    )
    .await;
    drop(pool);

    let out_file = NamedTempFile::new().expect("temp out");
    let out_path = out_file.path().to_path_buf();

    let count = export_jsonl(&ExportOptions {
        db_path: db_path.clone(),
        output: Some(out_path.clone()),
        format: ExportFormat::Jsonl,
        run_id: Some(SNAPSHOT_RUN_ID.to_string()),
        domain: None,
        status: None,
        since: None,
    })
    .await
    .expect("export_jsonl");

    assert_eq!(count, 1);
    let contents = std::fs::read_to_string(&out_path).unwrap();
    let normalized = normalize_for_snapshot(&contents);
    insta::assert_snapshot!(normalized);
}

#[test]
#[allow(deprecated)] // cargo_bin_cmd! requires cargo dev-dependency; migrate when upgrading
fn cli_help_includes_must_have_flags() {
    // Replaces a previous full-text snapshot of `--help`. That snapshot would
    // churn whenever any clap-generated description, hint, or subcommand line
    // changed, even though every test still passed. What we actually want to
    // guard is "the user-facing flags that downstream tooling relies on are
    // still discoverable", which is far better expressed as a handful of
    // substring asserts than as a frozen 200-line blob.
    let mut cmd = assert_cmd::Command::cargo_bin("domain_status").expect("cargo_bin domain_status");
    cmd.arg("--help");
    let output = cmd.output().expect("run domain_status --help");
    assert!(output.status.success(), "help should succeed");
    let help = String::from_utf8_lossy(&output.stdout);

    // Normalize executable name so the assertions are platform-agnostic
    // (Windows would otherwise add the `.exe` suffix).
    let help = help.replace("domain_status.exe", "domain_status");

    // Must-have entries on the top-level `--help`. If any of these vanish,
    // downstream documentation, scripts, and CI invocations will silently lose
    // their contract — that is what this test exists to catch. Subcommand
    // flags (`--config`, `--db-path`, etc.) are checked under `scan --help`
    // because clap renders them per-subcommand.
    for needle in [
        "Usage:",
        "domain_status",
        "Commands:",
        "scan",
        "export",
        "Options:",
        "--help",
        "--version",
    ] {
        assert!(
            help.contains(needle),
            "expected `{needle}` in `--help` output, got:\n{help}"
        );
    }

    // Sanity-check `scan --help` so the subcommand flags downstream tooling
    // depends on are still surfaced.
    let mut scan_cmd =
        assert_cmd::Command::cargo_bin("domain_status").expect("cargo_bin domain_status");
    scan_cmd.arg("scan").arg("--help");
    let scan_output = scan_cmd.output().expect("run domain_status scan --help");
    assert!(scan_output.status.success(), "scan --help should succeed");
    let scan_help = String::from_utf8_lossy(&scan_output.stdout);
    for needle in [
        "--config",
        "--db-path",
        "--max-concurrency",
        "--rate-limit-rps",
    ] {
        assert!(
            scan_help.contains(needle),
            "expected `{needle}` in `scan --help` output, got:\n{scan_help}"
        );
    }
}
