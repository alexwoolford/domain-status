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
        include_implied_tech: false,
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
        include_implied_tech: false,
    })
    .await
    .expect("export_jsonl");

    assert_eq!(count, 1);
    let contents = std::fs::read_to_string(&out_path).unwrap();
    let normalized = normalize_for_snapshot(&contents);
    insta::assert_snapshot!(normalized);
}

fn domain_status_bin() -> assert_cmd::Command {
    #[allow(deprecated)] // cargo_bin_cmd! requires cargo dev-dependency
    assert_cmd::Command::cargo_bin("domain-status").expect("cargo_bin domain-status")
}

fn assert_contains(haystack: &str, needle: &str, context: &str) {
    assert!(
        haystack.contains(needle),
        "expected `{needle}` in {context}, got:\n{haystack}"
    );
}

fn assert_not_contains(haystack: &str, needle: &str, context: &str) {
    assert!(
        !haystack.contains(needle),
        "did not expect `{needle}` in {context}, got:\n{haystack}"
    );
}

#[test]
fn cli_top_level_help_includes_must_have_flags() {
    let mut cmd = domain_status_bin();
    cmd.arg("--help");
    let output = cmd.output().expect("run domain-status --help");
    assert!(output.status.success(), "help should succeed");
    let help =
        String::from_utf8_lossy(&output.stdout).replace("domain-status.exe", "domain-status");
    for needle in [
        "Usage:",
        "domain-status",
        "Commands:",
        "scan",
        "export",
        "summary",
        "Options:",
        "--help",
        "--version",
        "Scan only hosts you are authorized to scan.",
        "Concurrent URL scanner",
    ] {
        assert_contains(&help, needle, "`--help` output");
    }
}

#[test]
fn cli_scan_long_help_includes_flags_and_authorized_use() {
    let mut scan_cmd = domain_status_bin();
    scan_cmd.arg("scan").arg("--help");
    let scan_output = scan_cmd.output().expect("run domain-status scan --help");
    assert!(scan_output.status.success(), "scan --help should succeed");
    let scan_help = String::from_utf8_lossy(&scan_output.stdout);
    for needle in [
        "--config",
        "--db-path",
        "--max-concurrency",
        "--rate-limit-rps",
        "Everyday flags: -h. All flags: --help. Docs: docs/CLI.md",
        "Scan only hosts you are authorized to scan.",
        "Scan:",
        "Enrichments:",
        "CI / logging:",
        "Advanced:",
    ] {
        assert_contains(&scan_help, needle, "`scan --help` output");
    }
    assert_not_contains(&scan_help, "--enable-whois", "`scan --help` output");
}

#[test]
fn cli_scan_short_help_hides_advanced_flags() {
    let mut short_cmd = domain_status_bin();
    short_cmd.arg("scan").arg("-h");
    let short_output = short_cmd.output().expect("run domain-status scan -h");
    assert!(short_output.status.success(), "scan -h should succeed");
    let short_help = String::from_utf8_lossy(&short_output.stdout);
    for needle in [
        "--db-path",
        "--timeout-seconds",
        "--max-concurrency",
        "--rate-limit-rps",
        "--no-whois",
        "--geoip",
        "--scan-external-scripts",
        "--fail-on",
        "-v",
        "-q",
        "Everyday flags: -h. All flags: --help. Docs: docs/CLI.md",
    ] {
        assert_contains(&short_help, needle, "`scan -h` output");
    }
    for needle in [
        "--config",
        "--user-agent",
        "--fingerprints",
        "--status-port",
        "--cache-dir",
        "--drain-timeout-secs",
        "--log-level",
        "--log-format",
        "--log-file",
        "--no-progress",
        "--fail-on-pct-threshold",
        "--enable-whois",
    ] {
        assert_not_contains(&short_help, needle, "`scan -h` output");
    }
}
