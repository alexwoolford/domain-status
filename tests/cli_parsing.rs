//! Tests for CLI subcommand parsing.

use clap::Parser;
use domain_status::config::{FailOn, LogFormat, LogLevel};
use std::path::PathBuf;

// Import the CLI types from main.rs
// Note: We can't directly import from main.rs, so we'll test the parsing logic
// by creating a minimal test structure that mirrors the CLI

#[derive(Debug, clap::Parser)]
#[command(name = "domain_status")]
enum TestCliCommand {
    #[command(name = "scan")]
    Scan(TestScanCommand),
    #[command(name = "export")]
    Export(TestExportCommand),
}

#[derive(Debug, clap::Parser)]
struct TestScanCommand {
    file: PathBuf,
    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    log_level: LogLevel,
    #[arg(long, value_enum, default_value_t = LogFormat::Plain)]
    log_format: LogFormat,
    #[arg(long, default_value = "./domain_status.db")]
    db_path: PathBuf,
    #[arg(long, default_value_t = 30)]
    max_concurrency: usize,
    #[arg(long, default_value_t = 10)]
    timeout_seconds: u64,
    #[arg(long, default_value_t = 15)]
    rate_limit_rps: u32,
    #[arg(long, value_enum, default_value_t = FailOn::Never)]
    fail_on: FailOn,
    #[arg(long, default_value_t = 10)]
    fail_on_pct_threshold: u8,
}

#[derive(Debug, clap::Parser)]
struct TestExportCommand {
    #[arg(long, default_value = "./domain_status.db")]
    db_path: PathBuf,
    #[arg(long, value_enum, default_value = "csv")]
    format: TestExportFormat,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    run_id: Option<String>,
    #[arg(long)]
    domain: Option<String>,
    #[arg(long)]
    status: Option<u16>,
    #[arg(long)]
    since: Option<i64>,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum TestExportFormat {
    Csv,
    Jsonl,
    Parquet,
}

#[test]
fn test_cli_scan_command_parsing() {
    // Test that scan subcommand parses correctly
    let args = ["domain_status", "scan", "test.txt"];
    let cli = TestCliCommand::try_parse_from(args.iter()).expect("Should parse scan command");

    match cli {
        TestCliCommand::Scan(cmd) => {
            assert_eq!(cmd.file, PathBuf::from("test.txt"));
            // LogLevel and LogFormat don't implement PartialEq, so we compare via conversion
            assert_eq!(
                log::LevelFilter::from(cmd.log_level.clone()),
                log::LevelFilter::from(LogLevel::Info)
            );
            // For LogFormat, we can match on variants
            match cmd.log_format {
                LogFormat::Plain => {}
                _ => panic!("Should be Plain format"),
            }
            assert_eq!(cmd.max_concurrency, 30);
            assert_eq!(cmd.fail_on, FailOn::Never);
        }
        _ => panic!("Should parse as Scan command"),
    }
}

#[test]
fn test_cli_scan_command_with_options() {
    let args = vec![
        "domain_status",
        "scan",
        "test.txt",
        "--log-level",
        "debug",
        "--max-concurrency",
        "50",
        "--fail-on",
        "any-failure",
    ];
    let cli = TestCliCommand::try_parse_from(args.iter()).expect("Should parse scan command");

    match cli {
        TestCliCommand::Scan(cmd) => {
            assert_eq!(
                log::LevelFilter::from(cmd.log_level.clone()),
                log::LevelFilter::from(LogLevel::Debug)
            );
            assert_eq!(cmd.max_concurrency, 50);
            assert_eq!(cmd.fail_on, FailOn::AnyFailure);
        }
        _ => panic!("Should parse as Scan command"),
    }
}

#[test]
fn test_cli_export_command_parsing() {
    let args = ["domain_status", "export", "--format", "csv"];
    let cli = TestCliCommand::try_parse_from(args.iter()).expect("Should parse export command");

    match cli {
        TestCliCommand::Export(cmd) => {
            assert_eq!(cmd.db_path, PathBuf::from("./domain_status.db"));
            match cmd.format {
                TestExportFormat::Csv => {}
                _ => panic!("Should parse as CSV format"),
            }
        }
        _ => panic!("Should parse as Export command"),
    }
}

#[test]
fn test_cli_export_command_with_filters() {
    let args = vec![
        "domain_status",
        "export",
        "--format",
        "csv",
        "--run-id",
        "test_run",
        "--domain",
        "example.com",
        "--status",
        "200",
        "--output",
        "output.csv",
    ];
    let cli = TestCliCommand::try_parse_from(args.iter()).expect("Should parse export command");

    match cli {
        TestCliCommand::Export(cmd) => {
            assert_eq!(cmd.run_id, Some("test_run".to_string()));
            assert_eq!(cmd.domain, Some("example.com".to_string()));
            assert_eq!(cmd.status, Some(200));
            assert_eq!(cmd.output, Some(PathBuf::from("output.csv")));
        }
        _ => panic!("Should parse as Export command"),
    }
}

#[test]
fn test_cli_missing_subcommand_error() {
    let args = ["domain_status", "test.txt"];
    let result = TestCliCommand::try_parse_from(args.iter());

    assert!(result.is_err(), "Should fail when subcommand is missing");
    let error = result.unwrap_err();
    let error_msg = error.to_string();
    assert!(
        error_msg.contains("subcommand") || error_msg.contains("COMMAND"),
        "Error message should mention subcommand: {}",
        error_msg
    );
}

#[test]
fn test_cli_invalid_subcommand_error() {
    let args = ["domain_status", "invalid", "test.txt"];
    let result = TestCliCommand::try_parse_from(args.iter());

    assert!(result.is_err(), "Should fail when subcommand is invalid");
    let error = result.unwrap_err();
    let error_msg = error.to_string();
    assert!(
        error_msg.contains("invalid") || error_msg.contains("unrecognized"),
        "Error message should mention invalid subcommand: {}",
        error_msg
    );
}

#[test]
fn test_cli_export_format_enum() {
    // Test that export format enum values work
    let args_csv = ["domain_status", "export", "--format", "csv"];
    let cli_csv = TestCliCommand::try_parse_from(args_csv.iter()).expect("Should parse CSV");
    match cli_csv {
        TestCliCommand::Export(cmd) => match cmd.format {
            TestExportFormat::Csv => {}
            _ => panic!("Should be CSV format"),
        },
        _ => panic!("Should be Export command"),
    }

    let args_jsonl = ["domain_status", "export", "--format", "jsonl"];
    let cli_jsonl = TestCliCommand::try_parse_from(args_jsonl.iter()).expect("Should parse JSONL");
    match cli_jsonl {
        TestCliCommand::Export(cmd) => match cmd.format {
            TestExportFormat::Jsonl => {}
            _ => panic!("Should be JSONL format"),
        },
        _ => panic!("Should be Export command"),
    }
}

#[test]
fn test_cli_scan_fail_on_options() {
    // Test all fail-on options
    let test_cases = vec![
        ("never", FailOn::Never),
        ("any-failure", FailOn::AnyFailure),
        ("pct>", FailOn::PctGreaterThan),
        ("errors-only", FailOn::ErrorsOnly),
    ];

    for (arg_value, expected) in test_cases {
        let args = ["domain_status", "scan", "test.txt", "--fail-on", arg_value];
        let cli = TestCliCommand::try_parse_from(args.iter())
            .unwrap_or_else(|_| panic!("Should parse fail-on={}", arg_value));

        match cli {
            TestCliCommand::Scan(cmd) => {
                assert_eq!(
                    cmd.fail_on, expected,
                    "fail-on={} should parse correctly",
                    arg_value
                );
            }
            _ => panic!("Should parse as Scan command"),
        }
    }
}
