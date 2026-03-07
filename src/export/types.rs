//! Export types and options.

use std::path::PathBuf;

/// Export format options.
///
/// Choose a format based on the downstream consumer:
///
/// - [`ExportFormat::Csv`] for flattened spreadsheet-friendly output
/// - [`ExportFormat::Jsonl`] for line-delimited scripting pipelines
/// - [`ExportFormat::Parquet`] for typed analytics workloads
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    /// CSV format (simplified, flattened view for Excel/Sheets)
    Csv,
    /// JSONL format (nested, preserves all data for programmatic access)
    Jsonl,
    /// Parquet format (nested, efficient columnar format for analytics)
    Parquet,
}

/// Options for exporting data.
///
/// `output: None` means "write to stdout". CLI callers achieve the same effect by
/// passing `--output -`, which is normalized before reaching this struct.
///
/// # Examples
///
/// Export a single run to JSONL on stdout:
///
/// ```no_run
/// use domain_status::export::{ExportFormat, ExportOptions};
/// use std::path::PathBuf;
///
/// let opts = ExportOptions {
///     db_path: PathBuf::from("./domain_status.db"),
///     output: None,
///     format: ExportFormat::Jsonl,
///     run_id: Some("run_1700000000000".to_string()),
///     domain: None,
///     status: None,
///     since: None,
/// };
/// ```
///
/// Export recent `200` rows for one domain to a file:
///
/// ```no_run
/// use domain_status::export::{ExportFormat, ExportOptions};
/// use std::path::PathBuf;
///
/// let opts = ExportOptions {
///     db_path: PathBuf::from("./domain_status.db"),
///     output: Some(PathBuf::from("report.parquet")),
///     format: ExportFormat::Parquet,
///     run_id: None,
///     domain: Some("example.com".to_string()),
///     status: Some(200),
///     since: Some(1_700_000_000_000),
/// };
/// ```
#[derive(Clone, Debug)]
pub struct ExportOptions {
    /// SQLite database file to read from.
    pub db_path: PathBuf,
    /// Output file path, or `None` to write to stdout.
    pub output: Option<PathBuf>,
    /// Export format to emit.
    pub format: ExportFormat,
    /// Optional exact `run_id` filter.
    pub run_id: Option<String>,
    /// Optional domain filter matching either initial or final domain.
    pub domain: Option<String>,
    /// Optional HTTP status-code filter.
    pub status: Option<u16>,
    /// Optional lower bound on `observed_at_ms`, in milliseconds since Unix epoch.
    pub since: Option<i64>,
}
