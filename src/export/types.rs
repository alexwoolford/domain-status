//! Export types and options.

use std::path::PathBuf;

/// Export format options.
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
#[derive(Clone, Debug)]
pub struct ExportOptions {
    /// Database path
    pub db_path: PathBuf,
    /// Output file path (or stdout if None)
    pub output: Option<PathBuf>,
    /// Export format
    pub format: ExportFormat,
    /// Filter by run ID (optional)
    pub run_id: Option<String>,
    /// Filter by domain (optional)
    pub domain: Option<String>,
    /// Filter by status code (optional)
    pub status: Option<u16>,
    /// Filter by timestamp (export records after this timestamp, in milliseconds)
    pub since: Option<i64>,
}
