//! Database insert operations.
//!
//! This module provides functions to insert various types of records into the database:
//! - URL status records and related satellite tables
//! - Run metadata and statistics
//! - `GeoIP` data
//! - Enrichment data (structured data, social media, WHOIS, analytics)
//! - Failure records
//!
//! All inserts use parameterized queries to prevent SQL injection.

pub mod enrichment;
pub mod failure;
mod record;
pub mod retry;
mod run;
pub mod url;
pub(crate) mod utils;

pub use failure::insert_url_failure;
pub(crate) use failure::insert_url_partial_failure_in_tx;
pub use record::insert_persisted_url_record;
pub(crate) use run::query_run_by_id;
pub(crate) use run::{count_run_fact_rows, count_run_partial_failures, saturating_i32_count};
pub use run::{
    insert_run_metadata, query_run_history, update_run_stats, RunMetadata, RunStats, RunSummary,
};
// Crate-internal re-export: `insert_url_record_with_outcome` is called from
// `record.rs::insert_persisted_url_record` via `insert::insert_url_record_with_outcome`.
pub(crate) use url::{insert_url_record_with_outcome, SatelliteWriteFailure, UrlUpsertOutcome};
