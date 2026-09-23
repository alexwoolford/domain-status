//! Export `url_status` rows (plus satellites) to CSV, JSONL, or Parquet.
//!
//! Optional filters: `run_id`, `domain` (exact `initial_domain` or `final_domain`),
//! `status`, `since`. Implied fingerprint technologies are omitted unless
//! [`ExportOptions::include_implied_tech`] is set.

mod bootstrap;
mod csv;
mod field_inventory;
mod fields;
mod jsonl;
mod parquet;
mod queries;
mod row;
mod types;

#[cfg(test)]
mod column_sentinel;
#[cfg(test)]
mod technology_roundtrip;

pub use csv::export_csv;
pub use jsonl::export_jsonl;
pub use parquet::export_parquet;
pub use types::{ExportFormat, ExportOptions};
