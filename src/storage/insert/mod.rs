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
mod utils;

// Re-export public API
pub use enrichment::{
    insert_analytics_ids, insert_contact_links, insert_exposed_secrets, insert_favicon_data,
    insert_geoip_data, insert_jwt_claims_batch, insert_security_warnings,
    insert_social_media_links, insert_structured_data, insert_whois_data,
};
pub use failure::{insert_url_failure, insert_url_partial_failure};
pub use record::insert_batch_record;
pub use run::{
    insert_run_metadata, query_run_history, update_run_stats, RunMetadata, RunStats, RunSummary,
};
// Crate-internal re-export: `insert_url_record` is called from
// `record.rs::insert_batch_record` via `insert::insert_url_record`, so it
// must be visible at this module path — but only inside the crate. The
// external (downstream-visible) re-export of both `insert_url_record` and
// `UrlRecordInsertParams` lives in `src/lib.rs` behind the `test-utils`
// feature; that path goes directly to `storage::insert::url::*` so this
// module doesn't need its own gated `pub use`.
pub(crate) use url::insert_url_record;
