//! HTTP request and response handlers.
//!
//! This module provides the main orchestration functions for handling HTTP requests
//! and processing responses, including error handling and failure context tracking.

mod request;
mod response;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlProcessOutcome {
    /// New `url_status` row for this `(run_id, initial_domain)`.
    Inserted,
    /// Existing row updated (duplicate domain key within the same run).
    Updated,
    /// Fetch/parse path chose not to persist (e.g. non-HTML).
    Skipped,
}

pub use request::handle_http_request;
pub use response::handle_response;
