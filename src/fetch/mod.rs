//! HTTP request handling and response processing.
//!
//! This module handles:
//! - HTTP request construction with realistic browser headers
//! - Redirect chain resolution
//! - Response data extraction and validation
//! - Error handling with structured failure context
//!
//! The main entry points are:
//! - `handle_http_request()` - Orchestrates the full HTTP request flow
//! - `handle_response()` - Processes successful HTTP responses

mod context;
mod dns;
mod handler;
mod record;
mod redirects;
mod request;
mod response;
mod utils;

pub use context::ProcessingContext;
#[allow(unused_imports)] // Public API re-export, even if not used in tests
pub use handler::{handle_http_request, handle_response};
pub use redirects::resolve_redirect_chain;

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
