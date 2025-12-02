//! HTTP request and response handlers.
//!
//! This module provides the main orchestration functions for handling HTTP requests
//! and processing responses, including error handling and failure context tracking.

mod request;
mod response;

pub use request::handle_http_request;
pub use response::handle_response;

