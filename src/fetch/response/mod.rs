//! HTTP response processing and HTML parsing.
//!
//! This module handles extracting data from HTTP responses and parsing HTML content.

mod extract;
mod html;
mod types;

pub(crate) use extract::extract_response_data;
#[cfg(any(test, feature = "bench-utils"))]
pub(crate) use html::parse_html_content;
pub(crate) use html::parse_html_content_timed;
pub(crate) use types::{HtmlData, ResponseData};
