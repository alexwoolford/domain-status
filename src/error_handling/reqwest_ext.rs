//! Extension trait for `reqwest::Error` (predicate-style API).
//!
//! Provides `categorize()` and `is_retriable()` so call sites that have a
//! `reqwest::Error` can inspect it without going through `anyhow::Error` or
//! calling free functions. Aligns with the pattern used by libraries like
//! hyper (`Error::is_timeout()`, etc.).

use super::categorization::categorize_reqwest_error;
use super::types::ErrorType;
use crate::config::HTTP_STATUS_TOO_MANY_REQUESTS;

#[allow(rustdoc::private_intra_doc_links)]
/// Extension trait for [`reqwest::Error`] providing categorization and retriability.
///
/// Use this when you already have a `reqwest::Error` and want to:
/// - Get a stable [`ErrorType`] for stats or logging: `error.categorize()`
/// - Decide if the request should be retried: `error.is_retriable()`
///
/// # Example
///
/// ```ignore
/// use domain_status::error_handling::ReqwestErrorExt;
///
/// if let Err(e) = client.get(url).send().await {
///     stats.increment_error(e.categorize());
///     if e.is_retriable() {
///         // retry with backoff
///     }
/// }
/// ```
pub trait ReqwestErrorExt {
    /// Returns the [`ErrorType`] for this error (for stats and logging).
    fn categorize(&self) -> ErrorType;

    /// Returns whether this error is retriable (transient; retry with backoff).
    ///
    /// Retriable: 429, 5xx, timeout, connect, request errors.
    /// Not retriable: 4xx (except 429), redirect, decode, builder, etc.
    fn is_retriable(&self) -> bool;
}

impl ReqwestErrorExt for reqwest::Error {
    fn categorize(&self) -> ErrorType {
        categorize_reqwest_error(self)
    }

    fn is_retriable(&self) -> bool {
        if let Some(status) = self.status() {
            let code = status.as_u16();
            if code == HTTP_STATUS_TOO_MANY_REQUESTS {
                return true;
            }
            if (400..500).contains(&code) {
                return false;
            }
            if (500..600).contains(&code) {
                return true;
            }
        }
        if self.is_timeout() || self.is_connect() || self.is_request() {
            return true;
        }
        if self.is_redirect() || self.is_decode() {
            return false;
        }
        false
    }
}
