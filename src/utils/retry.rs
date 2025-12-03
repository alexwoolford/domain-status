//! Error retriability and retry logic.

use anyhow::Error;

/// Determines if an error is retriable (should be retried).
///
/// This function categorizes errors into retriable (transient) and non-retriable (permanent)
/// categories to guide retry logic. Only transient errors that might succeed on retry
/// should be retried.
///
/// # Retriable Errors
///
/// - Network timeouts (`reqwest::Error::is_timeout()`)
/// - Connection failures (`reqwest::Error::is_connect()`)
/// - Request errors (`reqwest::Error::is_request()`)
/// - Server errors (5xx HTTP status codes)
/// - Rate limiting (429 Too Many Requests)
/// - DNS resolution failures
///
/// # Non-Retriable Errors
///
/// - Client errors (4xx HTTP status codes, except 429)
/// - URL parsing errors
/// - Database errors
/// - Redirect errors
/// - Decode errors
///
/// # Implementation Details
///
/// Uses error chain inspection to properly identify error types without relying on
/// fragile string matching. Checks for specific error types (reqwest::Error, url::ParseError,
/// sqlx::Error) via downcasting, which is more reliable than string matching.
///
/// # Examples
///
/// ```rust,no_run
/// use anyhow::Error;
///
/// // Timeout error - retriable
/// let timeout_err = Error::from(reqwest::Error::from(reqwest::ErrorKind::Request));
/// assert!(is_retriable_error(&timeout_err));
///
/// // URL parse error - not retriable
/// let parse_err = Error::from(url::ParseError::EmptyHost);
/// assert!(!is_retriable_error(&parse_err));
/// ```
pub(crate) fn is_retriable_error(error: &Error) -> bool {
    // Check error chain for specific error types
    for cause in error.chain() {
        // Check for reqwest errors (HTTP client errors)
        if let Some(reqwest_err) = cause.downcast_ref::<reqwest::Error>() {
            // Check HTTP status codes first
            if let Some(status) = reqwest_err.status() {
                let status_code = status.as_u16();

                // 429 (Too Many Requests) is retriable with backoff
                if status_code == crate::config::HTTP_STATUS_TOO_MANY_REQUESTS {
                    return true;
                }

                // Permanent client errors (4xx except 429) - don't retry
                if (400..500).contains(&status_code) {
                    return false;
                }

                // Server errors (5xx) - retry (temporary)
                if (500..600).contains(&status_code) {
                    return true;
                }
            }

            // Check reqwest error types (network-related errors are retriable)
            if reqwest_err.is_timeout() || reqwest_err.is_connect() || reqwest_err.is_request() {
                return true;
            }

            // Redirect errors, decode errors, etc. are not retriable
            if reqwest_err.is_redirect() || reqwest_err.is_decode() {
                return false;
            }
        }

        // Check for URL parsing errors (not retriable)
        if cause.downcast_ref::<url::ParseError>().is_some() {
            return false;
        }

        // Check for database errors (not retriable)
        if cause.downcast_ref::<sqlx::Error>().is_some() {
            return false;
        }

        // Check for DNS errors (retriable - network issue)
        // Note: hickory_resolver errors are wrapped in anyhow, so we check the message
        let msg = cause.to_string().to_lowercase();
        if msg.contains("dns") || msg.contains("resolve") || msg.contains("lookup failed") {
            return true;
        }

        // Check error message for specific patterns (fallback for non-reqwest errors)
        // This handles cases where we have an error but not a reqwest::Error with status code
        // (e.g., errors from other libraries that don't expose HTTP status directly)
        if msg.contains("404") || msg.contains("not found") {
            return false;
        }
        if msg.contains("403") || msg.contains("forbidden") {
            return false;
        }
        if msg.contains("401") || msg.contains("unauthorized") {
            return false;
        }
    }

    // Default: retry unknown errors (might be transient network issue)
    true
}
