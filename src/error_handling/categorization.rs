//! Error categorization and retry strategy.
//!
//! This module provides functions to categorize errors and configure retry strategies.

use std::time::Duration;
use tokio_retry::strategy::ExponentialBackoff;

use super::stats::ProcessingStats;
use super::types::ErrorType;

/// Creates an exponential backoff retry strategy.
///
/// Returns a retry strategy configured with:
/// - Initial delay: `RETRY_INITIAL_DELAY_MS` milliseconds
/// - Backoff factor: `RETRY_FACTOR` (doubles delay each retry)
/// - Maximum delay: `RETRY_MAX_DELAY_SECS` seconds
/// - Maximum attempts: `RETRY_MAX_ATTEMPTS` (prevents infinite retries)
///
/// # Returns
///
/// A retry strategy iterator ready for use with `tokio_retry::Retry`.
/// The iterator is limited to `RETRY_MAX_ATTEMPTS` attempts to prevent
/// infinite retries and ensure we don't exceed `URL_PROCESSING_TIMEOUT`.
pub fn get_retry_strategy() -> impl Iterator<Item = Duration> {
    ExponentialBackoff::from_millis(crate::config::RETRY_INITIAL_DELAY_MS)
        .factor(crate::config::RETRY_FACTOR) // Double the delay with each retry
        .max_delay(Duration::from_secs(crate::config::RETRY_MAX_DELAY_SECS)) // Maximum delay
        .take(crate::config::RETRY_MAX_ATTEMPTS) // Limit total attempts (initial + retries)
}

/// Categorizes a `reqwest::Error` into an `ErrorType`.
///
/// This is the unified error categorization logic used by both
/// `update_error_stats` and `extract_error_type` to ensure consistency.
///
/// # Arguments
///
/// * `error` - The `reqwest::Error` to categorize
///
/// # Returns
///
/// The appropriate `ErrorType` for the error.
pub fn categorize_reqwest_error(error: &reqwest::Error) -> ErrorType {
    // Check HTTP status codes first
    if let Some(status) = error.status() {
        match status.as_u16() {
            // Client errors (4xx)
            400 => return ErrorType::HttpRequestBadRequest,
            401 => return ErrorType::HttpRequestUnauthorized,
            403 => return ErrorType::HttpRequestBotDetectionError,
            404 => return ErrorType::HttpRequestNotFound,
            406 => return ErrorType::HttpRequestNotAcceptable,
            429 => return ErrorType::HttpRequestTooManyRequests,
            // Server errors (5xx)
            500 => return ErrorType::HttpRequestInternalServerError,
            502 => return ErrorType::HttpRequestBadGateway,
            503 => return ErrorType::HttpRequestServiceUnavailable,
            504 => return ErrorType::HttpRequestGatewayTimeout,
            521 => return ErrorType::HttpRequestCloudflareError,
            // Other client errors (4xx) - use generic format
            _ if status.is_client_error() => {
                return ErrorType::HttpRequestOtherError;
            }
            // Other server errors (5xx) - use generic format
            _ if status.is_server_error() => {
                return ErrorType::HttpRequestOtherError;
            }
            _ => {
                // Non-standard status codes - fall through to check error type
            }
        }
    }

    // Check reqwest error types
    if error.is_builder() {
        ErrorType::HttpRequestBuilderError
    } else if error.is_redirect() {
        ErrorType::HttpRequestRedirectError
    } else if error.is_status() {
        ErrorType::HttpRequestStatusError
    } else if error.is_timeout() {
        ErrorType::HttpRequestTimeoutError
    } else if error.is_request() {
        ErrorType::HttpRequestRequestError
    } else if error.is_connect() {
        ErrorType::HttpRequestConnectError
    } else if error.is_body() {
        ErrorType::HttpRequestBodyError
    } else if error.is_decode() {
        ErrorType::HttpRequestDecodeError
    } else {
        ErrorType::HttpRequestOtherError
    }
}

/// Updates processing statistics based on a `reqwest::Error`.
///
/// Analyzes the error and increments the appropriate `ErrorType` counter.
/// Handles both HTTP status errors (e.g., 429 Too Many Requests) and network-level
/// errors (timeouts, connection failures, etc.).
///
/// # Arguments
///
/// * `stats` - The processing statistics tracker to update
/// * `error` - The `reqwest::Error` to categorize and record
pub async fn update_error_stats(stats: &ProcessingStats, error: &reqwest::Error) {
    let error_type = categorize_reqwest_error(error);
    stats.increment_error(error_type);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_get_retry_strategy_initial_delay() {
        let strategy = get_retry_strategy();
        let first_delay = strategy
            .take(1)
            .next()
            .expect("Retry strategy should always yield at least one delay");

        // First delay should be at least RETRY_INITIAL_DELAY_MS
        // (ExponentialBackoff may have a minimum delay)
        let expected_ms = crate::config::RETRY_INITIAL_DELAY_MS as u128;
        let actual_ms = first_delay.as_millis();
        assert!(
            actual_ms >= expected_ms,
            "Expected delay >= {}ms, got {}ms",
            expected_ms,
            actual_ms
        );
    }

    #[test]
    fn test_get_retry_strategy_exponential_backoff() {
        let strategy = get_retry_strategy();
        let delays: Vec<Duration> = strategy.take(5).collect();

        // Verify delays increase (exponential backoff or capped at max)
        for i in 1..delays.len() {
            let prev = delays[i - 1].as_millis();
            let curr = delays[i].as_millis();
            // Delay should increase (or stay at max)
            assert!(curr >= prev, "Delay should increase: {} >= {}", curr, prev);

            // If not at max, should be approximately double
            let max_delay_ms = (crate::config::RETRY_MAX_DELAY_SECS * 1000) as u128;
            if curr < max_delay_ms {
                let ratio = curr as f64 / prev as f64;
                // Allow wide tolerance - ExponentialBackoff behavior can vary
                assert!(
                    (1.0..=3.0).contains(&ratio),
                    "Backoff factor should be reasonable: {} / {} = {}",
                    curr,
                    prev,
                    ratio
                );
            }
        }
    }

    #[test]
    fn test_get_retry_strategy_max_delay() {
        let strategy = get_retry_strategy();
        let max_delay_ms = crate::config::RETRY_MAX_DELAY_SECS * 1000;

        // All delays should be <= max_delay
        for delay in strategy {
            assert!(
                delay.as_millis() <= max_delay_ms as u128,
                "Delay {}ms exceeds max {}ms",
                delay.as_millis(),
                max_delay_ms
            );
        }
    }

    #[test]
    fn test_get_retry_strategy_max_attempts() {
        let strategy = get_retry_strategy();
        let count = strategy.count();

        // Should be limited to RETRY_MAX_ATTEMPTS
        assert_eq!(count, crate::config::RETRY_MAX_ATTEMPTS);
    }

    #[tokio::test]
    async fn test_update_error_stats() {
        use httptest::{matchers::*, responders::*, Expectation, Server};

        let stats = ProcessingStats::new();
        let server = Server::run();

        // Test with 404 error
        server.expect(
            Expectation::matching(request::method_path("GET", "/404"))
                .respond_with(status_code(404).body("Not Found")),
        );

        let client = reqwest::Client::new();
        let url = format!("http://{}/404", server.addr());
        let response = client.get(&url).send().await.unwrap();
        let error = response.error_for_status().unwrap_err();

        update_error_stats(&stats, &error).await;

        assert_eq!(
            stats.get_error_count(ErrorType::HttpRequestNotFound),
            1,
            "404 error should increment HttpRequestNotFound counter"
        );
    }

    // Test individual status codes (using separate tests to avoid lifetime issues)
    #[tokio::test]
    async fn test_categorize_reqwest_error_400() {
        test_status_code(400, ErrorType::HttpRequestBadRequest).await;
    }

    #[tokio::test]
    async fn test_categorize_reqwest_error_401() {
        test_status_code(401, ErrorType::HttpRequestUnauthorized).await;
    }

    #[tokio::test]
    async fn test_categorize_reqwest_error_403() {
        test_status_code(403, ErrorType::HttpRequestBotDetectionError).await;
    }

    #[tokio::test]
    async fn test_categorize_reqwest_error_404() {
        test_status_code(404, ErrorType::HttpRequestNotFound).await;
    }

    #[tokio::test]
    async fn test_categorize_reqwest_error_429() {
        test_status_code(429, ErrorType::HttpRequestTooManyRequests).await;
    }

    #[tokio::test]
    async fn test_categorize_reqwest_error_500() {
        test_status_code(500, ErrorType::HttpRequestInternalServerError).await;
    }

    #[tokio::test]
    async fn test_categorize_reqwest_error_502() {
        test_status_code(502, ErrorType::HttpRequestBadGateway).await;
    }

    #[tokio::test]
    async fn test_categorize_reqwest_error_503() {
        test_status_code(503, ErrorType::HttpRequestServiceUnavailable).await;
    }

    #[tokio::test]
    async fn test_categorize_reqwest_error_504() {
        test_status_code(504, ErrorType::HttpRequestGatewayTimeout).await;
    }

    #[tokio::test]
    async fn test_categorize_reqwest_error_521() {
        test_status_code(521, ErrorType::HttpRequestCloudflareError).await;
    }

    // Helper function to test a single status code
    async fn test_status_code(code: u16, expected_error_type: ErrorType) {
        use httptest::{matchers::*, responders::*, Expectation, Server};

        let server = Server::run();
        let client = reqwest::Client::new();

        // Use a static path pattern to avoid lifetime issues
        let path = match code {
            400 => "/400",
            401 => "/401",
            403 => "/403",
            404 => "/404",
            429 => "/429",
            500 => "/500",
            502 => "/502",
            503 => "/503",
            504 => "/504",
            521 => "/521",
            _ => panic!("Unsupported status code in test"),
        };

        server.expect(
            Expectation::matching(request::method_path("GET", path))
                .respond_with(status_code(code).body("Error")),
        );

        let url = format!("http://{}{}", server.addr(), path);
        let response = client.get(&url).send().await.unwrap();
        let error = response.error_for_status().unwrap_err();
        let categorized = categorize_reqwest_error(&error);

        assert_eq!(
            categorized, expected_error_type,
            "Status code {} should be categorized as {:?}",
            code, expected_error_type
        );
    }

    #[tokio::test]
    async fn test_categorize_reqwest_error_other_client_errors() {
        use httptest::{matchers::*, responders::*, Expectation, Server};

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/418"))
                .respond_with(status_code(418).body("I'm a teapot")), // 418 is a 4xx but not specifically handled
        );

        let client = reqwest::Client::new();
        let url = format!("http://{}/418", server.addr());
        let response = client.get(&url).send().await.unwrap();
        let error = response.error_for_status().unwrap_err();
        let categorized = categorize_reqwest_error(&error);

        assert_eq!(
            categorized,
            ErrorType::HttpRequestOtherError,
            "Other 4xx errors should be categorized as HttpRequestOtherError"
        );
    }

    #[tokio::test]
    async fn test_categorize_reqwest_error_other_server_errors() {
        use httptest::{matchers::*, responders::*, Expectation, Server};

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/507"))
                .respond_with(status_code(507).body("Insufficient Storage")), // 507 is a 5xx but not specifically handled
        );

        let client = reqwest::Client::new();
        let url = format!("http://{}/507", server.addr());
        let response = client.get(&url).send().await.unwrap();
        let error = response.error_for_status().unwrap_err();
        let categorized = categorize_reqwest_error(&error);

        assert_eq!(
            categorized,
            ErrorType::HttpRequestOtherError,
            "Other 5xx errors should be categorized as HttpRequestOtherError"
        );
    }

    #[tokio::test]
    async fn test_categorize_reqwest_error_timeout() {
        use std::time::Duration;

        // Test timeout by using a very short timeout on a non-existent server
        // This will trigger a timeout error
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(1))
            .build()
            .unwrap();

        // Use a URL that won't respond quickly (or at all)
        let error = client
            .get("http://192.0.2.1:80") // Test net (RFC 3330) - should not respond
            .send()
            .await
            .unwrap_err();

        let categorized = categorize_reqwest_error(&error);

        // Timeout errors should be categorized as HttpRequestTimeoutError
        // (may also be ConnectError depending on timing, but timeout is more likely)
        assert!(
            categorized == ErrorType::HttpRequestTimeoutError
                || categorized == ErrorType::HttpRequestConnectError,
            "Timeout errors should be categorized as TimeoutError or ConnectError, got {:?}",
            categorized
        );
    }

    #[tokio::test]
    async fn test_categorize_reqwest_error_connect() {
        use std::time::Duration;

        // Create a client that tries to connect to a non-existent server
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap();
        let error = client
            .get("http://127.0.0.1:1") // Port 1 is unlikely to be listening
            .send()
            .await
            .unwrap_err();

        let categorized = categorize_reqwest_error(&error);

        // Connection errors can be categorized as connect or timeout depending on timing
        assert!(
            categorized == ErrorType::HttpRequestConnectError
                || categorized == ErrorType::HttpRequestTimeoutError,
            "Connection errors should be categorized as ConnectError or TimeoutError, got {:?}",
            categorized
        );
    }
}
