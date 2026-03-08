//! `SQLite` retry logic for transient database errors.
//!
//! This module provides a reusable retry wrapper for database operations that may
//! encounter transient `SQLITE_BUSY` or `SQLITE_LOCKED` errors during high concurrency
//! or WAL checkpoints.

use std::future::Future;

use crate::error_handling::DatabaseError;

/// Maximum number of retry attempts for transient database errors.
pub const MAX_RETRIES: usize = 3;

/// Initial delay in milliseconds before first retry.
pub const INITIAL_DELAY_MS: u64 = 50;

/// Checks if a database error is retriable (transient).
///
/// Returns true for `SQLITE_BUSY` and `SQLITE_LOCKED` errors, which are transient
/// and may succeed on retry.
pub fn is_retriable_error(error: &DatabaseError) -> bool {
    matches!(
        error,
        DatabaseError::SqlError(sqlx::Error::Database(db_err))
            if db_err.message().contains("database is locked")
                || db_err.message().contains("database is busy")
    )
}

/// Executes a database operation with retry logic for transient errors.
///
/// Retries `SQLITE_BUSY` and `SQLITE_LOCKED` errors up to `MAX_RETRIES` times
/// with exponential backoff (50ms, 100ms, 200ms).
///
/// # Arguments
///
/// * `operation` - An async closure that performs the database operation
///
/// # Returns
///
/// The result of the operation, or the last error after all retries are exhausted.
///
/// # Example
///
/// ```ignore
/// let result = with_sqlite_retry(|| async {
///     insert_url_record_impl(params).await
/// }).await;
/// ```
pub async fn with_sqlite_retry<F, Fut, T>(mut operation: F) -> Result<T, DatabaseError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, DatabaseError>>,
{
    for attempt in 0..=MAX_RETRIES {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                if !is_retriable_error(&e) || attempt >= MAX_RETRIES {
                    return Err(e);
                }

                // Exponential backoff: 50ms, 100ms, 200ms
                let delay_ms = INITIAL_DELAY_MS * (1 << attempt);
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
        }
    }

    // Should never reach here, but handle it gracefully
    Err(DatabaseError::SqlError(sqlx::Error::PoolClosed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::error::{DatabaseError as SqlxDatabaseError, ErrorKind};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::{error::Error as StdError, fmt};

    #[derive(Debug)]
    struct FakeDatabaseError {
        message: String,
    }

    impl fmt::Display for FakeDatabaseError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.message)
        }
    }

    impl StdError for FakeDatabaseError {}

    impl SqlxDatabaseError for FakeDatabaseError {
        fn message(&self) -> &str {
            &self.message
        }

        fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> ErrorKind {
            ErrorKind::Other
        }
    }

    fn create_non_retriable_error() -> DatabaseError {
        DatabaseError::SqlError(sqlx::Error::Protocol("some other error".into()))
    }

    fn create_retriable_error(message: &str) -> DatabaseError {
        DatabaseError::SqlError(sqlx::Error::Database(Box::new(FakeDatabaseError {
            message: message.to_string(),
        })))
    }

    #[test]
    fn test_is_retriable_error_busy() {
        assert!(is_retriable_error(&create_retriable_error(
            "database is busy"
        )));
    }

    #[test]
    fn test_is_retriable_error_locked() {
        assert!(is_retriable_error(&create_retriable_error(
            "database is locked"
        )));
    }

    #[test]
    fn test_is_retriable_error_other() {
        assert!(!is_retriable_error(&create_non_retriable_error()));
    }

    #[tokio::test]
    async fn test_with_sqlite_retry_succeeds_immediately() {
        // Test that successful operations return immediately without retries
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let result = with_sqlite_retry(|| {
            let count = Arc::clone(&call_count_clone);
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                Ok::<_, DatabaseError>(42)
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "Should only call operation once on success"
        );
    }

    #[tokio::test]
    async fn test_with_sqlite_retry_non_retriable_error_no_retry() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let result: Result<i32, DatabaseError> = with_sqlite_retry(|| {
            let count = Arc::clone(&call_count_clone);
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                Err(create_non_retriable_error())
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "Should not retry non-retriable errors"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_with_sqlite_retry_succeeds_after_retries() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let retry = with_sqlite_retry(|| {
            let count = Arc::clone(&call_count_clone);
            async move {
                let attempt = count.fetch_add(1, Ordering::SeqCst);
                if attempt < 2 {
                    Err(create_retriable_error("database is locked"))
                } else {
                    Ok::<_, DatabaseError>(42)
                }
            }
        });

        tokio::pin!(retry);
        tokio::time::advance(std::time::Duration::from_millis(
            INITIAL_DELAY_MS + INITIAL_DELAY_MS * 2,
        ))
        .await;
        let result = retry.await;

        assert!(result.is_ok());
        assert_eq!(result.expect("successful retry"), 42);
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn test_with_sqlite_retry_returns_last_retriable_error_after_max_retries() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let retry = with_sqlite_retry(|| {
            let count = Arc::clone(&call_count_clone);
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                Err::<i32, DatabaseError>(create_retriable_error("database is busy"))
            }
        });

        tokio::pin!(retry);
        tokio::time::advance(std::time::Duration::from_millis(
            INITIAL_DELAY_MS + INITIAL_DELAY_MS * 2 + INITIAL_DELAY_MS * 4,
        ))
        .await;
        let result = retry.await;

        assert!(result.is_err());
        assert_eq!(call_count.load(Ordering::SeqCst), MAX_RETRIES + 1);
    }

    #[tokio::test]
    async fn test_retry_helper_returns_correct_type() {
        // Test that the retry helper correctly propagates the result type
        let result: Result<String, DatabaseError> =
            with_sqlite_retry(|| async { Ok("test".to_string()) }).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test");
    }

    #[tokio::test]
    async fn test_retry_helper_with_unit_return() {
        // Test that the retry helper works with unit return type
        let result: Result<(), DatabaseError> = with_sqlite_retry(|| async { Ok(()) }).await;

        assert!(result.is_ok());
    }
}
