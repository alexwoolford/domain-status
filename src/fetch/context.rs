//! Processing context for URL processing operations.
//!
//! This module defines the `ProcessingContext` struct that groups all shared
//! resources needed for processing URLs, reducing function argument counts
//! and improving maintainability.

use hickory_resolver::TokioAsyncResolver;
use publicsuffix::List;
use std::sync::Arc;

use crate::error_handling::ProcessingStats;
use crate::storage::circuit_breaker::DbWriteCircuitBreaker;
use crate::utils::TimingStats;
use sqlx::SqlitePool;

/// Context containing all shared resources needed for URL processing.
///
/// This struct groups related resources together, reducing the number of
/// function arguments and making the code easier to maintain and test.
#[derive(Clone)]
pub struct ProcessingContext {
    /// HTTP client for making requests (with redirects enabled)
    pub client: Arc<reqwest::Client>,
    /// HTTP client for redirect resolution (with redirects disabled)
    pub redirect_client: Arc<reqwest::Client>,
    /// Public Suffix List extractor for domain extraction
    pub extractor: Arc<List>,
    /// DNS resolver for hostname lookups
    pub resolver: Arc<TokioAsyncResolver>,
    /// Error statistics tracker
    pub error_stats: Arc<ProcessingStats>,
    /// Unique identifier for this run (for time-series tracking)
    pub run_id: Option<String>,
    /// Whether WHOIS lookup is enabled
    pub enable_whois: bool,
    /// Circuit breaker for database write operations
    pub db_circuit_breaker: Arc<DbWriteCircuitBreaker>,
    /// Database connection pool (for failure recording)
    pub pool: Arc<SqlitePool>,
    /// Timing statistics tracker (for performance analysis)
    pub timing_stats: Arc<TimingStats>,
}

impl ProcessingContext {
    /// Creates a new `ProcessingContext` with the given resources.
    #[allow(clippy::too_many_arguments)] // All arguments are necessary for context setup
    pub fn new(
        client: Arc<reqwest::Client>,
        redirect_client: Arc<reqwest::Client>,
        extractor: Arc<List>,
        resolver: Arc<TokioAsyncResolver>,
        error_stats: Arc<ProcessingStats>,
        run_id: Option<String>,
        enable_whois: bool,
        db_circuit_breaker: Arc<DbWriteCircuitBreaker>,
        pool: Arc<SqlitePool>,
        timing_stats: Arc<TimingStats>,
    ) -> Self {
        Self {
            client,
            redirect_client,
            extractor,
            resolver,
            error_stats,
            run_id,
            enable_whois,
            db_circuit_breaker,
            pool,
            timing_stats,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};

    fn create_test_resolver() -> Arc<TokioAsyncResolver> {
        Arc::new(TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        ))
    }

    fn create_test_extractor() -> Arc<List> {
        // Create a public suffix list for testing
        // List::new() creates a list with built-in data
        Arc::new(List::new())
    }

    #[tokio::test]
    async fn test_processing_context_new() {
        // Create test resources
        let client = Arc::new(
            reqwest::Client::builder()
                .build()
                .expect("Failed to create HTTP client"),
        );
        let redirect_client = Arc::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("Failed to create redirect client"),
        );
        let extractor = create_test_extractor();
        let resolver = create_test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        let run_id = Some("test-run-123".to_string());
        let enable_whois = true;
        let db_circuit_breaker = Arc::new(DbWriteCircuitBreaker::default());
        let pool = Arc::new(
            sqlx::SqlitePool::connect("sqlite::memory:")
                .await
                .expect("Failed to create test pool"),
        );
        let timing_stats = Arc::new(TimingStats::new());

        // Create context
        let context = ProcessingContext::new(
            client.clone(),
            redirect_client.clone(),
            extractor.clone(),
            resolver.clone(),
            error_stats.clone(),
            run_id.clone(),
            enable_whois,
            db_circuit_breaker.clone(),
            pool.clone(),
            timing_stats.clone(),
        );

        // Verify all fields are set correctly
        assert_eq!(Arc::as_ptr(&context.client), Arc::as_ptr(&client));
        assert_eq!(
            Arc::as_ptr(&context.redirect_client),
            Arc::as_ptr(&redirect_client)
        );
        assert_eq!(Arc::as_ptr(&context.extractor), Arc::as_ptr(&extractor));
        assert_eq!(Arc::as_ptr(&context.resolver), Arc::as_ptr(&resolver));
        assert_eq!(Arc::as_ptr(&context.error_stats), Arc::as_ptr(&error_stats));
        assert_eq!(context.run_id, run_id);
        assert_eq!(context.enable_whois, enable_whois);
        assert_eq!(
            Arc::as_ptr(&context.db_circuit_breaker),
            Arc::as_ptr(&db_circuit_breaker)
        );
        assert_eq!(Arc::as_ptr(&context.pool), Arc::as_ptr(&pool));
        assert_eq!(
            Arc::as_ptr(&context.timing_stats),
            Arc::as_ptr(&timing_stats)
        );
    }

    #[tokio::test]
    async fn test_processing_context_clone() {
        // Create test resources
        let client = Arc::new(
            reqwest::Client::builder()
                .build()
                .expect("Failed to create HTTP client"),
        );
        let redirect_client = Arc::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("Failed to create redirect client"),
        );
        let extractor = create_test_extractor();
        let resolver = create_test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        let run_id = Some("test-run-456".to_string());
        let enable_whois = false;
        let db_circuit_breaker = Arc::new(DbWriteCircuitBreaker::default());
        let pool = Arc::new(
            sqlx::SqlitePool::connect("sqlite::memory:")
                .await
                .expect("Failed to create test pool"),
        );
        let timing_stats = Arc::new(TimingStats::new());

        // Create context
        let context = ProcessingContext::new(
            client,
            redirect_client,
            extractor,
            resolver,
            error_stats,
            run_id.clone(),
            enable_whois,
            db_circuit_breaker,
            pool,
            timing_stats,
        );

        // Clone the context
        let cloned = context.clone();

        // Verify cloned context has same values
        assert_eq!(cloned.run_id, run_id);
        assert_eq!(cloned.enable_whois, enable_whois);
        // Arc pointers should be the same (shared ownership)
        assert_eq!(Arc::as_ptr(&context.client), Arc::as_ptr(&cloned.client));
    }

    #[tokio::test]
    async fn test_processing_context_without_run_id() {
        // Test context creation without run_id
        let client = Arc::new(
            reqwest::Client::builder()
                .build()
                .expect("Failed to create HTTP client"),
        );
        let redirect_client = Arc::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("Failed to create redirect client"),
        );
        let extractor = create_test_extractor();
        let resolver = create_test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        let run_id = None;
        let enable_whois = false;
        let db_circuit_breaker = Arc::new(DbWriteCircuitBreaker::default());
        let pool = Arc::new(
            sqlx::SqlitePool::connect("sqlite::memory:")
                .await
                .expect("Failed to create test pool"),
        );
        let timing_stats = Arc::new(TimingStats::new());

        let context = ProcessingContext::new(
            client,
            redirect_client,
            extractor,
            resolver,
            error_stats,
            run_id,
            enable_whois,
            db_circuit_breaker,
            pool,
            timing_stats,
        );

        assert_eq!(context.run_id, None);
    }
}
