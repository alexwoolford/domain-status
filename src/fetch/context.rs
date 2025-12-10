//! Processing context for URL processing operations.
//!
//! This module defines context structs that group related resources together,
//! reducing function argument counts and improving maintainability.

use hickory_resolver::TokioResolver;
use std::sync::Arc;

use crate::error_handling::ProcessingStats;
use crate::storage::circuit_breaker::DbWriteCircuitBreaker;
use crate::storage::DbPool;
use crate::utils::TimingStats;

/// Network-related resources (HTTP clients, DNS resolver, domain extractor).
#[derive(Clone)]
pub struct NetworkContext {
    /// HTTP client for making requests (with redirects enabled)
    pub client: Arc<reqwest::Client>,
    /// HTTP client for redirect resolution (with redirects disabled)
    pub redirect_client: Arc<reqwest::Client>,
    /// Domain extractor for extracting registrable domains from URLs
    pub extractor: Arc<psl::List>,
    /// DNS resolver for hostname lookups
    pub resolver: Arc<TokioResolver>,
}

/// Database-related resources (connection pool, circuit breaker).
#[derive(Clone)]
pub struct DatabaseContext {
    /// Database connection pool (for failure recording)
    pub pool: DbPool,
    /// Circuit breaker for database write operations
    pub circuit_breaker: Arc<DbWriteCircuitBreaker>,
}

/// Configuration and statistics tracking.
#[derive(Clone)]
pub struct ConfigContext {
    /// Error statistics tracker
    pub error_stats: Arc<ProcessingStats>,
    /// Timing statistics tracker (for performance analysis)
    pub timing_stats: Arc<TimingStats>,
    /// Unique identifier for this run (for time-series tracking)
    pub run_id: Option<String>,
    /// Whether WHOIS lookup is enabled
    pub enable_whois: bool,
}

/// Main processing context containing all shared resources.
///
/// This struct groups related resources together, reducing the number of
/// function arguments and making the code easier to maintain and test.
#[derive(Clone)]
pub struct ProcessingContext {
    /// Network-related resources
    pub network: NetworkContext,
    /// Database-related resources
    pub db: DatabaseContext,
    /// Configuration and statistics
    pub config: ConfigContext,
}

impl NetworkContext {
    /// Creates a new `NetworkContext` with the given resources.
    pub fn new(
        client: Arc<reqwest::Client>,
        redirect_client: Arc<reqwest::Client>,
        extractor: Arc<psl::List>,
        resolver: Arc<TokioResolver>,
    ) -> Self {
        Self {
            client,
            redirect_client,
            extractor,
            resolver,
        }
    }
}

impl DatabaseContext {
    /// Creates a new `DatabaseContext` with the given resources.
    pub fn new(pool: DbPool, circuit_breaker: Arc<DbWriteCircuitBreaker>) -> Self {
        Self {
            pool,
            circuit_breaker,
        }
    }
}

impl ConfigContext {
    /// Creates a new `ConfigContext` with the given resources.
    pub fn new(
        error_stats: Arc<ProcessingStats>,
        timing_stats: Arc<TimingStats>,
        run_id: Option<String>,
        enable_whois: bool,
    ) -> Self {
        Self {
            error_stats,
            timing_stats,
            run_id,
            enable_whois,
        }
    }
}

impl ProcessingContext {
    /// Creates a new `ProcessingContext` with the given resources.
    #[allow(clippy::too_many_arguments)] // All arguments are necessary for context setup
    pub fn new(
        client: Arc<reqwest::Client>,
        redirect_client: Arc<reqwest::Client>,
        extractor: Arc<psl::List>,
        resolver: Arc<TokioResolver>,
        error_stats: Arc<ProcessingStats>,
        run_id: Option<String>,
        enable_whois: bool,
        db_circuit_breaker: Arc<DbWriteCircuitBreaker>,
        pool: DbPool,
        timing_stats: Arc<TimingStats>,
    ) -> Self {
        Self {
            network: NetworkContext::new(client, redirect_client, extractor, resolver),
            db: DatabaseContext::new(pool, db_circuit_breaker),
            config: ConfigContext::new(error_stats, timing_stats, run_id, enable_whois),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::config::ResolverOpts;

    fn create_test_resolver() -> Arc<TokioResolver> {
        Arc::new(
            TokioResolver::builder_tokio()
                .unwrap()
                .with_options(ResolverOpts::default())
                .build(),
        )
    }

    fn create_test_extractor() -> Arc<psl::List> {
        // Create a domain extractor for testing
        Arc::new(psl::List)
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
        assert_eq!(Arc::as_ptr(&context.network.client), Arc::as_ptr(&client));
        assert_eq!(
            Arc::as_ptr(&context.network.redirect_client),
            Arc::as_ptr(&redirect_client)
        );
        assert_eq!(
            Arc::as_ptr(&context.network.extractor),
            Arc::as_ptr(&extractor)
        );
        assert_eq!(
            Arc::as_ptr(&context.network.resolver),
            Arc::as_ptr(&resolver)
        );
        assert_eq!(
            Arc::as_ptr(&context.config.error_stats),
            Arc::as_ptr(&error_stats)
        );
        assert_eq!(context.config.run_id, run_id);
        assert_eq!(context.config.enable_whois, enable_whois);
        assert_eq!(
            Arc::as_ptr(&context.db.circuit_breaker),
            Arc::as_ptr(&db_circuit_breaker)
        );
        assert_eq!(Arc::as_ptr(&context.db.pool), Arc::as_ptr(&pool));
        assert_eq!(
            Arc::as_ptr(&context.config.timing_stats),
            Arc::as_ptr(&timing_stats)
        );
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

        assert_eq!(context.config.run_id, None);
    }
}
