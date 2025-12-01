//! Processing context for URL processing operations.
//!
//! This module defines the `ProcessingContext` struct that groups all shared
//! resources needed for processing URLs, reducing function argument counts
//! and improving maintainability.

use hickory_resolver::TokioAsyncResolver;
use publicsuffix::List;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::error_handling::ProcessingStats;
use crate::storage::circuit_breaker::DbWriteCircuitBreaker;
use crate::storage::BatchRecord;

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
    /// Database connection pool
    /// Note: Currently unused due to batch writer, but kept for potential future use
    #[allow(dead_code)]
    pub pool: Arc<SqlitePool>,
    /// Public Suffix List extractor for domain extraction
    pub extractor: Arc<List>,
    /// DNS resolver for hostname lookups
    pub resolver: Arc<TokioAsyncResolver>,
    /// Error statistics tracker
    pub error_stats: Arc<ProcessingStats>,
    /// Unique identifier for this run (for time-series tracking)
    pub run_id: Option<String>,
    /// Batch writer sender for queuing records
    pub batch_sender: Option<mpsc::UnboundedSender<BatchRecord>>,
    /// Whether WHOIS lookup is enabled
    pub enable_whois: bool,
    /// Circuit breaker for database write operations
    pub db_circuit_breaker: Arc<DbWriteCircuitBreaker>,
}

impl ProcessingContext {
    /// Creates a new `ProcessingContext` with the given resources.
    #[allow(clippy::too_many_arguments)] // All arguments are necessary for context setup
    pub fn new(
        client: Arc<reqwest::Client>,
        redirect_client: Arc<reqwest::Client>,
        pool: Arc<SqlitePool>,
        extractor: Arc<List>,
        resolver: Arc<TokioAsyncResolver>,
        error_stats: Arc<ProcessingStats>,
        run_id: Option<String>,
        batch_sender: Option<mpsc::UnboundedSender<BatchRecord>>,
        enable_whois: bool,
        db_circuit_breaker: Arc<DbWriteCircuitBreaker>,
    ) -> Self {
        Self {
            client,
            redirect_client,
            pool,
            extractor,
            resolver,
            error_stats,
            run_id,
            batch_sender,
            enable_whois,
            db_circuit_breaker,
        }
    }
}
