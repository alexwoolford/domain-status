//! Processing context for URL processing operations.
//!
//! This module defines context structs that group related resources together,
//! reducing function argument counts and improving maintainability.

use hickory_resolver::TokioResolver;
use std::path::PathBuf;
use std::sync::Arc;

use crate::error_handling::ProcessingStats;
use crate::fingerprint::FingerprintRuleset;
use crate::runtime_metrics::RuntimeMetrics;
use crate::storage::DbPool;
use crate::utils::TimingStats;

/// Network-related resources (HTTP clients and DNS resolver).
#[derive(Clone)]
pub struct NetworkContext {
    /// HTTP client for making requests (with redirects enabled)
    pub client: Arc<reqwest::Client>,
    /// HTTP client for redirect resolution (with redirects disabled)
    pub redirect_client: Arc<reqwest::Client>,
    /// DNS resolver for hostname lookups
    pub resolver: Arc<TokioResolver>,
}

/// Runtime flags and statistics tracked during a scan.
///
/// Named `RuntimeContext` (not "config") because it holds live stats and
/// per-run flags rather than static configuration file contents.
#[derive(Clone)]
pub struct RuntimeContext {
    /// Error statistics tracker
    pub error_stats: Arc<ProcessingStats>,
    /// Timing statistics tracker (for performance analysis)
    pub timing_stats: Arc<TimingStats>,
    /// Unique identifier for this run (for time-series tracking)
    pub run_id: Option<String>,
    /// Whether WHOIS lookup is enabled
    pub enable_whois: bool,
    /// Directory for WHOIS/RDAP disk cache (under the shared cache root)
    pub whois_cache_dir: PathBuf,
    /// Whether first-party external `<script src>` URLs should be fetched for
    /// secret detection and static `scripts` technology patterns. Mirrors
    /// `Config::scan_external_scripts`. Off by default.
    pub scan_external_scripts: bool,
    /// Live runtime counters for retries and degradation paths
    pub runtime_metrics: Arc<RuntimeMetrics>,
    /// If true, redirect resolution allows loopback URLs (`127.0.0.1`, `::1`) so
    /// integration tests against `httptest`/`wiremock` mock servers work.
    /// Mirrors `Config::allow_localhost_for_tests`. Must NOT be set in production.
    pub allow_localhost_for_tests: bool,
}

/// Main processing context containing all shared resources.
///
/// This struct groups related resources together, reducing the number of
/// function arguments and making the code easier to maintain and test.
#[derive(Clone)]
pub struct ProcessingContext {
    /// Network-related resources
    pub network: NetworkContext,
    /// Database connection pool (for inserts and failure recording)
    pub pool: DbPool,
    /// Runtime flags and statistics
    pub runtime: RuntimeContext,
    /// Fingerprint ruleset used for technology detection (hot path; no global lookup)
    pub ruleset: Arc<FingerprintRuleset>,
}

impl NetworkContext {
    /// Creates a new `NetworkContext` with the given resources.
    pub fn new(
        client: Arc<reqwest::Client>,
        redirect_client: Arc<reqwest::Client>,
        resolver: Arc<TokioResolver>,
    ) -> Self {
        Self {
            client,
            redirect_client,
            resolver,
        }
    }
}

impl RuntimeContext {
    /// Creates a new `RuntimeContext` with the given resources.
    #[allow(clippy::too_many_arguments)] // small per-feature flags; refactor would
                                         // produce more boilerplate than it saves
    pub fn new(
        error_stats: Arc<ProcessingStats>,
        timing_stats: Arc<TimingStats>,
        run_id: Option<String>,
        enable_whois: bool,
        whois_cache_dir: PathBuf,
        scan_external_scripts: bool,
        runtime_metrics: Arc<RuntimeMetrics>,
        allow_localhost_for_tests: bool,
    ) -> Self {
        Self {
            error_stats,
            timing_stats,
            run_id,
            enable_whois,
            whois_cache_dir,
            scan_external_scripts,
            runtime_metrics,
            allow_localhost_for_tests,
        }
    }
}

impl ProcessingContext {
    /// Creates a new `ProcessingContext` from pre-built sub-contexts and a ruleset.
    pub fn new(
        network: NetworkContext,
        pool: DbPool,
        runtime: RuntimeContext,
        ruleset: Arc<FingerprintRuleset>,
    ) -> Self {
        Self {
            network,
            pool,
            runtime,
            ruleset,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::initialization::test_resolver;

    fn empty_ruleset() -> Arc<FingerprintRuleset> {
        Arc::new(FingerprintRuleset::empty_for_tests())
    }

    #[tokio::test]
    async fn test_processing_context_new() {
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
        let resolver = test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        let run_id = Some("test-run-123".to_string());
        let enable_whois = true;
        let pool = Arc::new(
            sqlx::SqlitePool::connect("sqlite::memory:")
                .await
                .expect("Failed to create test pool"),
        );
        let timing_stats = Arc::new(TimingStats::new());
        let ruleset = empty_ruleset();

        let context = ProcessingContext::new(
            NetworkContext::new(client.clone(), redirect_client.clone(), resolver.clone()),
            pool.clone(),
            RuntimeContext::new(
                error_stats.clone(),
                timing_stats.clone(),
                run_id.clone(),
                enable_whois,
                std::path::PathBuf::from("/tmp/domain_status_whois_test"),
                false,
                Arc::new(RuntimeMetrics::default()),
                true,
            ),
            Arc::clone(&ruleset),
        );

        assert_eq!(Arc::as_ptr(&context.network.client), Arc::as_ptr(&client));
        assert_eq!(
            Arc::as_ptr(&context.network.redirect_client),
            Arc::as_ptr(&redirect_client)
        );
        assert_eq!(
            Arc::as_ptr(&context.network.resolver),
            Arc::as_ptr(&resolver)
        );
        assert_eq!(
            Arc::as_ptr(&context.runtime.error_stats),
            Arc::as_ptr(&error_stats)
        );
        assert_eq!(context.runtime.run_id, run_id);
        assert_eq!(context.runtime.enable_whois, enable_whois);
        assert_eq!(Arc::as_ptr(&context.pool), Arc::as_ptr(&pool));
        assert_eq!(
            Arc::as_ptr(&context.runtime.timing_stats),
            Arc::as_ptr(&timing_stats)
        );
        assert_eq!(Arc::as_ptr(&context.ruleset), Arc::as_ptr(&ruleset));
    }

    #[tokio::test]
    async fn test_processing_context_without_run_id() {
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
        let resolver = test_resolver();
        let error_stats = Arc::new(ProcessingStats::new());
        let run_id = None;
        let enable_whois = false;
        let pool = Arc::new(
            sqlx::SqlitePool::connect("sqlite::memory:")
                .await
                .expect("Failed to create test pool"),
        );
        let timing_stats = Arc::new(TimingStats::new());

        let context = ProcessingContext::new(
            NetworkContext::new(client, redirect_client, resolver),
            pool,
            RuntimeContext::new(
                error_stats,
                timing_stats,
                run_id,
                enable_whois,
                std::path::PathBuf::from("/tmp/domain_status_whois_test"),
                false,
                Arc::new(RuntimeMetrics::default()),
                true,
            ),
            empty_ruleset(),
        );

        assert_eq!(context.runtime.run_id, None);
    }
}
