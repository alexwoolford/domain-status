//! DNS resolver initialization.
//!
//! This module provides functions to initialize the DNS resolver with proper
//! timeout configuration.

use std::sync::Arc;
use std::time::Duration;

use crate::error_handling::InitializationError;
use hickory_resolver::TokioAsyncResolver;

/// Initializes the DNS resolver for hostname lookups.
///
/// Creates a DNS resolver using default configuration (Google DNS: 8.8.8.8, 8.8.4.4)
/// with aggressive timeouts to prevent hanging on slow or unresponsive DNS servers.
///
/// The resolver supports both forward lookups (hostname → IP) and reverse lookups
/// (IP → hostname) using PTR records.
///
/// Timeouts are configured to prevent hanging on slow or unresponsive DNS servers.
///
/// # Returns
///
/// A configured `TokioAsyncResolver` wrapped in `Arc` for sharing across tasks,
/// or an error if initialization fails.
///
/// # Errors
///
/// Returns `InitializationError::DnsResolverError` if both system and fallback
/// configurations fail (though fallback should rarely fail).
pub fn init_resolver() -> Result<Arc<TokioAsyncResolver>, InitializationError> {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};

    // Configure DNS resolver with timeouts
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(crate::config::DNS_TIMEOUT_SECS);
    opts.attempts = 2; // Reduce retry attempts to fail faster
                       // Set ndots to 0 to prevent search domain appending (preserved from 0.25 workaround)
    opts.ndots = 0;

    // Use default resolver configuration with timeouts
    // This ensures consistent timeout behavior across all DNS queries
    // In hickory-resolver 0.24, use TokioAsyncResolver::tokio() with ResolverConfig::default()
    // This worked correctly and didn't have the search domain issues of 0.25
    Ok(Arc::new(TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        opts,
    )))
}

