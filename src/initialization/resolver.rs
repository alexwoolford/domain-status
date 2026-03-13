//! DNS resolver initialization.
//!
//! This module provides functions to initialize the DNS resolver with proper
//! timeout configuration.

use std::sync::Arc;
use std::time::Duration;

use crate::error_handling::InitializationError;
use hickory_resolver::TokioResolver;

/// Initializes the DNS resolver for hostname lookups.
///
/// Creates a DNS resolver using the local system resolver configuration with
/// domain-status-specific timeout settings layered on top.
///
/// The resolver supports both forward lookups (hostname → IP) and reverse lookups
/// (IP → hostname) using PTR records.
///
/// Timeouts are configured to prevent hanging on slow or unresponsive DNS servers,
/// and `ndots = 0` avoids search-domain expansion for scanned hostnames.
///
/// # Returns
///
/// A configured `TokioResolver` wrapped in `Arc` for sharing across tasks,
/// or an error if initialization fails.
///
/// # Errors
///
/// Returns `InitializationError::DnsResolverError` if both system and fallback
/// configurations fail (though fallback should rarely fail).
///
/// # Examples
///
/// ```
/// use domain_status::initialization::init_resolver;
///
/// let resolver = init_resolver().expect("resolver should initialize");
/// let _shared = resolver.clone();
/// ```
pub fn init_resolver() -> Result<Arc<TokioResolver>, InitializationError> {
    use hickory_resolver::config::ResolverOpts;

    // ResolverOpts: timeout, attempts, ndots. Cache and try_tcp_on_error left at resolver default;
    // they can be tuned later via ResolverOpts if needed.
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(crate::config::DNS_TIMEOUT_SECS);
    opts.attempts = 1; // Fail-fast for scans; avoid retries so slow DNS doesn't block the run.
    opts.ndots = 0; // No search-domain expansion for scanned hostnames.

    // Use builder API for hickory-resolver 0.25+
    // The builder uses system config by default (reads resolv.conf), we just need to set options
    // This provides better security, DNSSEC validation, and correctness improvements
    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| {
            InitializationError::DnsResolverError(format!("Failed to create resolver builder: {e}"))
        })?
        .with_options(opts)
        .build();

    Ok(Arc::new(resolver))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_resolver_success() {
        let result = init_resolver();
        assert!(result.is_ok());
        let resolver = result.unwrap();
        assert_eq!(Arc::strong_count(&resolver), 1);
    }

    #[test]
    fn test_init_resolver_returns_arc() {
        let resolver1 = init_resolver().unwrap();
        let resolver2 = Arc::clone(&resolver1);
        assert_eq!(Arc::strong_count(&resolver1), 2);
        assert!(Arc::ptr_eq(&resolver1, &resolver2));
    }

    #[test]
    fn test_init_resolver_multiple_calls() {
        let resolver1 = init_resolver().unwrap();
        let resolver2 = init_resolver().unwrap();
        // Different instances should be created
        assert!(!Arc::ptr_eq(&resolver1, &resolver2));
    }
}
