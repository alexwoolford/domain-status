//! Application initialization and resource setup.
//!
//! This module provides functions to initialize all shared resources:
//! - HTTP clients (with rate limiting and timeouts)
//! - DNS resolver
//! - Database connection pool
//! - Processing context
//!
//! All initialization functions return proper error types for error handling.

mod client;
mod logger;
mod rate_limiter;
mod resolver;

use std::sync::Arc;

use rustls::crypto::{ring::default_provider, CryptoProvider};
use tokio::sync::Semaphore;

// Re-export public API
pub use client::{init_client, init_redirect_client};
pub use logger::{init_logger_to_file, init_logger_with};
pub use rate_limiter::init_rate_limiter;
pub use resolver::init_resolver;

/// Initializes a semaphore for controlling concurrency.
///
/// Creates a new semaphore with the specified permit count. This semaphore is used
/// to limit the number of concurrent URL processing tasks.
///
/// # Arguments
///
/// * `count` - Maximum number of concurrent operations allowed
///
/// # Returns
///
/// An `Arc<Semaphore>` that can be shared across multiple tasks.
pub fn init_semaphore(count: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(count))
}

/// Initializes the Public Suffix List extractor.
///
/// Creates a new `psl::List` instance for extracting registrable domains
/// from URLs using the Public Suffix List.
///
/// # Returns
///
/// An `Arc<psl::List>` that can be shared across multiple tasks for domain extraction.
pub fn init_extractor() -> Arc<psl::List> {
    Arc::new(psl::List)
}

/// Initializes the crypto provider for TLS operations.
///
/// Configures the global crypto provider for `rustls`. This must be called before
/// any TLS connections are established. Uses the default provider which supports
/// all standard TLS features.
pub fn init_crypto_provider() {
    // The return value is ignored because reinstalling the provider is harmless
    let _ = CryptoProvider::install_default(default_provider());
}
