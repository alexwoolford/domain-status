//! HTTP client initialization.
//!
//! This module provides functions to initialize HTTP clients with proper
//! configuration for requests and redirect handling.

use std::sync::Arc;
use std::time::Duration;

use crate::config::Opt;
use reqwest::ClientBuilder;

/// Initializes the HTTP client with default settings.
///
/// Creates a `reqwest::Client` configured with:
/// - User-Agent header from options
/// - Timeout from options
/// - Redirect following enabled (up to 10 hops)
/// - HTTP/2 support enabled
/// - Rustls TLS backend (no native TLS)
///
/// # Arguments
///
/// * `opt` - Command-line options containing user-agent and timeout settings
///
/// # Returns
///
/// A configured HTTP client ready for making requests.
///
/// # Errors
///
/// Returns a `reqwest::Error` if client creation fails.
pub async fn init_client(opt: &Opt) -> Result<Arc<reqwest::Client>, reqwest::Error> {
    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(opt.timeout_seconds))
        .user_agent(opt.user_agent.clone())
        .build()?;
    Ok(Arc::new(client))
}

/// Initializes a shared HTTP client for redirect resolution.
///
/// Creates a `reqwest::Client` with redirects disabled so we can manually track
/// the redirect chain. This allows us to capture the full redirect path including
/// intermediate URLs.
///
/// # Arguments
///
/// * `opt` - Command-line options containing user-agent and timeout settings
///
/// # Returns
///
/// A configured HTTP client with redirects disabled.
///
/// # Errors
///
/// Returns a `reqwest::Error` if client creation fails.
pub async fn init_redirect_client(opt: &Opt) -> Result<Arc<reqwest::Client>, reqwest::Error> {
    let client = ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(opt.timeout_seconds))
        .user_agent(opt.user_agent.clone())
        .build()?;
    Ok(Arc::new(client))
}

