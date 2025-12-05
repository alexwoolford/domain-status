//! HTTP request handling.

use anyhow::Error;
use log::debug;

use crate::config::MAX_REDIRECT_HOPS;
use crate::error_handling::update_error_stats;
use crate::fetch::request::RequestHeaders;
use crate::fetch::utils::serialize_json_with_default;
use crate::fetch::{resolve_redirect_chain, ProcessingContext};

/// Handles an HTTP request, resolving redirects and processing the response.
///
/// # Arguments
///
/// * `ctx` - Processing context containing all shared resources
/// * `url` - The URL to process
/// * `start_time` - Request start time for calculating response time
///
/// # Errors
///
/// Returns an error if redirect resolution, HTTP request, or response handling fails.
pub async fn handle_http_request(
    ctx: &ProcessingContext,
    url: &str,
    start_time: std::time::Instant,
) -> Result<(), Error> {
    debug!("Resolving redirects for {url}");

    let (final_url_string, redirect_chain) =
        resolve_redirect_chain(url, MAX_REDIRECT_HOPS, &ctx.redirect_client).await?;

    // Track redirect info metrics
    // redirect_chain includes the original URL, so:
    // - len == 1: No redirects (original URL only)
    // - len == 2: Single redirect (original + final)
    // - len > 2: Multiple redirects (original + intermediate + final)
    if redirect_chain.len() > 1 {
        // Any redirect occurred (single or multiple)
        ctx.error_stats
            .increment_info(crate::error_handling::InfoType::HttpRedirect);

        // Check for HTTP to HTTPS redirect
        // Use proper URL parsing to extract scheme (more reliable than string split)
        let original_scheme = url::Url::parse(url)
            .ok()
            .map(|u| u.scheme().to_string())
            .unwrap_or_default();
        let final_scheme = url::Url::parse(&final_url_string)
            .ok()
            .map(|u| u.scheme().to_string())
            .unwrap_or_default();
        if original_scheme == "http" && final_scheme == "https" {
            ctx.error_stats
                .increment_info(crate::error_handling::InfoType::HttpsRedirect);
        }

        // Multiple redirects (more than one redirect hop)
        if redirect_chain.len() > 2 {
            ctx.error_stats
                .increment_info(crate::error_handling::InfoType::MultipleRedirects);
        }
    }

    debug!("Sending request to final URL {final_url_string}");

    // Add realistic browser headers to reduce bot detection
    // Note: JA3 TLS fingerprinting will still identify rustls, but these headers
    // help with other detection methods (header analysis, behavioral patterns)
    // Capture actual request headers for failure tracking
    let request_headers = RequestHeaders::as_vec();

    // Build request with headers using the consolidated header builder
    let request_builder =
        RequestHeaders::apply_to_request_builder(ctx.client.get(&final_url_string));

    let res = request_builder.send().await;

    match res {
        Ok(response) => {
            // Extract headers BEFORE calling error_for_status() (which consumes response)
            // This allows us to capture headers even for error responses (4xx/5xx)
            let response_headers: Vec<(String, String)> = response
                .headers()
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
                .collect();
            let response_headers_str = serialize_json_with_default(&response_headers, "[]");

            match response.error_for_status() {
                Ok(response) => {
                    let elapsed = start_time.elapsed().as_secs_f64();
                    super::response::handle_response(
                        response,
                        url,
                        &final_url_string,
                        ctx,
                        elapsed,
                        Some(redirect_chain),
                        start_time, // Pass start_time so total_start can use the same baseline
                    )
                    .await
                }
                Err(e) => {
                    update_error_stats(&ctx.error_stats, &e).await;

                    // Track bot detection (403) as info metric
                    if let Some(status) = e.status() {
                        if status.as_u16() == 403 {
                            ctx.error_stats
                                .increment_info(crate::error_handling::InfoType::BotDetection403);
                        }
                    }

                    log::error!("HTTP request error for {}: {} (status: {:?}, is_timeout: {}, is_connect: {}, is_request: {})", 
                        url, e, e.status(), e.is_timeout(), e.is_connect(), e.is_request());

                    // Attach structured failure context to error
                    let failure_context = crate::storage::failure::FailureContext {
                        final_url: Some(final_url_string.clone()),
                        redirect_chain: redirect_chain.clone(),
                        response_headers: response_headers.clone(),
                        request_headers: request_headers.clone(),
                    };
                    // Attach structured failure context using helper function
                    // This provides detailed debugging information (URL, redirect chain, headers)
                    let redirect_chain_str = serialize_json_with_default(&redirect_chain, "[]");
                    let error = Error::from(e);
                    Err(crate::storage::failure::attach_failure_context(
                        error
                            .context(format!("HTTP request failed for {url}"))
                            .context(format!("FINAL_URL:{final_url_string}"))
                            .context(format!("REDIRECT_CHAIN:{redirect_chain_str}"))
                            .context(format!("RESPONSE_HEADERS:{response_headers_str}"))
                            .context(format!(
                                "REQUEST_HEADERS:{}",
                                serialize_json_with_default(&request_headers, "[]")
                            )),
                        failure_context,
                    ))
                }
            }
        }
        Err(e) => {
            update_error_stats(&ctx.error_stats, &e).await;
            log::error!("HTTP request error for {}: {} (status: {:?}, is_timeout: {}, is_connect: {}, is_request: {})", 
                url, e, e.status(), e.is_timeout(), e.is_connect(), e.is_request());

            // Attach structured failure context to error
            // For connection errors, there are no response headers
            let failure_context = crate::storage::failure::FailureContext {
                final_url: Some(final_url_string.clone()),
                redirect_chain: redirect_chain.clone(),
                response_headers: Vec::new(), // No response for connection errors
                request_headers: request_headers.clone(),
            };
            let context_error = crate::storage::failure::FailureContextError {
                context: failure_context,
            };

            // Also attach string context for backward compatibility
            let error = Error::from(e);
            let redirect_chain_str = serialize_json_with_default(&redirect_chain, "[]");
            Err(error
                .context(format!("HTTP request failed for {url}"))
                .context(format!("FINAL_URL:{final_url_string}"))
                .context(format!("REDIRECT_CHAIN:{redirect_chain_str}"))
                .context(format!(
                    "REQUEST_HEADERS:{}",
                    serialize_json_with_default(&request_headers, "[]")
                ))
                .context(Error::from(context_error))) // Attach structured context
        }
    }
}
