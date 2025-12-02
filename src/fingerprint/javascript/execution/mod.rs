//! JavaScript execution operations for property detection.
//!
//! This module handles executing JavaScript code to detect technology properties,
//! matching the behavior of the Golang Wappalyzer tool.

mod core;

use anyhow::Result;

use core::execute_js_property_check;

/// Checks if a JavaScript property exists by executing JavaScript code (async version).
///
/// This function executes JavaScript code and checks if properties exist on the window object,
/// matching the behavior of the Golang Wappalyzer tool.
///
/// **Security:** This function enforces strict limits on script size and execution time
/// to prevent DoS attacks. Scripts are limited to 100KB per script and 500KB total,
/// and execution is limited to 1 second with a 10MB memory limit.
///
/// # Arguments
///
/// * `script_content` - The JavaScript code to execute (inline + external scripts)
/// * `js_property` - The property path to check (e.g., "jQuery" or "window.React")
/// * `pattern` - Optional pattern to match against the property value
///
/// # Returns
///
/// `true` if the property exists (and matches the pattern if provided), `false` otherwise
pub(crate) async fn check_js_property_async(
    script_content: &str,
    js_property: &str,
    pattern: &str,
) -> bool {
    // Skip if script content is empty
    if script_content.trim().is_empty() {
        return false;
    }

    // Security: Enforce size limits to prevent DoS attacks
    if script_content.len() > crate::config::MAX_TOTAL_SCRIPT_CONTENT_SIZE {
        log::debug!(
            "Script content too large ({} bytes), skipping JavaScript execution",
            script_content.len()
        );
        return false;
    }

    // Try to execute JavaScript using QuickJS (via rquickjs) with timeout protection
    match execute_js_property_check_with_timeout(script_content, js_property, pattern).await {
        Ok(result) => {
            if result {
                log::info!("JavaScript execution found property '{}'", js_property);
            }
            result
        }
        Err(e) => {
            log::debug!(
                "JavaScript execution failed or timed out for '{}': {e}",
                js_property
            );
            false
        }
    }
}

/// Executes JavaScript code and checks if a property exists with timeout protection.
///
/// Uses QuickJS to execute the script and check property existence on the window object.
/// Enforces strict security limits: memory limit, execution timeout, and size limits.
///
/// **Security measures:**
/// - Memory limit: 10MB per context
/// - Execution timeout: 1 second (via Tokio timeout)
/// - Size limits enforced by caller
async fn execute_js_property_check_with_timeout(
    script_content: &str,
    js_property: &str,
    pattern: &str,
) -> Result<bool> {
    // Use Tokio timeout to prevent infinite loops and CPU exhaustion
    // Note: QuickJS execution is blocking, so we run it in spawn_blocking
    let timeout_duration =
        std::time::Duration::from_millis(crate::config::MAX_JS_EXECUTION_TIME_MS);

    let script_content = script_content.to_string();
    let js_property = js_property.to_string();
    let pattern = pattern.to_string();

    // Use spawn_blocking to run QuickJS in a blocking thread pool
    // This prevents blocking the async runtime
    let handle = tokio::task::spawn_blocking(move || {
        execute_js_property_check(&script_content, &js_property, &pattern)
    });

    // Apply timeout to the spawned task
    tokio::time::timeout(timeout_duration, handle)
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "JavaScript execution timed out after {}ms",
                crate::config::MAX_JS_EXECUTION_TIME_MS
            )
        })?
        .map_err(|e| anyhow::anyhow!("Task join error: {e}"))?
}

