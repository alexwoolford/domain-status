//! Batched JavaScript property checking for performance optimization.
//!
//! This module provides a batched approach to JavaScript property checking:
//! - Execute scripts once in a single QuickJS context
//! - Check all properties in the same context
//! - Reuse the context across multiple property checks
//!
//! This is much more efficient than creating a new context for each property check.

use anyhow::Result;
use std::collections::HashMap;

use crate::fingerprint::javascript::execution::core::property::{
    build_pattern_check, build_property_check_code, build_property_expression,
};
use crate::fingerprint::javascript::execution::core::runtime::{create_context, create_runtime};
use crate::fingerprint::javascript::execution::core::stubs::initialize_browser_stubs;

/// Checks multiple JavaScript properties in a single QuickJS context.
///
/// This is much more efficient than checking properties one-by-one because:
/// - Scripts are executed only once
/// - A single QuickJS runtime/context is created and reused
/// - All property checks happen in the same context
///
/// # Arguments
///
/// * `script_content` - The JavaScript code to execute (inline + external scripts)
/// * `properties` - Vector of (property_name, pattern) tuples to check
///
/// # Returns
///
/// A HashMap mapping property names to whether they exist (and match their pattern)
pub(crate) fn check_js_properties_batch(
    script_content: &str,
    properties: &[(String, String)],
) -> Result<HashMap<String, bool>> {
    // Skip if script content is empty or no properties to check
    if script_content.trim().is_empty() || properties.is_empty() {
        return Ok(HashMap::new());
    }

    // Security: Enforce size limits to prevent DoS attacks
    if script_content.len() > crate::config::MAX_TOTAL_SCRIPT_CONTENT_SIZE {
        log::debug!(
            "Script content too large ({} bytes), skipping JavaScript execution",
            script_content.len()
        );
        return Ok(HashMap::new());
    }

    // Create a QuickJS runtime with memory limit
    let runtime = create_runtime()?;

    // Create a context within the runtime
    let context = create_context(&runtime)?;

    // Initialize browser stubs (window, document, etc.)
    // Use the first property name for stubs initialization (doesn't matter which one)
    if let Some((first_prop, _)) = properties.first() {
        initialize_browser_stubs(&context, first_prop);
    }

    // Execute the script content once to populate the window object
    let setup_code = format!(
        r#"
        try {{
            {}
        }} catch (e) {{
            // Ignore errors during script execution - scripts may fail but still set globals
        }}
        "#,
        script_content
    );

    // Execute the script (ignore errors - some scripts may fail but still set properties)
    context.with(|ctx| {
        if let Err(e) = ctx.eval::<rquickjs::Value, _>(setup_code.as_str()) {
            log::debug!("Script execution error (non-fatal) in batch check: {e}");
        }
    });

    // Check all properties in the same context
    let mut results = HashMap::new();
    for (js_property, pattern) in properties {
        // Build the property access expression
        let (property_expr, global_property_expr) = build_property_expression(js_property);

        // Build pattern check code
        let pattern_check = build_pattern_check(pattern);

        // Build the property check code
        let check_code = build_property_check_code(
            js_property,
            &property_expr,
            &global_property_expr,
            &pattern_check,
        );

        // Execute the property check code and convert result to bool
        let found = context.with(|ctx| {
            let result = match ctx.eval::<rquickjs::Value, _>(check_code.as_str()) {
                Ok(val) => val,
                Err(e) => {
                    log::debug!("JavaScript eval error for property '{}': {e}", js_property);
                    return false;
                }
            };

            // Result should be a boolean - rquickjs returns Value which we need to convert
            if let Some(bool_val) = result.as_bool() {
                bool_val
            } else {
                // If not a boolean, check if it's truthy (not null/undefined)
                !result.is_null() && !result.is_undefined()
            }
        });

        // Use composite key (property:pattern) because same property can have different patterns
        let key = format!("{}:{}", js_property, pattern);
        results.insert(key, found);
    }

    Ok(results)
}
