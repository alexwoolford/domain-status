//! Core JavaScript execution logic for property detection.

mod property;
mod runtime;
mod stubs;

use anyhow::Result;

use property::{build_pattern_check, build_property_check_code, build_property_expression};
use runtime::{create_context, create_runtime};
use stubs::initialize_browser_stubs;

/// Executes JavaScript code and checks if a property exists.
///
/// Uses QuickJS (via rquickjs) to execute the script and check property existence on the window object.
///
/// **Security:** This function enforces a memory limit but does NOT enforce execution timeout.
/// Callers should use `execute_js_property_check_with_timeout` instead.
pub(crate) fn execute_js_property_check(
    script_content: &str,
    js_property: &str,
    pattern: &str,
) -> Result<bool> {
    // Create a QuickJS runtime with memory limit to prevent memory exhaustion attacks
    let runtime = create_runtime()?;

    // Create a context within the runtime
    let context = create_context(&runtime)?;

    // Create window object and stub browser APIs in global scope before executing scripts
    // rquickjs doesn't have a global 'window' object by default, so we need to create it
    // Following WappalyzerGo's approach: create window, document, and other browser APIs as stubs
    // This allows scripts to initialize without errors, even if they can't fully function
    initialize_browser_stubs(&context, js_property);

    // Execute the script content to populate the window object
    // Wrap in try-catch to handle errors gracefully
    // Scripts may fail partially but still set global variables we need
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
            log::debug!(
                "Script execution error (non-fatal) for property '{}': {e}",
                js_property
            );
        }
    });

    // Build the property access expression
    let (property_expr, global_property_expr) = build_property_expression(js_property);

    // Build pattern check code
    let pattern_check = build_pattern_check(pattern);

    // Build the property check code
    let check_code = build_property_check_code(js_property, &property_expr, &global_property_expr, &pattern_check);

    // Execute the property check code and convert result to bool
    // All operations must be within the same `with` closure due to lifetime constraints
    context.with(|ctx| {
        let result = match ctx.eval::<rquickjs::Value, _>(check_code.as_str()) {
            Ok(val) => val,
            Err(e) => {
                log::debug!("JavaScript eval error for property '{}': {e}", js_property);
                return Err(anyhow::anyhow!("Failed to execute property check: {e}"));
            }
        };

        // Result should be a boolean - rquickjs returns Value which we need to convert
        // Check if it's a boolean value
        if let Some(bool_val) = result.as_bool() {
            Ok(bool_val)
        } else {
            // If not a boolean, check if it's truthy (not null/undefined)
            Ok(!result.is_null() && !result.is_undefined())
        }
    })
}

