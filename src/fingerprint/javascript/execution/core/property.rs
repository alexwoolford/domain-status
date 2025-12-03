//! JavaScript property checking logic.

/// Builds the property access expression for checking property existence.
pub fn build_property_expression(js_property: &str) -> (String, String) {
    // Handle both simple properties (e.g., "jQuery") and property paths (e.g., "window.React" or ".__NEXT_DATA__.nextExport")
    let property_expr = if js_property.starts_with('.') {
        // Property path starting with dot (e.g., ".__NEXT_DATA__.nextExport")
        // Access from window
        format!("window{}", js_property)
    } else if js_property.contains('.') {
        // Property path with dots (e.g., "window.React" or "ufe.funnelData")
        // Use as-is if it starts with window/global/self, otherwise prepend window
        if js_property.starts_with("window.")
            || js_property.starts_with("global.")
            || js_property.starts_with("self.")
        {
            js_property.to_string()
        } else {
            format!("window.{}", js_property)
        }
    } else {
        // Simple property name (e.g., "jQuery" or "NREUM")
        // Check both window.NREUM and global NREUM (some scripts set it globally, not on window)
        format!("window.{}", js_property)
    };

    // Also check global scope for properties that might not be on window
    // Some scripts (like New Relic) set properties globally: NREUM={} not window.NREUM={}
    let global_property_expr = if js_property.contains('.') {
        // For nested properties, check global scope too
        js_property.to_string()
    } else {
        // For simple properties, check global scope
        js_property.to_string()
    };

    (property_expr, global_property_expr)
}

/// Builds the pattern check code for property value matching.
pub fn build_pattern_check(pattern: &str) -> String {
    if pattern.is_empty() {
        "return true;".to_string()
    } else if pattern == "true" {
        "return value === true || value === 'true' || (typeof value === 'object' && value !== null);".to_string()
    } else if pattern == "false" {
        "return value === false || value === 'false';".to_string()
    } else {
        // For other patterns, convert to string and check
        // Escape single quotes and backslashes in pattern for JavaScript string
        let escaped_pattern = pattern.replace('\\', "\\\\").replace('\'', "\\'");
        format!(
            "return String(value).indexOf('{}') !== -1;",
            escaped_pattern
        )
    }
}

/// Builds the property check code for execution.
pub fn build_property_check_code(
    js_property: &str,
    property_expr: &str,
    global_property_expr: &str,
    pattern_check: &str,
) -> String {
    // Check if property exists by trying to access it
    // Following WappalyzerGo's approach: check typeof and then access the property
    // window should exist from initialization in global scope
    // For simple properties, also check global scope (some scripts set NREUM={} not window.NREUM={})
    if !js_property.contains('.')
        && !js_property.starts_with("window.")
        && !js_property.starts_with("global.")
        && !js_property.starts_with("self.")
    {
        // Simple property name - check both window.property and global property
        // This handles cases like New Relic where NREUM={} sets it globally, not window.NREUM={}
        format!(
            r#"
            (function() {{
                try {{
                    // Check window property first
                    var value;
                    if (typeof {} !== 'undefined') {{
                        value = {};
                    }} else if (typeof {} !== 'undefined') {{
                        // Fallback to global scope (for scripts that set NREUM={{}} not window.NREUM={{}})
                        value = {};
                    }} else {{
                        return false;
                    }}
                    
                    if (value === undefined || value === null) {{
                        return false;
                    }}
                    
                    {}
                }} catch (e) {{
                    return false;
                }}
            }})()
            "#,
            property_expr,        // typeof window.NREUM !== 'undefined'
            property_expr,        // window.NREUM
            global_property_expr, // typeof NREUM !== 'undefined'
            global_property_expr, // NREUM
            pattern_check
        )
    } else {
        // Complex property path - only check window
        format!(
            r#"
            (function() {{
                try {{
                    // Check if the property path exists (e.g., window.NREUM or window.jQuery.fn.jquery)
                    // Use typeof to safely check existence before accessing
                    var value;
                    if (typeof {} !== 'undefined') {{
                        value = {};
                    }} else {{
                        return false;
                    }}
                    
                    if (value === undefined || value === null) {{
                        return false;
                    }}
                    
                    {}
                }} catch (e) {{
                    return false;
                }}
            }})()
            "#,
            property_expr, // First check: typeof window.NREUM !== 'undefined'
            property_expr, // Second access: window.NREUM (to get the value)
            pattern_check
        )
    }
}
