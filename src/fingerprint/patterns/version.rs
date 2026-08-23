//! Version template evaluation for Wappalyzer patterns (`\\;version:...`).
//!
//! Handles capture placeholders (`\\1`) and ternary expressions (`\\1?foo:bar`).

/// Extracts version from template using regex capture groups.
/// Template format: "version:\\1" where \\1 refers to capture group 1
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn extract_version_from_template(
    template: &str,
    captures: &regex::Captures,
) -> Option<String> {
    if !template.starts_with("version:") {
        return None;
    }

    let version_expr = template.strip_prefix("version:").unwrap_or("").trim();
    if version_expr.is_empty() {
        return None;
    }

    // Which placeholders exist in the template (for semicolon sanity check later).
    // Check up to \99 — Wappalyzer regexes can have 10+ capture groups.
    let mut placeholders_in_template = std::collections::HashSet::new();
    for i in 1..=99 {
        let placeholder_double = format!("\\\\{i}");
        let placeholder_single = format!("\\{i}");
        if version_expr.contains(&placeholder_double) || version_expr.contains(&placeholder_single)
        {
            placeholders_in_template.insert(i);
        }
    }

    static RE_PLACEHOLDER: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"\\\d+").expect("placeholder regex"));

    // Ternary must be evaluated on the raw template (with \1, \2 placeholders) BEFORE
    // substituting capture values. Otherwise a captured value containing '?' or ':'
    // (e.g. "beta:v2") would be split by the ternary parser and corrupt the version string.
    let mut result = if version_expr.contains('?') {
        evaluate_version_ternary(version_expr, captures)
    } else {
        // Replace \1, \2, etc. with actual capture group values
        // In the template string, \1 is stored as a single backslash followed by 1
        // We need to match both \\1 (escaped in Rust string) and \1 (from JSON)
        // IMPORTANT: Only replace placeholders that actually exist in the template
        // Replace in reverse order (highest first) to avoid partial matches (e.g., \10 vs \1)
        let mut res = version_expr.to_string();

        // Replace placeholders in reverse order (highest first) to avoid partial matches
        for i in (1..captures.len()).rev() {
            if placeholders_in_template.contains(&i) {
                if let Some(cap_value) = captures.get(i) {
                    let placeholder_double = format!("\\\\{i}");
                    let placeholder_single = format!("\\{i}");
                    res = res.replace(&placeholder_double, cap_value.as_str());
                    res = res.replace(&placeholder_single, cap_value.as_str());
                }
            }
        }

        // Remove any remaining placeholders (unmatched groups)
        RE_PLACEHOLDER.replace_all(&res, "").to_string()
    };

    // Remove any remaining placeholders (e.g. ternary chose branch with \3 but only \1,\2 matched)
    result = RE_PLACEHOLDER.replace_all(&result, "").to_string();

    if result.is_empty() {
        None
    } else {
        let trimmed = result.trim().to_string();

        // Sanity check: if version contains semicolon and we only had \1 in template,
        // something went wrong. Take only the first part before semicolon.
        // This prevents issues like "64;5.3" when template was just "\1"
        if trimmed.contains(';') {
            // Check if template had multiple placeholders (like \1;\2) - if so, semicolon is intentional
            let has_multiple_placeholders = placeholders_in_template.len() > 1;
            if !has_multiple_placeholders {
                // Template only had one placeholder, but we got semicolon - take first part only
                let first_part = trimmed.split(';').next().unwrap_or(&trimmed).trim();
                if !first_part.is_empty() {
                    return Some(first_part.to_string());
                }
            }
        }
        Some(trimmed)
    }
}

/// Replaces placeholder references (\1, \2, etc.) with actual capture group values.
///
/// Handles both escaped (\\1) and unescaped (\1) placeholders.
///
/// # Arguments
///
/// * `template` - The template string with placeholders
/// * `captures` - The regex captures containing the values
///
/// # Returns
///
/// The template with placeholders replaced by capture group values
pub(super) fn replace_placeholders(template: &str, captures: &regex::Captures) -> String {
    let mut result = template.to_string();
    for i in (1..captures.len()).rev() {
        if let Some(cap_value) = captures.get(i) {
            let placeholder_double = format!("\\\\{i}");
            let placeholder_single = format!("\\{i}");
            result = result.replace(&placeholder_double, cap_value.as_str());
            result = result.replace(&placeholder_single, cap_value.as_str());
        }
    }
    result
}

/// Parses a ternary expression into its components.
///
/// Format: "value1?value1:value2"
///
/// # Arguments
///
/// * `expression` - The ternary expression string
///
/// # Returns
///
/// `Some((true_part, false_part))` if valid ternary, `None` if invalid
pub(super) fn parse_ternary_expression(expression: &str) -> Option<(&str, &str)> {
    if !expression.contains('?') {
        return None;
    }

    let parts: Vec<&str> = expression.splitn(2, '?').collect();
    let after_question = parts.get(1)?;

    let true_false_parts: Vec<&str> = after_question.splitn(2, ':').collect();
    match (true_false_parts.first(), true_false_parts.get(1)) {
        (Some(true_val), Some(false_val)) => Some((true_val, false_val)),
        _ => None,
    }
}

/// Evaluates ternary expressions in version strings (matching wappalyzergo's evaluateVersionExpression).
/// Format: "value1?value1:value2" - evaluates based on submatches
/// Logic matches wappalyzergo's evaluateVersionExpression exactly (patterns.go lines 122-151)
///
/// In wappalyzergo, `submatches` refers to capture groups AFTER the full match (submatches[1:] in extractVersion).
/// So `len(submatches) == 0` means no capture groups matched.
pub(super) fn evaluate_version_ternary(expression: &str, captures: &regex::Captures) -> String {
    // If not a ternary expression, return as-is
    let Some((true_part, false_part)) = parse_ternary_expression(expression) else {
        return expression.to_string();
    };

    // In wappalyzergo, submatches is the capture groups (excluding full match)
    // So len(submatches) == 0 means captures.len() <= 1 (only full match, no groups)
    let has_capture_groups = captures.len() > 1;

    // wappalyzergo logic (from patterns.go lines 135-147):
    // if trueFalseParts[0] != "" { // Simple existence check
    //     if len(submatches) == 0 {
    //         return trueFalseParts[1], nil
    //     }
    //     return trueFalseParts[0], nil
    // }
    // if trueFalseParts[1] == "" {
    //     if len(submatches) == 0 {
    //         return "", nil
    //     }
    //     return trueFalseParts[0], nil
    // }
    // return trueFalseParts[1], nil

    if true_part.is_empty() {
        // true_part is empty — wappalyzergo (patterns.go:141-147):
        // if trueFalseParts[1] == "" { check submatches; return trueFalseParts[0] }
        // return trueFalseParts[1]   // unconditionally when false_part is non-empty
        if false_part.is_empty() {
            // Both parts empty - return empty regardless of capture groups
            String::new()
        } else {
            // false_part is non-empty, use it (replace placeholders)
            replace_placeholders(false_part, captures)
        }
    } else {
        // true_part is non-empty
        if has_capture_groups {
            // We have capture groups, use true_part (replace placeholders)
            replace_placeholders(true_part, captures)
        } else {
            // No capture groups, use false_part (replace placeholders)
            replace_placeholders(false_part, captures)
        }
    }
}
