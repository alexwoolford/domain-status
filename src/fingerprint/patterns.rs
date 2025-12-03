//! Pattern matching utilities for technology detection.
//!
//! This module provides pattern matching functions that support Wappalyzer pattern syntax:
//! - Simple substring matching
//! - Regex pattern matching
//! - Meta tag pattern matching with prefix support

use std::collections::HashMap;

/// Checks if meta tag patterns match any meta tag values.
///
/// Wappalyzer meta patterns can be:
/// - Simple name: "generator" -> matches meta name="generator"
/// - Prefixed: "property:og:title" -> matches meta property="og:title"
/// - Prefixed: "http-equiv:content-type" -> matches meta http-equiv="content-type"
///
/// For simple keys (without prefix), tries all three attribute types (name, property, http-equiv).
///
/// # Arguments
///
/// * `meta_key` - The meta key from the technology ruleset
/// * `patterns` - Vector of patterns to match against meta values
/// * `meta_tags` - HashMap of extracted meta tags (key format: "prefix:name")
///
/// # Returns
///
/// `true` if any pattern matches any meta tag value, `false` otherwise.
pub(crate) fn check_meta_patterns(
    meta_key: &str,
    patterns: &[String],
    meta_tags: &HashMap<String, String>,
) -> bool {
    let meta_key_lower = meta_key.to_lowercase();

    // Helper to check patterns against a meta value
    let check_patterns = |meta_value: &str| -> bool {
        patterns
            .iter()
            .any(|pattern| matches_pattern(pattern, meta_value))
    };

    // Check if key already has a prefix (property: or http-equiv:)
    if meta_key_lower.starts_with("property:") {
        let key_without_prefix = meta_key_lower
            .strip_prefix("property:")
            .unwrap_or(&meta_key_lower);
        if let Some(meta_value) = meta_tags.get(&format!("property:{}", key_without_prefix)) {
            return check_patterns(meta_value);
        }
    } else if meta_key_lower.starts_with("http-equiv:") {
        let key_without_prefix = meta_key_lower
            .strip_prefix("http-equiv:")
            .unwrap_or(&meta_key_lower);
        if let Some(meta_value) = meta_tags.get(&format!("http-equiv:{}", key_without_prefix)) {
            return check_patterns(meta_value);
        }
    } else {
        // Simple key (like "generator") - try all three attribute types
        // Try name: prefix (most common)
        if let Some(meta_value) = meta_tags.get(&format!("name:{}", meta_key_lower)) {
            if check_patterns(meta_value) {
                return true;
            }
        }
        // Try property: prefix (Open Graph, etc.)
        if let Some(meta_value) = meta_tags.get(&format!("property:{}", meta_key_lower)) {
            if check_patterns(meta_value) {
                return true;
            }
        }
        // Try http-equiv: prefix
        if let Some(meta_value) = meta_tags.get(&format!("http-equiv:{}", meta_key_lower)) {
            if check_patterns(meta_value) {
                return true;
            }
        }
    }

    false
}

/// Pattern matching supporting Wappalyzer pattern syntax
/// Patterns can be:
/// - Simple strings (substring match)
/// - Regex patterns (if they start with ^ or contain regex special chars)
/// - Patterns with version extraction (e.g., "version:\\1")
pub(crate) fn matches_pattern(pattern: &str, text: &str) -> bool {
    // Handle empty pattern (matches anything)
    if pattern.is_empty() {
        return true;
    }

    // Check if pattern contains regex-like syntax
    // Wappalyzer patterns often use regex but we'll try to be smart about it
    // Patterns starting with ^ or containing regex special chars are likely regex
    let is_regex = pattern.starts_with('^')
        || pattern.contains('$')
        || pattern.contains('\\')
        || pattern.contains('[')
        || pattern.contains('(')
        || pattern.contains('*')
        || pattern.contains('+')
        || pattern.contains('?');

    if is_regex {
        // Try to compile as regex
        // Remove version extraction syntax (e.g., ";version:\\1") for matching
        let pattern_for_match = pattern.split(';').next().unwrap_or(pattern).trim();

        match regex::Regex::new(pattern_for_match) {
            Ok(re) => re.is_match(text),
            Err(_) => {
                // If regex compilation fails, fall back to substring
                // This handles cases where the pattern looks like regex but isn't valid
                text.contains(pattern)
            }
        }
    } else {
        // Simple substring match
        text.contains(pattern)
    }
}
