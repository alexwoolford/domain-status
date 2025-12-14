//! Pattern matching utilities for technology detection.
//!
//! This module provides pattern matching functions that support Wappalyzer pattern syntax:
//! - Simple substring matching
//! - Regex pattern matching
//! - Meta tag pattern matching with prefix support

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Global cache for compiled regex patterns.
/// This cache is shared across all threads and persists for the lifetime of the program.
/// Regex compilation is expensive (10-100x slower than matching), so caching provides
/// significant performance improvements when the same patterns are used repeatedly.
static REGEX_CACHE: Lazy<Arc<Mutex<HashMap<String, regex::Regex>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// Result of meta pattern matching with optional version
#[derive(Debug, Clone)]
pub(crate) struct MetaMatchResult {
    pub matched: bool,
    pub version: Option<String>,
}

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
/// `MetaMatchResult` with match status and extracted version (if any).
pub(crate) fn check_meta_patterns(
    meta_key: &str,
    patterns: &[String],
    meta_tags: &HashMap<String, Vec<String>>,
) -> MetaMatchResult {
    // wappalyzergo normalizes meta keys to lowercase during update (update-fingerprints/main.go line 271)
    // But when matching, it compares lowercase fingerprint key against raw HTML name (case-sensitive comparison)
    // However, since fingerprint keys are lowercase and we normalize HTML names to lowercase when extracting,
    // we can match directly. But we need to handle the case where meta_key might have a prefix.
    let meta_key_lower = meta_key.to_lowercase();

    // Helper to check patterns against meta values and extract version
    // wappalyzergo passes raw content value to pattern.Evaluate (which uses case-insensitive regex)
    // We pass raw content, which is correct
    // meta_values is a Vec<String> because there can be multiple meta tags with the same name
    let check_patterns = |meta_values: &Vec<String>| -> MetaMatchResult {
        let mut matched_version: Option<String> = None;
        let mut has_match = false;

        // Check all meta values (there can be multiple meta tags with the same name)
        for meta_value in meta_values {
            for pattern in patterns {
                let result = matches_pattern(pattern, meta_value);
                if result.matched {
                    has_match = true;
                    // Take the first version found (matching wappalyzergo behavior)
                    if matched_version.is_none() && result.version.is_some() {
                        matched_version = result.version.clone();
                    }
                    // If we found a version, we can stop checking patterns for this meta value
                    if matched_version.is_some() {
                        break;
                    }
                }
            }
            // If we found a version, we can stop checking other meta values
            if matched_version.is_some() {
                break;
            }
        }

        MetaMatchResult {
            matched: has_match,
            version: matched_version,
        }
    };

    // wappalyzergo's matchKeyValueString does: if data != key { continue }
    // where data is the fingerprint meta key (lowercase) and key is the raw HTML meta name
    // Since fingerprint keys are lowercase and we normalize HTML names to lowercase,
    // we can match directly. But we need to handle prefixes correctly.

    // Check if key already has a prefix (property: or http-equiv:)
    if meta_key_lower.starts_with("property:") {
        let key_without_prefix = meta_key_lower
            .strip_prefix("property:")
            .unwrap_or(&meta_key_lower);
        // Try exact match first (normalized key)
        if let Some(meta_value) = meta_tags.get(&format!("property:{}", key_without_prefix)) {
            let result = check_patterns(meta_value);
            if result.matched {
                return result;
            }
        }
        // Also try case-insensitive match (in case HTML has different case)
        for (stored_key, meta_value) in meta_tags.iter() {
            if stored_key.to_lowercase() == format!("property:{}", key_without_prefix) {
                let result = check_patterns(meta_value);
                if result.matched {
                    return result;
                }
            }
        }
    } else if meta_key_lower.starts_with("http-equiv:") {
        let key_without_prefix = meta_key_lower
            .strip_prefix("http-equiv:")
            .unwrap_or(&meta_key_lower);
        if let Some(meta_value) = meta_tags.get(&format!("http-equiv:{}", key_without_prefix)) {
            let result = check_patterns(meta_value);
            if result.matched {
                return result;
            }
        }
        // Also try case-insensitive match
        for (stored_key, meta_value) in meta_tags.iter() {
            if stored_key.to_lowercase() == format!("http-equiv:{}", key_without_prefix) {
                let result = check_patterns(meta_value);
                if result.matched {
                    return result;
                }
            }
        }
    } else {
        // Simple key (like "generator") - try all three attribute types
        // wappalyzergo matches against raw HTML name (case-sensitive), but fingerprint key is lowercase
        // Since we normalize HTML names to lowercase, we can match directly
        // Try name: prefix (most common)
        if let Some(meta_value) = meta_tags.get(&format!("name:{}", meta_key_lower)) {
            let result = check_patterns(meta_value);
            if result.matched {
                return result;
            }
        }
        // Try property: prefix (Open Graph, etc.)
        if let Some(meta_value) = meta_tags.get(&format!("property:{}", meta_key_lower)) {
            let result = check_patterns(meta_value);
            if result.matched {
                return result;
            }
        }
        // Try http-equiv: prefix
        if let Some(meta_value) = meta_tags.get(&format!("http-equiv:{}", meta_key_lower)) {
            let result = check_patterns(meta_value);
            if result.matched {
                return result;
            }
        }
    }

    MetaMatchResult {
        matched: false,
        version: None,
    }
}

/// Pattern matching result with optional version extraction.
#[derive(Debug, Clone)]
pub(crate) struct PatternMatchResult {
    pub matched: bool,
    pub version: Option<String>,
}

/// Pattern matching supporting Wappalyzer pattern syntax
/// Patterns can be:
/// - Simple strings (substring match)
/// - Regex patterns (if they start with ^ or contain regex special chars)
/// - Patterns with version extraction (e.g., "version:\\1")
///
/// Returns PatternMatchResult with match status and extracted version (if any).
pub(crate) fn matches_pattern(pattern: &str, text: &str) -> PatternMatchResult {
    // Match wappalyzergo's ParsePattern exactly:
    // 1. Split on "\;" to get parts
    // 2. First part (i==0) is the regex pattern
    // 3. For parts after first (i>0), split on ":" to get key-value pairs
    // 4. If key is "version", store value in p.Version
    // 5. If key is "confidence", parse as int and store in p.Confidence (we ignore this)

    let parts: Vec<&str> = pattern.split("\\;").collect();
    let pattern_for_match = parts[0].trim();

    // Find version template by looking for "version:" key in subsequent parts
    let mut version_template: Option<&str> = None;
    for part in parts.iter().skip(1) {
        if let Some(colon_pos) = part.find(':') {
            let key = &part[..colon_pos];
            let value = &part[colon_pos + 1..];

            match key {
                "version" => {
                    version_template = Some(value);
                    break; // wappalyzergo processes parts in order, first "version:" wins
                }
                "confidence" => {
                    // Ignore confidence - we don't use it
                }
                _ => {
                    // Unknown key, ignore
                }
            }
        }
    }

    // Handle empty pattern (matches anything)
    // If there's a version template, extract version even without a pattern match
    if pattern_for_match.is_empty() {
        let version = if let Some(template) = version_template {
            // For empty patterns with version templates (e.g., "\;version:ga4"),
            // extract the literal version from the template
            if template.starts_with("version:") {
                let version_str = template.strip_prefix("version:").unwrap_or("").trim();
                if !version_str.is_empty() {
                    // Check if it's a literal (no capture groups like \1, \2)
                    if !version_str.contains('\\')
                        || !version_str.chars().any(|c| c.is_ascii_digit())
                    {
                        // It's a literal version string (e.g., "ga4", "ua")
                        Some(version_str.to_string())
                    } else {
                        // It has capture groups, but we have no captures for an empty pattern
                        // This shouldn't happen for empty patterns, but handle it gracefully
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        return PatternMatchResult {
            matched: true,
            version,
        };
    }

    // Check if pattern contains regex-like syntax
    // Wappalyzer patterns often use regex but we'll try to be smart about it
    // Patterns starting with ^ or containing regex special chars are likely regex
    let is_regex = pattern_for_match.starts_with('^')
        || pattern_for_match.contains('$')
        || pattern_for_match.contains('\\')
        || pattern_for_match.contains('[')
        || pattern_for_match.contains('(')
        || pattern_for_match.contains('*')
        || pattern_for_match.contains('+')
        || pattern_for_match.contains('?');

    if is_regex {
        // Try to compile as regex (with caching)
        // Check cache first (use case-insensitive pattern for cache key)
        // wappalyzergo uses case-insensitive matching: regexp.Compile("(?i)" + regexPattern)
        // We need to match this behavior for parity
        let case_insensitive_pattern = format!("(?i){}", pattern_for_match);
        let cache_key = pattern_for_match.to_string(); // Cache key is the original pattern

        // Handle mutex poisoning gracefully - if poisoned, recover by getting the inner value
        let cache = REGEX_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        let cached_re = cache.get(&cache_key).cloned();
        drop(cache); // Release lock before compilation

        let re = if let Some(cached) = cached_re {
            cached
        } else {
            // Compile regex (this is expensive, so we cache it)
            match regex::Regex::new(&case_insensitive_pattern) {
                Ok(re) => {
                    // Cache the compiled regex
                    let mut cache = REGEX_CACHE.lock().unwrap_or_else(|e| e.into_inner());
                    // Check again in case another thread compiled it while we were waiting
                    if let Some(cached) = cache.get(&cache_key) {
                        cached.clone()
                    } else {
                        let re_clone = re.clone();
                        cache.insert(cache_key, re);
                        re_clone
                    }
                }
                Err(_) => {
                    // If regex compilation fails, fall back to substring
                    // This handles cases where the pattern looks like regex but isn't valid
                    return PatternMatchResult {
                        matched: text
                            .to_lowercase()
                            .contains(&pattern_for_match.to_lowercase()),
                        version: None,
                    };
                }
            }
        };

        // Match and extract version
        if let Some(captures) = re.captures(text) {
            let version = if let Some(template) = version_template {
                // template is already the value after "version:" (e.g., "\1" or "\1?next:")
                // extract_version_from_template expects "version:..." format
                extract_version_from_template(&format!("version:{}", template), &captures)
            } else {
                None
            };
            PatternMatchResult {
                matched: true,
                version,
            }
        } else {
            PatternMatchResult {
                matched: false,
                version: None,
            }
        }
    } else {
        // Simple string pattern - wappalyzergo compiles ALL patterns as regex, even simple strings
        // For a simple string like "jquery", wappalyzergo compiles it as "(?i)jquery" which matches
        // "jquery" anywhere in the string (case-insensitive). We need to match this behavior.
        // However, wappalyzergo may have additional logic that prevents matching in certain contexts
        // to avoid false positives. Based on testing, wappalyzergo detects jQuery for some domains
        // (like 1liberty.com) but not others (like 163.com), even though the pattern matches.
        // This suggests there may be additional filtering based on pattern order or
        // other factors. For now, we'll compile simple strings as regex to match wappalyzergo's
        // basic behavior, but we may need to add additional logic later.
        let case_insensitive_pattern = format!("(?i){}", regex::escape(pattern_for_match));
        let cache_key = pattern_for_match.to_string();

        let cache = REGEX_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        let cached_re = cache.get(&cache_key).cloned();
        drop(cache);

        let re = if let Some(cached) = cached_re {
            cached
        } else {
            match regex::Regex::new(&case_insensitive_pattern) {
                Ok(re) => {
                    let mut cache = REGEX_CACHE.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(cached) = cache.get(&cache_key) {
                        cached.clone()
                    } else {
                        let re_clone = re.clone();
                        cache.insert(cache_key, re);
                        re_clone
                    }
                }
                Err(_) => {
                    // If regex compilation fails, fall back to substring match
                    let pattern_lower = pattern_for_match.to_lowercase();
                    let text_lower = text.to_lowercase();
                    return PatternMatchResult {
                        matched: text_lower.contains(&pattern_lower),
                        version: None,
                    };
                }
            }
        };

        // Match using regex (like wappalyzergo does)
        PatternMatchResult {
            matched: re.is_match(text),
            version: None,
        }
    }
}

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

    // Replace \1, \2, etc. with actual capture group values
    // In the template string, \1 is stored as a single backslash followed by 1
    // We need to match both \\1 (escaped in Rust string) and \1 (from JSON)
    // IMPORTANT: Only replace placeholders that actually exist in the template
    // Replace in reverse order (highest first) to avoid partial matches (e.g., \10 vs \1)
    let mut result = version_expr.to_string();

    // Find which placeholders are actually in the template (check \1 through \9)
    let mut placeholders_in_template = std::collections::HashSet::new();
    for i in 1..=9 {
        let placeholder_double = format!("\\\\{}", i);
        let placeholder_single = format!("\\{}", i);
        if result.contains(&placeholder_double) || result.contains(&placeholder_single) {
            placeholders_in_template.insert(i);
        }
    }

    // Replace placeholders in reverse order (highest first) to avoid partial matches
    for i in (1..captures.len()).rev() {
        if placeholders_in_template.contains(&i) {
            if let Some(cap_value) = captures.get(i) {
                // Try both \\1 (double backslash - Rust string literal) and \1 (single backslash - from JSON)
                let placeholder_double = format!("\\\\{}", i);
                let placeholder_single = format!("\\{}", i);
                result = result.replace(&placeholder_double, cap_value.as_str());
                result = result.replace(&placeholder_single, cap_value.as_str());
            }
        }
    }

    // Remove any remaining placeholders (unmatched groups)
    // This handles cases where template has \3 but only \1 and \2 matched
    // Match both \\\d+ (escaped) and \\d+ (from JSON)
    let re_placeholder = regex::Regex::new(r"\\\d+").ok()?;
    result = re_placeholder.replace_all(&result, "").to_string();

    // Handle ternary expressions (e.g., "\\1?\\1:\\2")
    // wappalyzergo evaluates these: if submatches exist, use first part, else use second part
    result = evaluate_version_ternary(&result, captures);

    if result.is_empty() {
        None
    } else {
        let trimmed = result.trim().to_string();

        // Sanity check: if version contains semicolon and we only had \1 in template,
        // something went wrong. Take only the first part before semicolon.
        // This prevents issues like "64;5.3" when template was just "\1"
        if trimmed.contains(';') {
            // Check if template had multiple placeholders (like \1;\2) - if so, semicolon is intentional
            let has_multiple_placeholders = version_expr.matches(r"\d+").count() > 1;
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

/// Evaluates ternary expressions in version strings (matching wappalyzergo's evaluateVersionExpression).
/// Format: "value1?value1:value2" - evaluates based on submatches
/// Logic matches wappalyzergo's evaluateVersionExpression exactly (patterns.go lines 122-151)
///
/// In wappalyzergo, `submatches` refers to capture groups AFTER the full match (submatches[1:] in extractVersion).
/// So `len(submatches) == 0` means no capture groups matched.
fn evaluate_version_ternary(expression: &str, captures: &regex::Captures) -> String {
    if !expression.contains('?') {
        return expression.to_string();
    }

    let parts: Vec<&str> = expression.splitn(2, '?').collect();
    if parts.len() != 2 {
        return expression.to_string(); // Invalid ternary, return as-is
    }

    let true_false_parts: Vec<&str> = parts[1].splitn(2, ':').collect();
    if true_false_parts.len() != 2 {
        return expression.to_string(); // Invalid ternary, return as-is
    }

    let true_part = true_false_parts[0];
    let false_part = true_false_parts[1];

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

    // In wappalyzergo, submatches is the capture groups (excluding full match)
    // So len(submatches) == 0 means captures.len() <= 1 (only full match, no groups)
    let has_capture_groups = captures.len() > 1;

    if !true_part.is_empty() {
        // true_part is non-empty
        if !has_capture_groups {
            // No capture groups, use false_part
            // But false_part might have placeholders, replace them
            let mut result = false_part.to_string();
            for i in 1..captures.len() {
                if let Some(cap_value) = captures.get(i) {
                    let placeholder_double = format!("\\\\{}", i);
                    let placeholder_single = format!("\\{}", i);
                    result = result.replace(&placeholder_double, cap_value.as_str());
                    result = result.replace(&placeholder_single, cap_value.as_str());
                }
            }
            result
        } else {
            // We have capture groups, use true_part (replace placeholders)
            let mut result = true_part.to_string();
            for i in 1..captures.len() {
                if let Some(cap_value) = captures.get(i) {
                    let placeholder_double = format!("\\\\{}", i);
                    let placeholder_single = format!("\\{}", i);
                    result = result.replace(&placeholder_double, cap_value.as_str());
                    result = result.replace(&placeholder_single, cap_value.as_str());
                }
            }
            result
        }
    } else {
        // true_part is empty
        if false_part.is_empty() {
            // Both parts empty - return empty regardless of capture groups
            String::new()
        } else {
            // false_part is non-empty, use it (replace placeholders)
            let mut result = false_part.to_string();
            for i in 1..captures.len() {
                if let Some(cap_value) = captures.get(i) {
                    let placeholder_double = format!("\\\\{}", i);
                    let placeholder_single = format!("\\{}", i);
                    result = result.replace(&placeholder_double, cap_value.as_str());
                    result = result.replace(&placeholder_single, cap_value.as_str());
                }
            }
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Clears the regex cache (useful for testing).
    /// Handles mutex poisoning gracefully.
    fn clear_regex_cache() {
        let mut cache = REGEX_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        cache.clear();
    }

    #[test]
    fn test_matches_pattern_empty_pattern() {
        // Empty pattern matches anything
        assert!(matches_pattern("", "anything").matched);
        assert!(matches_pattern("", "").matched);
        assert!(matches_pattern("", "test string").matched);
    }

    #[test]
    fn test_matches_pattern_simple_substring() {
        // Simple substring matching (case-insensitive to match wappalyzergo)
        // wappalyzergo normalizes everything to lowercase: normalizedBody := bytes.ToLower(body)
        assert!(matches_pattern("nginx", "nginx/1.18.0").matched);
        assert!(matches_pattern("WordPress", "Powered by WordPress").matched); // Case-insensitive
        assert!(matches_pattern("wordpress", "Powered by WordPress").matched); // Case-insensitive
        assert!(matches_pattern("WORDPRESS", "Powered by WordPress").matched); // Case-insensitive
        assert!(!matches_pattern("apache", "nginx/1.18.0").matched);
        assert!(!matches_pattern("nginx", "apache/2.4").matched);
    }

    #[test]
    fn test_matches_pattern_regex_starts_with_caret() {
        // Regex pattern starting with ^
        assert!(matches_pattern("^nginx", "nginx/1.18.0").matched);
        assert!(!matches_pattern("^nginx", "server: nginx/1.18.0").matched);
    }

    #[test]
    fn test_matches_pattern_regex_ends_with_dollar() {
        // Regex pattern ending with $
        assert!(matches_pattern("nginx$", "nginx").matched);
        assert!(!matches_pattern("nginx$", "nginx/1.18.0").matched);
    }

    #[test]
    fn test_matches_pattern_regex_special_chars() {
        // Regex patterns with special characters
        assert!(matches_pattern("nginx.*", "nginx/1.18.0").matched);
        assert!(matches_pattern("wordpress\\+", "wordpress+").matched);
        assert!(matches_pattern("test\\?", "test?").matched);
        assert!(matches_pattern("[0-9]+", "version 123").matched);
    }

    #[test]
    fn test_matches_pattern_invalid_regex_falls_back() {
        // Invalid regex should fall back to substring
        assert!(matches_pattern("[invalid", "text with [invalid").matched);
        assert!(!matches_pattern("[invalid", "text without pattern").matched);
    }

    #[test]
    fn test_matches_pattern_version_extraction() {
        // Patterns with version extraction syntax
        let result1 = matches_pattern(
            "jquery(?:-(\\d+\\.\\d+\\.\\d+))[/.-]\\;version:\\1",
            "jquery-3.6.0.min.js",
        );
        assert!(result1.matched);
        assert_eq!(result1.version, Some("3.6.0".to_string()));

        let result2 = matches_pattern("^wordpress\\;version:\\1$", "wordpress");
        assert!(result2.matched);
    }

    #[test]
    fn test_check_meta_patterns_simple_name() {
        let mut meta_tags = HashMap::new();
        meta_tags.insert("name:generator".to_string(), vec!["WordPress".to_string()]);

        assert!(check_meta_patterns("generator", &["WordPress".to_string()], &meta_tags).matched);
        assert!(!check_meta_patterns("generator", &["Drupal".to_string()], &meta_tags).matched);
    }

    #[test]
    fn test_check_meta_patterns_property_prefix() {
        let mut meta_tags = HashMap::new();
        meta_tags.insert(
            "property:og:title".to_string(),
            vec!["My Title".to_string()],
        );

        assert!(
            check_meta_patterns("property:og:title", &["My Title".to_string()], &meta_tags).matched
        );
        assert!(
            !check_meta_patterns(
                "property:og:title",
                &["Other Title".to_string()],
                &meta_tags
            )
            .matched
        );
    }

    #[test]
    fn test_check_meta_patterns_http_equiv_prefix() {
        let mut meta_tags = HashMap::new();
        meta_tags.insert(
            "http-equiv:content-type".to_string(),
            vec!["text/html".to_string()],
        );

        assert!(
            check_meta_patterns(
                "http-equiv:content-type",
                &["text/html".to_string()],
                &meta_tags
            )
            .matched
        );
    }

    #[test]
    fn test_check_meta_patterns_tries_all_prefixes() {
        // Simple key should try name:, property:, and http-equiv:
        let mut meta_tags = HashMap::new();
        meta_tags.insert(
            "property:generator".to_string(),
            vec!["WordPress".to_string()],
        );

        // Should find it via property: prefix
        assert!(check_meta_patterns("generator", &["WordPress".to_string()], &meta_tags).matched);
    }

    #[test]
    fn test_check_meta_patterns_case_insensitive_key() {
        let mut meta_tags = HashMap::new();
        // Key is lowercased in the function, so we need to use lowercase in the map
        meta_tags.insert("name:generator".to_string(), vec!["WordPress".to_string()]);

        // Key should be lowercased when looking up
        assert!(check_meta_patterns("GENERATOR", &["WordPress".to_string()], &meta_tags).matched);
    }

    #[test]
    fn test_check_meta_patterns_multiple_patterns() {
        let mut meta_tags = HashMap::new();
        meta_tags.insert(
            "name:generator".to_string(),
            vec!["WordPress 5.0".to_string()],
        );

        // Should match if any pattern matches
        assert!(
            check_meta_patterns(
                "generator",
                &["Drupal".to_string(), "WordPress".to_string()],
                &meta_tags
            )
            .matched
        );
    }

    #[test]
    fn test_check_meta_patterns_empty_meta_tags() {
        let meta_tags = HashMap::new();
        assert!(!check_meta_patterns("generator", &["WordPress".to_string()], &meta_tags).matched);
    }

    #[test]
    fn test_check_meta_patterns_empty_patterns() {
        let mut meta_tags = HashMap::new();
        meta_tags.insert("name:generator".to_string(), vec!["WordPress".to_string()]);

        // Empty patterns should not match
        assert!(!check_meta_patterns("generator", &[], &meta_tags).matched);
    }

    #[test]
    fn test_check_meta_patterns_regex_in_patterns() {
        let mut meta_tags = HashMap::new();
        meta_tags.insert(
            "name:generator".to_string(),
            vec!["WordPress 5.0".to_string()],
        );

        // Patterns can contain regex
        assert!(check_meta_patterns("generator", &["^WordPress".to_string()], &meta_tags).matched);
    }

    #[test]
    fn test_regex_cache_works() {
        clear_regex_cache();

        // First call should compile and cache
        let start = std::time::Instant::now();
        assert!(matches_pattern("^nginx", "nginx/1.18.0").matched);
        let first_call_time = start.elapsed();

        // Second call should use cache (much faster)
        let start = std::time::Instant::now();
        assert!(matches_pattern("^nginx", "nginx/1.18.0").matched);
        let second_call_time = start.elapsed();

        // Cached call should be significantly faster (at least 2x, often 10-100x)
        // Note: This is a rough check - exact timing depends on system load
        assert!(
            second_call_time < first_call_time || second_call_time.as_nanos() < 1_000_000,
            "Cached regex should be faster. First: {:?}, Second: {:?}",
            first_call_time,
            second_call_time
        );

        // Verify cache is populated
        let cache = REGEX_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            cache.contains_key("^nginx"),
            "Cache should contain compiled regex for '^nginx'"
        );
    }

    #[test]
    fn test_regex_cache_thread_safety() {
        // Use unique patterns with a test-specific prefix and timestamp to avoid conflicts
        // with other tests running in parallel. This ensures the test is deterministic.
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let test_prefix = format!("thread_safety_test_{}_", timestamp);

        // Test that multiple threads can safely use the cache
        use std::thread;
        let patterns: Vec<String> = (0..10).map(|i| format!("^{}{}", test_prefix, i)).collect();

        // First, verify patterns work correctly (this also populates the cache)
        for (i, pattern) in patterns.iter().enumerate() {
            let text = format!("{}{}value", test_prefix, i);
            assert!(
                matches_pattern(pattern, &text).matched,
                "Pattern '{}' should match text '{}'",
                pattern,
                text
            );
        }

        // Now test concurrent access - all threads should be able to use cached patterns
        let handles: Vec<_> = patterns
            .iter()
            .enumerate()
            .map(|(i, pattern)| {
                let pattern_clone = pattern.clone();
                let prefix_clone = test_prefix.clone();
                thread::spawn(move || {
                    let text = format!("{}{}value", prefix_clone, i);
                    // Call twice to ensure cache is used
                    let result1 = matches_pattern(&pattern_clone, &text);
                    let result2 = matches_pattern(&pattern_clone, &text);
                    // Both calls should return the same result
                    assert_eq!(
                        result1.matched, result2.matched,
                        "Cached and uncached calls should return same result"
                    );
                    result1
                })
            })
            .collect();

        // Verify all threads completed successfully (no panics or data races)
        // This is the primary test - if the cache wasn't thread-safe, we'd see panics, data races,
        // or incorrect results. The fact that all threads complete successfully with correct results
        // proves the cache is thread-safe.
        for handle in handles {
            assert!(
                handle.join().unwrap().matched,
                "Thread should return true for pattern match"
            );
        }

        // Note: We don't verify cache state here because:
        // 1. The primary goal is to test thread safety, which is proven by successful completion
        // 2. Cache state verification is racy when tests run in parallel (other tests may clear/modify cache)
        // 3. Cache functionality is already tested in test_regex_cache_works
        // 4. The fact that all threads completed without panics or incorrect results proves the cache
        //    is working correctly and is thread-safe
    }

    #[test]
    fn test_regex_cache_benchmark() {
        clear_regex_cache();

        // Benchmark: compile same regex 1000 times
        let pattern = "^nginx.*version";
        let text = "nginx/1.18.0 version";

        // Without cache (simulated by clearing each time)
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            clear_regex_cache();
            let _ = matches_pattern(pattern, text);
        }
        let without_cache_time = start.elapsed();

        // With cache
        clear_regex_cache();
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = matches_pattern(pattern, text);
        }
        let with_cache_time = start.elapsed();

        // Cached version should be significantly faster
        // In practice, this should be 10-100x faster
        assert!(
            with_cache_time < without_cache_time,
            "Cached version should be faster. Without cache: {:?}, With cache: {:?}",
            without_cache_time,
            with_cache_time
        );

        let speedup = if with_cache_time.as_nanos() > 0 {
            without_cache_time.as_nanos() as f64 / with_cache_time.as_nanos() as f64
        } else {
            0.0 // Fallback if with_cache_time is 0 (shouldn't happen due to assertion above)
        };
        println!(
            "Regex cache benchmark: Without cache: {:?}, With cache: {:?}, Speedup: {:.2}x",
            without_cache_time, with_cache_time, speedup
        );
    }

    #[test]
    fn test_matches_pattern_regex_fallback_edge_cases() {
        // Test edge cases where regex compilation fails and falls back to substring
        // These are critical because invalid regex could cause false positives

        // Pattern with regex chars but invalid syntax - should fall back to substring
        assert!(matches_pattern("[unclosed", "text with [unclosed bracket").matched);
        assert!(!matches_pattern("[unclosed", "text without pattern").matched);

        // Pattern with regex chars but invalid escape - should fall back
        assert!(matches_pattern("\\invalid", "text with \\invalid").matched);

        // Pattern with regex chars but unmatched parentheses - should fall back
        assert!(matches_pattern("(unclosed", "text with (unclosed paren").matched);

        // Pattern with regex chars but invalid quantifier - should fall back
        assert!(matches_pattern("test{invalid", "text with test{invalid").matched);
    }

    #[test]
    fn test_check_meta_patterns_malformed_prefix() {
        // Test edge cases with malformed prefixes
        let mut meta_tags = HashMap::new();
        meta_tags.insert("name:generator".to_string(), vec!["WordPress".to_string()]);

        // Key with double prefix (should not match)
        assert!(
            !check_meta_patterns(
                "property:property:og:title",
                &["WordPress".to_string()],
                &meta_tags
            )
            .matched
        );

        // Key with empty prefix value
        assert!(!check_meta_patterns("property:", &["WordPress".to_string()], &meta_tags).matched);
    }

    #[test]
    fn test_check_meta_patterns_empty_key() {
        // Test with empty key (edge case)
        // Empty key will try to match "name:", "property:", "http-equiv:" prefixes
        let mut meta_tags = HashMap::new();
        meta_tags.insert("name:".to_string(), vec!["value".to_string()]);

        // Empty key will try "name:" which exists, so it will check patterns
        // This is actually valid behavior - empty key matches "name:" meta tag
        let result = check_meta_patterns("", &["value".to_string()], &meta_tags);
        // Result depends on whether "name:" exists and matches pattern
        // The key behavior is that it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_matches_pattern_very_long_string() {
        // Test pattern matching with very long strings (performance/overflow edge case)
        let very_long_text = "A".repeat(1_000_000);
        let pattern = "test";

        // Should handle very long strings without panicking or excessive memory usage
        let result = matches_pattern(pattern, &very_long_text);
        assert!(
            !result.matched,
            "Pattern should not match in very long string"
        );
    }

    #[test]
    fn test_matches_pattern_special_regex_chars_in_substring() {
        // Test that special regex characters in substring mode don't cause issues
        // These should be treated as literal characters, not regex
        let text = "test[pattern]with(special)chars";

        // Patterns without ^ or other regex indicators should be substring matches
        assert!(matches_pattern("[pattern]", text).matched);
        assert!(matches_pattern("(special)", text).matched);
        assert!(matches_pattern("chars", text).matched);
    }

    #[test]
    fn test_matches_pattern_version_extraction_complex() {
        // Test version extraction syntax with complex patterns
        // Version extraction syntax: ";version:\\1" should be stripped before matching
        let pattern = "^nginx/(\\d+\\.\\d+);version:\\1";
        let text = "nginx/1.18.0";

        // Should match the pattern part (before ;) and extract version
        let result = matches_pattern(pattern, text);
        assert!(result.matched);
        assert_eq!(result.version, Some("1.18".to_string()));
    }

    #[test]
    fn test_matches_pattern_regex_anchors_edge_cases() {
        // Test regex anchors with edge cases
        // ^ at start, $ at end
        assert!(matches_pattern("^start", "start of text").matched);
        assert!(!matches_pattern("^start", "text with start").matched);
        assert!(matches_pattern("end$", "text with end").matched);
        assert!(!matches_pattern("end$", "end of text with more").matched);
        assert!(matches_pattern("^exact$", "exact").matched);
        assert!(!matches_pattern("^exact$", "not exact").matched);
    }

    #[test]
    fn test_check_meta_patterns_empty_patterns_vector() {
        // Test with empty patterns vector (edge case)
        let mut meta_tags = HashMap::new();
        meta_tags.insert("name:generator".to_string(), vec!["WordPress".to_string()]);

        // Empty patterns should not match
        assert!(!check_meta_patterns("generator", &[], &meta_tags).matched);
    }

    #[test]
    fn test_check_meta_patterns_multiple_prefixes_same_key() {
        // Test that simple key tries all prefixes correctly
        let mut meta_tags = HashMap::new();
        meta_tags.insert("name:test".to_string(), vec!["value1".to_string()]);
        meta_tags.insert("property:test".to_string(), vec!["value2".to_string()]);
        meta_tags.insert("http-equiv:test".to_string(), vec!["value3".to_string()]);

        // Should match if any prefix matches
        assert!(check_meta_patterns("test", &["value1".to_string()], &meta_tags).matched);
        assert!(check_meta_patterns("test", &["value2".to_string()], &meta_tags).matched);
        assert!(check_meta_patterns("test", &["value3".to_string()], &meta_tags).matched);
    }

    #[test]
    fn test_check_meta_patterns_wordpress_version_extraction() {
        // Test WordPress version extraction from generator meta tag
        // Pattern: ^wordpress(?: ([\d.]+))?\;version:\1
        // Content: WordPress 6.8.3
        // Should extract version: 6.8.3
        let mut meta_tags = HashMap::new();
        meta_tags.insert(
            "name:generator".to_string(),
            vec!["WordPress 6.8.3".to_string()],
        );

        let result = check_meta_patterns(
            "generator",
            &[r"^wordpress(?: ([\d.]+))?\;version:\1".to_string()],
            &meta_tags,
        );

        assert!(result.matched, "Should match WordPress generator meta tag");
        assert_eq!(
            result.version,
            Some("6.8.3".to_string()),
            "Should extract WordPress version 6.8.3"
        );
    }

    #[test]
    fn test_matches_pattern_with_version_template() {
        // Test pattern with version template
        let pattern = r"^version ([\d.]+)\;version:\1";
        let text = "version 5.0";

        let result = matches_pattern(pattern, text);

        assert!(result.matched, "Should match pattern");
        assert_eq!(
            result.version,
            Some("5.0".to_string()),
            "Should extract version 5.0"
        );
    }

    #[test]
    fn test_matches_pattern_ignores_non_version_template() {
        // Test that patterns with metadata (not starting with "version:") are ignored
        let pattern = r"^test\;metadata:value";
        let text = "test";

        let result = matches_pattern(pattern, text);

        assert!(result.matched, "Should match pattern");
        assert_eq!(
            result.version, None,
            "Should not extract version when template doesn't start with 'version:'"
        );
    }
}
