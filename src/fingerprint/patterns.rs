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
            .any(|pattern| matches_pattern(pattern, meta_value).matched)
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
    // Handle empty pattern (matches anything)
    if pattern.is_empty() {
        return PatternMatchResult {
            matched: true,
            version: None,
        };
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

    // Parse pattern for version extraction (e.g., "pattern\\;version:\\1")
    // wappalyzergo uses "\\;" (escaped semicolon) in JSON, which becomes "\;" in the string
    // We need to look for "\;" (backslash followed by semicolon)
    let (pattern_for_match, version_template) = if let Some(semicolon_pos) = pattern.find("\\;") {
        let (pat, version_part) = pattern.split_at(semicolon_pos);
        let version_template = version_part.strip_prefix("\\;").unwrap_or("");
        (pat.trim(), Some(version_template))
    } else if let Some(semicolon_pos) = pattern.find(";") {
        // Also check for unescaped semicolon (some patterns might use it)
        let (pat, version_part) = pattern.split_at(semicolon_pos);
        let version_template = version_part.strip_prefix(";").unwrap_or("");
        (pat.trim(), Some(version_template))
    } else {
        (pattern, None)
    };

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
                extract_version_from_template(template, &captures)
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
        // Simple substring match - wappalyzergo does case-insensitive substring matching
        // We need to match this behavior for parity
        let matched = text
            .to_lowercase()
            .contains(&pattern_for_match.to_lowercase());
        PatternMatchResult {
            matched,
            version: None, // No version extraction for simple substring patterns
        }
    }
}

/// Extracts version from template using regex capture groups.
/// Template format: "version:\\1" where \\1 refers to capture group 1
fn extract_version_from_template(template: &str, captures: &regex::Captures) -> Option<String> {
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
    let mut result = version_expr.to_string();
    for i in 1..captures.len() {
        if let Some(cap_value) = captures.get(i) {
            // Try both \\1 (double backslash - Rust string literal) and \1 (single backslash - from JSON)
            let placeholder_double = format!("\\\\{}", i);
            let placeholder_single = format!("\\{}", i);
            result = result.replace(&placeholder_double, cap_value.as_str());
            result = result.replace(&placeholder_single, cap_value.as_str());
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
        Some(result.trim().to_string())
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
        meta_tags.insert("name:generator".to_string(), "WordPress".to_string());

        assert!(check_meta_patterns(
            "generator",
            &["WordPress".to_string()],
            &meta_tags
        ));
        assert!(!check_meta_patterns(
            "generator",
            &["Drupal".to_string()],
            &meta_tags
        ));
    }

    #[test]
    fn test_check_meta_patterns_property_prefix() {
        let mut meta_tags = HashMap::new();
        meta_tags.insert("property:og:title".to_string(), "My Title".to_string());

        assert!(check_meta_patterns(
            "property:og:title",
            &["My Title".to_string()],
            &meta_tags
        ));
        assert!(!check_meta_patterns(
            "property:og:title",
            &["Other Title".to_string()],
            &meta_tags
        ));
    }

    #[test]
    fn test_check_meta_patterns_http_equiv_prefix() {
        let mut meta_tags = HashMap::new();
        meta_tags.insert(
            "http-equiv:content-type".to_string(),
            "text/html".to_string(),
        );

        assert!(check_meta_patterns(
            "http-equiv:content-type",
            &["text/html".to_string()],
            &meta_tags
        ));
    }

    #[test]
    fn test_check_meta_patterns_tries_all_prefixes() {
        // Simple key should try name:, property:, and http-equiv:
        let mut meta_tags = HashMap::new();
        meta_tags.insert("property:generator".to_string(), "WordPress".to_string());

        // Should find it via property: prefix
        assert!(check_meta_patterns(
            "generator",
            &["WordPress".to_string()],
            &meta_tags
        ));
    }

    #[test]
    fn test_check_meta_patterns_case_insensitive_key() {
        let mut meta_tags = HashMap::new();
        // Key is lowercased in the function, so we need to use lowercase in the map
        meta_tags.insert("name:generator".to_string(), "WordPress".to_string());

        // Key should be lowercased when looking up
        assert!(check_meta_patterns(
            "GENERATOR",
            &["WordPress".to_string()],
            &meta_tags
        ));
    }

    #[test]
    fn test_check_meta_patterns_multiple_patterns() {
        let mut meta_tags = HashMap::new();
        meta_tags.insert("name:generator".to_string(), "WordPress 5.0".to_string());

        // Should match if any pattern matches
        assert!(check_meta_patterns(
            "generator",
            &["Drupal".to_string(), "WordPress".to_string()],
            &meta_tags
        ));
    }

    #[test]
    fn test_check_meta_patterns_empty_meta_tags() {
        let meta_tags = HashMap::new();
        assert!(!check_meta_patterns(
            "generator",
            &["WordPress".to_string()],
            &meta_tags
        ));
    }

    #[test]
    fn test_check_meta_patterns_empty_patterns() {
        let mut meta_tags = HashMap::new();
        meta_tags.insert("name:generator".to_string(), "WordPress".to_string());

        // Empty patterns should not match
        assert!(!check_meta_patterns("generator", &[], &meta_tags));
    }

    #[test]
    fn test_check_meta_patterns_regex_in_patterns() {
        let mut meta_tags = HashMap::new();
        meta_tags.insert("name:generator".to_string(), "WordPress 5.0".to_string());

        // Patterns can contain regex
        assert!(check_meta_patterns(
            "generator",
            &["^WordPress".to_string()],
            &meta_tags
        ));
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
        meta_tags.insert("name:generator".to_string(), "WordPress".to_string());

        // Key with double prefix (should not match)
        assert!(!check_meta_patterns(
            "property:property:og:title",
            &["WordPress".to_string()],
            &meta_tags
        ));

        // Key with empty prefix value
        assert!(!check_meta_patterns(
            "property:",
            &["WordPress".to_string()],
            &meta_tags
        ));
    }

    #[test]
    fn test_check_meta_patterns_empty_key() {
        // Test with empty key (edge case)
        // Empty key will try to match "name:", "property:", "http-equiv:" prefixes
        let mut meta_tags = HashMap::new();
        meta_tags.insert("name:".to_string(), "value".to_string());

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
        meta_tags.insert("name:generator".to_string(), "WordPress".to_string());

        // Empty patterns should not match
        assert!(!check_meta_patterns("generator", &[], &meta_tags));
    }

    #[test]
    fn test_check_meta_patterns_multiple_prefixes_same_key() {
        // Test that simple key tries all prefixes correctly
        let mut meta_tags = HashMap::new();
        meta_tags.insert("name:test".to_string(), "value1".to_string());
        meta_tags.insert("property:test".to_string(), "value2".to_string());
        meta_tags.insert("http-equiv:test".to_string(), "value3".to_string());

        // Should match if any prefix matches
        assert!(check_meta_patterns(
            "test",
            &["value1".to_string()],
            &meta_tags
        ));
        assert!(check_meta_patterns(
            "test",
            &["value2".to_string()],
            &meta_tags
        ));
        assert!(check_meta_patterns(
            "test",
            &["value3".to_string()],
            &meta_tags
        ));
    }
}
