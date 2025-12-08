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
        // Try to compile as regex (with caching)
        // Remove version extraction syntax (e.g., ";version:\\1") for matching
        let pattern_for_match = pattern.split(';').next().unwrap_or(pattern).trim();

        // Check cache first
        // Handle mutex poisoning gracefully - if poisoned, recover by getting the inner value
        let cache = REGEX_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(cached_re) = cache.get(pattern_for_match) {
            return cached_re.is_match(text);
        }
        drop(cache); // Release lock before compilation

        // Compile regex (this is expensive, so we cache it)
        match regex::Regex::new(pattern_for_match) {
            Ok(re) => {
                // Cache the compiled regex
                // Handle mutex poisoning gracefully
                let mut cache = REGEX_CACHE.lock().unwrap_or_else(|e| e.into_inner());
                // Check again in case another thread compiled it while we were waiting
                if let Some(cached_re) = cache.get(pattern_for_match) {
                    cached_re.is_match(text)
                } else {
                    // Store in cache and use it
                    let result = re.is_match(text);
                    cache.insert(pattern_for_match.to_string(), re);
                    result
                }
            }
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
        assert!(matches_pattern("", "anything"));
        assert!(matches_pattern("", ""));
        assert!(matches_pattern("", "test string"));
    }

    #[test]
    fn test_matches_pattern_simple_substring() {
        // Simple substring matching (case-sensitive)
        assert!(matches_pattern("nginx", "nginx/1.18.0"));
        assert!(matches_pattern("WordPress", "Powered by WordPress")); // Case must match
        assert!(!matches_pattern("wordpress", "Powered by WordPress")); // Case-sensitive
        assert!(!matches_pattern("apache", "nginx/1.18.0"));
        assert!(!matches_pattern("nginx", "apache/2.4"));
    }

    #[test]
    fn test_matches_pattern_regex_starts_with_caret() {
        // Regex pattern starting with ^
        assert!(matches_pattern("^nginx", "nginx/1.18.0"));
        assert!(!matches_pattern("^nginx", "server: nginx/1.18.0"));
    }

    #[test]
    fn test_matches_pattern_regex_ends_with_dollar() {
        // Regex pattern ending with $
        assert!(matches_pattern("nginx$", "nginx"));
        assert!(!matches_pattern("nginx$", "nginx/1.18.0"));
    }

    #[test]
    fn test_matches_pattern_regex_special_chars() {
        // Regex patterns with special characters
        assert!(matches_pattern("nginx.*", "nginx/1.18.0"));
        assert!(matches_pattern("wordpress\\+", "wordpress+"));
        assert!(matches_pattern("test\\?", "test?"));
        assert!(matches_pattern("[0-9]+", "version 123"));
    }

    #[test]
    fn test_matches_pattern_invalid_regex_falls_back() {
        // Invalid regex should fall back to substring
        assert!(matches_pattern("[invalid", "text with [invalid"));
        assert!(!matches_pattern("[invalid", "text without pattern"));
    }

    #[test]
    fn test_matches_pattern_version_extraction() {
        // Patterns with version extraction syntax
        assert!(matches_pattern("nginx;version:\\1", "nginx/1.18.0"));
        assert!(matches_pattern("^wordpress;version:\\1$", "wordpress"));
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
        assert!(matches_pattern("^nginx", "nginx/1.18.0"));
        let first_call_time = start.elapsed();

        // Second call should use cache (much faster)
        let start = std::time::Instant::now();
        assert!(matches_pattern("^nginx", "nginx/1.18.0"));
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
                matches_pattern(pattern, &text),
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
                        result1, result2,
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
                handle.join().unwrap(),
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
            matches_pattern(pattern, text);
        }
        let without_cache_time = start.elapsed();

        // With cache
        clear_regex_cache();
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            matches_pattern(pattern, text);
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
        assert!(matches_pattern("[unclosed", "text with [unclosed bracket"));
        assert!(!matches_pattern("[unclosed", "text without pattern"));

        // Pattern with regex chars but invalid escape - should fall back
        assert!(matches_pattern("\\invalid", "text with \\invalid"));

        // Pattern with regex chars but unmatched parentheses - should fall back
        assert!(matches_pattern("(unclosed", "text with (unclosed paren"));

        // Pattern with regex chars but invalid quantifier - should fall back
        assert!(matches_pattern("test{invalid", "text with test{invalid"));
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
        let mut meta_tags = HashMap::new();
        meta_tags.insert("name:".to_string(), "value".to_string());

        // Empty key should not match
        assert!(!check_meta_patterns("", &["value".to_string()], &meta_tags));
    }
}
