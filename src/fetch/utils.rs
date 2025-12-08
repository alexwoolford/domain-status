//! Shared utilities for the fetch module.
//!
//! Provides common helper functions used across multiple fetch submodules.

/// Serializes a value to JSON string.
///
/// Note: JSON object key order is not guaranteed by the JSON spec, but serde_json
/// typically preserves insertion order for HashMap. If deterministic key ordering
/// is required, use BTreeMap in the source data structure instead.
///
/// # Errors
///
/// If serialization fails, logs a warning and returns an empty JSON object `"{}"`.
pub(crate) fn serialize_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|e| {
        log::warn!(
            "Failed to serialize value to JSON: {}. Using default: {{}}",
            e
        );
        "{}".to_string()
    })
}

/// Serializes a value to JSON string with a custom default for errors.
///
/// Useful for arrays where we want "[]" instead of "{}" on serialization failure.
///
/// # Arguments
///
/// * `value` - The value to serialize
/// * `default` - The default string to return if serialization fails
///
/// # Errors
///
/// If serialization fails, logs a warning and returns the provided default.
pub(crate) fn serialize_json_with_default<T: serde::Serialize>(value: &T, default: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|e| {
        log::warn!(
            "Failed to serialize value to JSON: {}. Using default: {}",
            e,
            default
        );
        default.to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_serialize_json_success() {
        let mut map = HashMap::new();
        map.insert("key1", "value1");
        map.insert("key2", "value2");
        let json = serialize_json(&map);
        assert!(json.contains("key1"));
        assert!(json.contains("value1"));
        assert!(json.contains("key2"));
        assert!(json.contains("value2"));
    }

    #[test]
    fn test_serialize_json_array() {
        let vec = vec!["item1", "item2", "item3"];
        let json = serialize_json(&vec);
        assert_eq!(json, r#"["item1","item2","item3"]"#);
    }

    #[test]
    fn test_serialize_json_with_default_success() {
        let vec = vec!["item1", "item2"];
        let json = serialize_json_with_default(&vec, "[]");
        assert_eq!(json, r#"["item1","item2"]"#);
    }

    #[test]
    fn test_serialize_json_with_default_custom() {
        let vec = vec!["item1"];
        let json = serialize_json_with_default(&vec, "[]");
        assert_eq!(json, r#"["item1"]"#);
    }

    #[test]
    fn test_serialize_json_with_default_empty_array() {
        let vec: Vec<String> = vec![];
        let json = serialize_json_with_default(&vec, "[]");
        assert_eq!(json, "[]");
    }

    #[test]
    fn test_serialize_json_with_default_custom_default() {
        let vec: Vec<String> = vec!["test".to_string()];
        let json = serialize_json_with_default(&vec, "fallback");
        // Should serialize successfully, not use fallback
        assert!(json.contains("test"));
        assert!(!json.contains("fallback"));
    }

    #[test]
    fn test_serialize_json_empty_map() {
        let map: HashMap<String, String> = HashMap::new();
        let json = serialize_json(&map);
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_serialize_json_with_default_nested_structure() {
        #[derive(serde::Serialize)]
        struct Nested {
            inner: Vec<String>,
        }
        let nested = Nested {
            inner: vec!["a".to_string(), "b".to_string()],
        };
        let json = serialize_json_with_default(&nested, "{}");
        assert!(json.contains("inner"));
        assert!(json.contains("a"));
        assert!(json.contains("b"));
    }

    #[test]
    fn test_serialize_json_with_default_null_values() {
        use serde_json::json;
        let value = json!({
            "key1": "value1",
            "key2": null,
            "key3": ["item1", null, "item2"]
        });
        let json = serialize_json_with_default(&value, "{}");
        assert!(json.contains("key1"));
        assert!(json.contains("key2"));
        assert!(json.contains("null")); // null values should be serialized
    }
}
