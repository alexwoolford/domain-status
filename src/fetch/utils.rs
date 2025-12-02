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
        log::warn!("Failed to serialize value to JSON: {}. Using default: {{}}", e);
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
        log::warn!("Failed to serialize value to JSON: {}. Using default: {}", e, default);
        default.to_string()
    })
}

