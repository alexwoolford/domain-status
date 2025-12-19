//! Data structures for fingerprint rulesets.
//!
//! This module contains the core data structures used for technology detection:
//! - `Technology`: A single technology fingerprint rule
//! - `FingerprintMetadata`: Metadata about a ruleset (source, version, timestamp)
//! - `FingerprintRuleset`: Container for all technologies and categories
//! - `Category`: Category information from categories.json

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

/// Technology fingerprint rule structure matching Wappalyzer schema
/// Note: The technology name is the key in the JSON, not a field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technology {
    /// Category IDs
    #[serde(default)]
    pub cats: Vec<u32>,
    /// Website URL
    #[serde(default)]
    pub website: String,
    /// Header patterns: header_name -> pattern
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Cookie patterns: cookie_name -> pattern
    #[serde(default)]
    pub cookies: HashMap<String, String>,
    /// Meta tag patterns: meta_name -> pattern(s)
    /// In Wappalyzer, meta values can be either a string or an array of strings
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_meta_map")]
    pub meta: HashMap<String, Vec<String>>,
    /// Script source patterns (can be string or array) - Wappalyzer uses "scriptSrc"
    #[serde(default)]
    #[serde(alias = "scriptSrc")]
    #[serde(deserialize_with = "deserialize_string_or_array")]
    pub script: Vec<String>,
    /// HTML text patterns (can be string or array)
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_string_or_array")]
    pub html: Vec<String>,
    /// URL patterns (can be string or array)
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_string_or_array")]
    pub url: Vec<String>,
    /// JavaScript object properties to check
    #[serde(default)]
    pub js: HashMap<String, String>,
    /// Implies other technologies (can be string or array)
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_string_or_array")]
    pub implies: Vec<String>,
    /// Excludes other technologies (can be string or array)
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_string_or_array")]
    pub excludes: Vec<String>,
}

/// Deserializes a field that can be either a string or an array of strings
fn deserialize_string_or_array<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct StringOrArrayVisitor;

    impl<'de> Visitor<'de> for StringOrArrayVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string or an array of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(vec![value.to_string()])
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(vec![value])
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            while let Some(elem) = seq.next_element::<String>()? {
                vec.push(elem);
            }
            Ok(vec)
        }
    }

    deserializer.deserialize_any(StringOrArrayVisitor)
}

/// Deserializes a meta map where values can be either strings or arrays of strings
/// This matches the Go implementation which uses reflection to handle both cases
fn deserialize_meta_map<'de, D>(deserializer: D) -> Result<HashMap<String, Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, MapAccess, Visitor};
    use std::fmt;

    struct MetaMapVisitor;

    impl<'de> Visitor<'de> for MetaMapVisitor {
        type Value = HashMap<String, Vec<String>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a map of string to string or array of strings")
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut result = HashMap::new();
            while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                let patterns = match value {
                    serde_json::Value::String(s) => vec![s],
                    serde_json::Value::Array(arr) => arr
                        .into_iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect(),
                    _ => {
                        return Err(de::Error::invalid_type(
                            de::Unexpected::Other("expected string or array"),
                            &self,
                        ));
                    }
                };
                result.insert(key, patterns);
            }
            Ok(result)
        }
    }

    deserializer.deserialize_map(MetaMapVisitor)
}

/// Fingerprint ruleset metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintMetadata {
    /// Source URL or path
    pub source: String,
    /// Version/commit identifier
    pub version: String,
    /// Last update timestamp
    pub last_updated: SystemTime,
}

/// Category information from categories.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Category {
    pub(crate) name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    priority: u32,
}

/// Fingerprint ruleset container
#[derive(Debug, Clone)]
pub struct FingerprintRuleset {
    /// Technologies indexed by name
    pub technologies: HashMap<String, Technology>,
    /// Categories indexed by ID (u32) -> name
    pub categories: HashMap<u32, String>,
    /// Metadata about the ruleset
    pub metadata: FingerprintMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test deserializing a technology with string fields (single values)
    #[test]
    fn test_technology_deserialize_string_fields() {
        let json = r#"{
            "cats": [1, 2],
            "website": "https://example.com",
            "html": "pattern1",
            "script": "jquery.js",
            "implies": "PHP"
        }"#;

        let tech: Technology = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(tech.cats, vec![1, 2]);
        assert_eq!(tech.website, "https://example.com");
        assert_eq!(tech.html, vec!["pattern1"]);
        assert_eq!(tech.script, vec!["jquery.js"]);
        assert_eq!(tech.implies, vec!["PHP"]);
    }

    /// Test deserializing a technology with array fields (multiple values)
    #[test]
    fn test_technology_deserialize_array_fields() {
        let json = r#"{
            "cats": [1],
            "html": ["pattern1", "pattern2"],
            "script": ["jquery.js", "bootstrap.js"],
            "implies": ["PHP", "MySQL"]
        }"#;

        let tech: Technology = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(tech.html, vec!["pattern1", "pattern2"]);
        assert_eq!(tech.script, vec!["jquery.js", "bootstrap.js"]);
        assert_eq!(tech.implies, vec!["PHP", "MySQL"]);
    }

    /// Test deserializing meta tags with string values
    #[test]
    fn test_technology_deserialize_meta_string() {
        let json = r#"{
            "meta": {
                "generator": "WordPress"
            }
        }"#;

        let tech: Technology = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(
            tech.meta.get("generator"),
            Some(&vec!["WordPress".to_string()])
        );
    }

    /// Test deserializing meta tags with array values
    #[test]
    fn test_technology_deserialize_meta_array() {
        let json = r#"{
            "meta": {
                "generator": ["WordPress", "Drupal"]
            }
        }"#;

        let tech: Technology = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(
            tech.meta.get("generator"),
            Some(&vec!["WordPress".to_string(), "Drupal".to_string()])
        );
    }

    /// Test deserializing headers map
    #[test]
    fn test_technology_deserialize_headers() {
        let json = r#"{
            "headers": {
                "Server": "Apache",
                "X-Powered-By": "PHP"
            }
        }"#;

        let tech: Technology = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(tech.headers.get("Server"), Some(&"Apache".to_string()));
        assert_eq!(tech.headers.get("X-Powered-By"), Some(&"PHP".to_string()));
    }

    /// Test deserializing cookies map
    #[test]
    fn test_technology_deserialize_cookies() {
        let json = r#"{
            "cookies": {
                "PHPSESSID": "",
                "laravel_session": "^eyJ"
            }
        }"#;

        let tech: Technology = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(tech.cookies.get("PHPSESSID"), Some(&"".to_string()));
        assert_eq!(
            tech.cookies.get("laravel_session"),
            Some(&"^eyJ".to_string())
        );
    }

    /// Test deserializing scriptSrc alias
    #[test]
    fn test_technology_deserialize_script_src_alias() {
        let json = r#"{
            "scriptSrc": ["jquery.min.js", "bootstrap.bundle.js"]
        }"#;

        let tech: Technology = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(tech.script, vec!["jquery.min.js", "bootstrap.bundle.js"]);
    }

    /// Test deserializing empty/default fields
    #[test]
    fn test_technology_deserialize_defaults() {
        let json = r#"{}"#;

        let tech: Technology = serde_json::from_str(json).expect("Failed to deserialize");
        assert!(tech.cats.is_empty());
        assert!(tech.website.is_empty());
        assert!(tech.headers.is_empty());
        assert!(tech.cookies.is_empty());
        assert!(tech.meta.is_empty());
        assert!(tech.script.is_empty());
        assert!(tech.html.is_empty());
        assert!(tech.url.is_empty());
        assert!(tech.js.is_empty());
        assert!(tech.implies.is_empty());
        assert!(tech.excludes.is_empty());
    }

    /// Test deserializing a complete technology (real-world example)
    #[test]
    fn test_technology_deserialize_complete() {
        let json = r#"{
            "cats": [1, 11],
            "website": "https://wordpress.org",
            "headers": {
                "X-Powered-By": "WordPress"
            },
            "cookies": {
                "wp-settings-": ""
            },
            "meta": {
                "generator": "^WordPress\\s+([\\d.]+)?\\;version:\\1"
            },
            "html": [
                "<link[^>]+/wp-(?:content|includes)/",
                "data-flavor=\"developer\""
            ],
            "scriptSrc": "wp-(?:content|includes)/",
            "implies": ["PHP", "MySQL"]
        }"#;

        let tech: Technology = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(tech.cats, vec![1, 11]);
        assert_eq!(tech.website, "https://wordpress.org");
        assert_eq!(tech.headers.len(), 1);
        assert_eq!(tech.cookies.len(), 1);
        assert_eq!(tech.meta.len(), 1);
        assert_eq!(tech.html.len(), 2);
        assert_eq!(tech.script.len(), 1);
        assert_eq!(tech.implies, vec!["PHP", "MySQL"]);
    }

    /// Test Category deserialization
    #[test]
    fn test_category_deserialize() {
        let json = r#"{
            "name": "CMS",
            "description": "Content Management System",
            "priority": 10
        }"#;

        let cat: Category = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(cat.name, "CMS");
    }

    /// Test Category deserialization with defaults
    #[test]
    fn test_category_deserialize_defaults() {
        let json = r#"{"name": "CMS"}"#;

        let cat: Category = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(cat.name, "CMS");
        // description and priority should use defaults
    }

    /// Test FingerprintMetadata serialization roundtrip
    #[test]
    fn test_fingerprint_metadata_roundtrip() {
        let metadata = FingerprintMetadata {
            source: "https://example.com/rules".to_string(),
            version: "1.0.0".to_string(),
            last_updated: SystemTime::now(),
        };

        let json = serde_json::to_string(&metadata).expect("Failed to serialize");
        let deserialized: FingerprintMetadata =
            serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(deserialized.source, metadata.source);
        assert_eq!(deserialized.version, metadata.version);
    }

    /// Test mixed meta types in same object
    #[test]
    fn test_technology_deserialize_mixed_meta() {
        let json = r#"{
            "meta": {
                "generator": "WordPress",
                "author": ["John", "Jane"],
                "keywords": "single keyword"
            }
        }"#;

        let tech: Technology = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(
            tech.meta.get("generator"),
            Some(&vec!["WordPress".to_string()])
        );
        assert_eq!(
            tech.meta.get("author"),
            Some(&vec!["John".to_string(), "Jane".to_string()])
        );
        assert_eq!(
            tech.meta.get("keywords"),
            Some(&vec!["single keyword".to_string()])
        );
    }

    /// Test URL patterns
    #[test]
    fn test_technology_deserialize_url_patterns() {
        let json = r#"{
            "url": ["^https?://[^/]+/wp-admin/", "\\.aspx$"]
        }"#;

        let tech: Technology = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(tech.url.len(), 2);
        assert!(tech.url[0].contains("wp-admin"));
        assert!(tech.url[1].contains("aspx"));
    }

    /// Test JS patterns
    #[test]
    fn test_technology_deserialize_js_patterns() {
        let json = r#"{
            "js": {
                "jQuery": "",
                "jQuery.fn.jquery": "\\;version:\\1"
            }
        }"#;

        let tech: Technology = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(tech.js.len(), 2);
        assert_eq!(tech.js.get("jQuery"), Some(&"".to_string()));
    }

    /// Test excludes field
    #[test]
    fn test_technology_deserialize_excludes() {
        let json = r#"{
            "excludes": ["WordPress", "Drupal"]
        }"#;

        let tech: Technology = serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(tech.excludes, vec!["WordPress", "Drupal"]);
    }

    /// Test error handling for invalid JSON
    #[test]
    fn test_technology_deserialize_invalid_json() {
        let invalid_json = r#"{
            "cats": [1, 2],
            "html": "pattern1",
            "invalid_field": {
                "nested": "invalid"
            }
        }"#;

        // Invalid JSON should fail to deserialize
        let result: Result<Technology, _> = serde_json::from_str(invalid_json);
        // This should succeed because serde ignores unknown fields by default
        // But we verify the deserialization works correctly
        assert!(result.is_ok(), "Should handle invalid fields gracefully");
    }

    /// Test error handling for wrong type in array field
    #[test]
    fn test_technology_deserialize_wrong_type_in_array() {
        let json = r#"{
            "html": [123, "pattern2"]
        }"#;

        // This should fail because html expects strings, not numbers
        let result: Result<Technology, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "Should fail when array contains non-string values"
        );
    }

    /// Test error handling for wrong type in meta map
    #[test]
    fn test_technology_deserialize_wrong_type_in_meta() {
        let json = r#"{
            "meta": {
                "generator": 123
            }
        }"#;

        // This should fail because meta values must be strings or arrays of strings
        let result: Result<Technology, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "Should fail when meta value is not string or array"
        );
    }

    /// Test error handling for malformed meta array
    #[test]
    fn test_technology_deserialize_malformed_meta_array() {
        let json = r#"{
            "meta": {
                "generator": [123, "WordPress"]
            }
        }"#;

        // The deserializer filters out non-string values, so this succeeds
        // but only "WordPress" is included (123 is filtered out)
        let result: Result<Technology, _> = serde_json::from_str(json);
        assert!(
            result.is_ok(),
            "Should handle non-string values by filtering them out"
        );
        let tech = result.unwrap();
        assert_eq!(
            tech.meta.get("generator"),
            Some(&vec!["WordPress".to_string()]),
            "Should only include string values"
        );
    }

    /// Test error handling for invalid category JSON
    #[test]
    fn test_category_deserialize_invalid_json() {
        let invalid_json = r#"{
            "name": 123
        }"#;

        // This should fail because name must be a string
        let result: Result<Category, _> = serde_json::from_str(invalid_json);
        assert!(
            result.is_err(),
            "Should fail when category name is not a string"
        );
    }

    /// Test error handling for missing required field in category
    #[test]
    fn test_category_deserialize_missing_name() {
        let json = r#"{
            "description": "Test"
        }"#;

        // This should fail because name is required (no default)
        let result: Result<Category, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Should fail when category name is missing");
    }
}
