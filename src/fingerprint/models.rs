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

