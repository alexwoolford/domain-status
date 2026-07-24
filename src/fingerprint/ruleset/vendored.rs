//! Built-in minimal fingerprint ruleset used when remote sources fail.
//!
//! Remote GitHub refresh remains the preferred path; this fallback keeps
//! offline/CI cold starts working with a small common-tech ruleset.

use std::collections::HashMap;
use std::time::SystemTime;

use anyhow::{Context, Result};

use crate::fingerprint::models::{Category, FingerprintMetadata, FingerprintRuleset, Technology};

const VENDORED_TECHNOLOGIES_JSON: &str =
    include_str!("../../../assets/fingerprints/technologies.json");
const VENDORED_CATEGORIES_JSON: &str = include_str!("../../../assets/fingerprints/categories.json");

/// Load the compile-time vendored ruleset.
///
/// # Errors
/// Returns an error if the embedded JSON is malformed (should not happen in release).
pub(crate) fn load_vendored_ruleset() -> Result<FingerprintRuleset> {
    let technologies: HashMap<String, Technology> =
        serde_json::from_str(VENDORED_TECHNOLOGIES_JSON)
            .context("Failed to parse vendored technologies.json")?;

    let categories_map: HashMap<String, Category> = serde_json::from_str(VENDORED_CATEGORIES_JSON)
        .context("Failed to parse vendored categories.json")?;

    let mut categories = HashMap::new();
    for (id_str, category) in categories_map {
        if let Ok(id) = id_str.parse::<u32>() {
            categories.insert(id, category.name);
        }
    }

    Ok(FingerprintRuleset {
        technologies,
        categories,
        metadata: FingerprintMetadata {
            source: "vendored:assets/fingerprints".to_string(),
            version: "bundled-minimal".to_string(),
            last_updated: SystemTime::now(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendored_ruleset_parses_and_has_common_techs() {
        let ruleset = load_vendored_ruleset().expect("vendored JSON should parse");
        assert!(ruleset.technologies.contains_key("Nginx"));
        assert!(ruleset.technologies.contains_key("WordPress"));
        assert!(ruleset.technologies.contains_key("React"));
        assert!(!ruleset.categories.is_empty());
        assert_eq!(ruleset.metadata.version, "bundled-minimal");
    }
}
