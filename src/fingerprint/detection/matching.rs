//! Technology exclusion logic.
//!
//! After pattern matching and implies expansion, technologies listed in another
//! detected technology's `excludes` field are removed.

use std::collections::HashSet;

use crate::fingerprint::models::FingerprintRuleset;

/// Extracts base technology name from formatted name (strips version if present).
/// `"jQuery:3.6.0"` -> `"jQuery"`, `"WordPress"` -> `"WordPress"`
fn extract_base_tech_name(formatted_name: &str) -> &str {
    if let Some(colon_pos) = formatted_name.find(':') {
        &formatted_name[..colon_pos]
    } else {
        formatted_name
    }
}

/// Applies technology exclusions, removing technologies that are excluded by others.
///
/// A technology is excluded if any other detected technology lists it in its `excludes` field.
/// For example, if `TechA` excludes `TechB`, and both are detected, `TechB` will be removed.
pub(crate) fn apply_technology_exclusions(
    detected: &HashSet<String>,
    ruleset: &FingerprintRuleset,
) -> HashSet<String> {
    let mut final_detected = HashSet::new();
    for tech_name in detected {
        let base_tech_name = extract_base_tech_name(tech_name);

        // Check if this technology is excluded by any other detected technology
        let is_excluded = detected.iter().any(|other_tech_name| {
            if other_tech_name == tech_name {
                return false; // A technology doesn't exclude itself
            }
            let other_base_name = extract_base_tech_name(other_tech_name);

            // Check if the other technology excludes this one
            ruleset
                .technologies
                .get(other_base_name)
                .is_some_and(|other_tech| {
                    other_tech
                        .excludes
                        .iter()
                        .any(|excluded| excluded == base_tech_name)
                })
        });

        if !is_excluded {
            final_detected.insert(tech_name.clone());
        }
    }
    final_detected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::models::Technology;
    use std::collections::HashMap;

    fn create_empty_technology() -> Technology {
        Technology {
            cats: vec![],
            website: String::new(),
            headers: HashMap::new(),
            cookies: HashMap::new(),
            meta: HashMap::new(),
            script: vec![],
            html: vec![],
            url: vec![],
            js: HashMap::new(),
            implies: vec![],
            excludes: vec![],
        }
    }

    fn create_test_metadata() -> crate::fingerprint::models::FingerprintMetadata {
        crate::fingerprint::models::FingerprintMetadata {
            source: "test".to_string(),
            version: "test".to_string(),
            last_updated: std::time::SystemTime::now(),
        }
    }

    #[test]
    fn test_apply_technology_exclusions_no_exclusions() {
        let ruleset = FingerprintRuleset {
            technologies: HashMap::new(),
            categories: HashMap::new(),
            metadata: create_test_metadata(),
        };

        let mut detected = HashSet::new();
        detected.insert("WordPress".to_string());
        detected.insert("PHP".to_string());

        let result = apply_technology_exclusions(&detected, &ruleset);
        assert_eq!(result.len(), 2);
        assert!(result.contains("WordPress"));
        assert!(result.contains("PHP"));
    }

    #[test]
    fn test_apply_technology_exclusions_with_exclusion() {
        let mut ruleset = FingerprintRuleset {
            technologies: HashMap::new(),
            categories: HashMap::new(),
            metadata: create_test_metadata(),
        };

        let mut tech_a = create_empty_technology();
        tech_a.excludes.push("TechB".to_string());
        ruleset.technologies.insert("TechA".to_string(), tech_a);

        let mut detected = HashSet::new();
        detected.insert("TechA".to_string());
        detected.insert("TechB".to_string());

        let result = apply_technology_exclusions(&detected, &ruleset);
        assert_eq!(result.len(), 1);
        assert!(result.contains("TechA"));
        assert!(!result.contains("TechB"));
    }

    #[test]
    fn test_apply_technology_exclusions_multiple_exclusions() {
        let mut ruleset = FingerprintRuleset {
            technologies: HashMap::new(),
            categories: HashMap::new(),
            metadata: create_test_metadata(),
        };

        let mut tech_a = create_empty_technology();
        tech_a.excludes.push("TechB".to_string());
        tech_a.excludes.push("TechC".to_string());
        ruleset.technologies.insert("TechA".to_string(), tech_a);

        let mut detected = HashSet::new();
        detected.insert("TechA".to_string());
        detected.insert("TechB".to_string());
        detected.insert("TechC".to_string());
        detected.insert("TechD".to_string());

        let result = apply_technology_exclusions(&detected, &ruleset);
        assert_eq!(result.len(), 2);
        assert!(result.contains("TechA"));
        assert!(result.contains("TechD"));
        assert!(!result.contains("TechB"));
        assert!(!result.contains("TechC"));
    }

    #[test]
    fn test_apply_technology_exclusions_exclusion_not_detected() {
        let mut ruleset = FingerprintRuleset {
            technologies: HashMap::new(),
            categories: HashMap::new(),
            metadata: create_test_metadata(),
        };

        let mut tech_a = create_empty_technology();
        tech_a.excludes.push("TechB".to_string());
        ruleset.technologies.insert("TechA".to_string(), tech_a);

        let mut detected = HashSet::new();
        detected.insert("TechA".to_string());

        let result = apply_technology_exclusions(&detected, &ruleset);
        assert_eq!(result.len(), 1);
        assert!(result.contains("TechA"));
    }

    #[test]
    fn test_apply_technology_exclusions_unknown_technology() {
        let ruleset = FingerprintRuleset {
            technologies: HashMap::new(),
            categories: HashMap::new(),
            metadata: create_test_metadata(),
        };

        let mut detected = HashSet::new();
        detected.insert("UnknownTech".to_string());

        let result = apply_technology_exclusions(&detected, &ruleset);
        assert_eq!(result.len(), 1);
        assert!(result.contains("UnknownTech"));
    }

    #[test]
    fn test_apply_technology_exclusions_missing_technology_in_ruleset() {
        let mut ruleset = FingerprintRuleset {
            technologies: HashMap::new(),
            categories: HashMap::new(),
            metadata: create_test_metadata(),
        };

        let mut tech_a = create_empty_technology();
        tech_a.excludes.push("TechB".to_string());
        ruleset.technologies.insert("TechA".to_string(), tech_a);

        let mut detected = HashSet::new();
        detected.insert("TechA".to_string());
        detected.insert("TechB".to_string());

        let result = apply_technology_exclusions(&detected, &ruleset);
        assert!(result.contains("TechA"));
        assert!(!result.contains("TechB"));
    }

    #[test]
    fn test_extract_base_tech_name_with_version() {
        assert_eq!(extract_base_tech_name("jQuery:3.6.0"), "jQuery");
        assert_eq!(extract_base_tech_name("WordPress"), "WordPress");
    }
}
