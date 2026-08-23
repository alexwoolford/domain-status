//! Technology exclusion logic.
//!
//! After pattern matching and implies expansion, technologies listed in another
//! detected technology's `excludes` field are removed.

use std::collections::HashSet;

use crate::fingerprint::models::FingerprintRuleset;
use crate::fingerprint::patterns::parse_technology_reference;

/// Applies technology exclusions, removing technologies that are excluded by others.
///
/// `detected` must be a set of bare technology names (not `name:version` strings).
/// Version is stored separately on [`crate::fingerprint::detection::TechInfo`] and must
/// never be encoded into the name — tech names may themselves contain `:`.
///
/// A technology is excluded if any other detected technology lists it in its `excludes` field.
pub(crate) fn apply_technology_exclusions(
    detected: &HashSet<String>,
    ruleset: &FingerprintRuleset,
) -> HashSet<String> {
    let mut final_detected = HashSet::new();
    for tech_name in detected {
        let is_excluded = detected.iter().any(|other_tech_name| {
            if other_tech_name == tech_name {
                return false;
            }
            ruleset
                .technologies
                .get(other_tech_name.as_str())
                .is_some_and(|other_tech| {
                    other_tech.excludes.iter().any(|excluded| {
                        let (excluded_name, _) = parse_technology_reference(excluded);
                        excluded_name == *tech_name
                    })
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
        Technology::default()
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
    fn test_colon_in_tech_name_is_not_treated_as_version_separator() {
        // Names like Re:amaze must stay intact; exclusions key on bare names only.
        let mut ruleset = FingerprintRuleset {
            technologies: HashMap::new(),
            categories: HashMap::new(),
            metadata: create_test_metadata(),
        };
        let mut tech_a = create_empty_technology();
        tech_a.excludes.push("Re:amaze".to_string());
        ruleset.technologies.insert("TechA".to_string(), tech_a);
        ruleset
            .technologies
            .insert("Re:amaze".to_string(), create_empty_technology());

        let mut detected = HashSet::new();
        detected.insert("TechA".to_string());
        detected.insert("Re:amaze".to_string());

        let result = apply_technology_exclusions(&detected, &ruleset);
        assert!(result.contains("TechA"));
        assert!(
            !result.contains("Re:amaze"),
            "exclusion must match full name including colon"
        );
    }
}
