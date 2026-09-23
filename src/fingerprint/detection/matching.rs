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

/// Drops detections whose Wappalyzer `requires` / `requiresCategory` are unmet.
///
/// Iterates to a fixed point so a dropped parent can cause children to drop.
pub(crate) fn apply_technology_requires(
    detected: &HashSet<String>,
    ruleset: &FingerprintRuleset,
) -> HashSet<String> {
    const MAX_REQUIRES_DEPTH: u32 = 10;
    let mut remaining = detected.clone();
    for _ in 0..MAX_REQUIRES_DEPTH {
        let mut next = HashSet::new();
        let mut dropped_any = false;
        for name in &remaining {
            if technology_requires_satisfied(name, &remaining, ruleset) {
                next.insert(name.clone());
            } else {
                dropped_any = true;
            }
        }
        remaining = next;
        if !dropped_any {
            break;
        }
    }
    remaining
}

fn technology_requires_satisfied(
    name: &str,
    detected: &HashSet<String>,
    ruleset: &FingerprintRuleset,
) -> bool {
    let Some(tech) = ruleset.technologies.get(name) else {
        return true;
    };
    for req in &tech.requires {
        let (req_name, _) = parse_technology_reference(req);
        if !detected.contains(&req_name) {
            return false;
        }
    }
    if tech.requires_category.is_empty() {
        return true;
    }
    detected.iter().any(|other| {
        if other == name {
            return false;
        }
        ruleset.technologies.get(other).is_some_and(|other_tech| {
            other_tech
                .cats
                .iter()
                .any(|cat| tech.requires_category.contains(cat))
        })
    })
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
            literals: std::sync::OnceLock::new(),
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
            literals: std::sync::OnceLock::new(),
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
            literals: std::sync::OnceLock::new(),
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
            literals: std::sync::OnceLock::new(),
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
            literals: std::sync::OnceLock::new(),
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
            literals: std::sync::OnceLock::new(),
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
            literals: std::sync::OnceLock::new(),
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

    #[test]
    fn test_requires_drops_plugin_without_parent() {
        let mut ruleset = FingerprintRuleset {
            literals: std::sync::OnceLock::new(),
            technologies: HashMap::new(),
            categories: HashMap::new(),
            metadata: create_test_metadata(),
        };
        let mut plugin = create_empty_technology();
        plugin.requires.push("WordPress".to_string());
        ruleset
            .technologies
            .insert("Gravity Forms".to_string(), plugin);
        ruleset
            .technologies
            .insert("WordPress".to_string(), create_empty_technology());

        let mut detected = HashSet::new();
        detected.insert("Gravity Forms".to_string());
        let result = apply_technology_requires(&detected, &ruleset);
        assert!(result.is_empty());

        detected.insert("WordPress".to_string());
        let result = apply_technology_requires(&detected, &ruleset);
        assert!(result.contains("Gravity Forms"));
        assert!(result.contains("WordPress"));
    }

    #[test]
    fn test_requires_category_needs_another_tech_in_category() {
        let mut ruleset = FingerprintRuleset {
            literals: std::sync::OnceLock::new(),
            technologies: HashMap::new(),
            categories: HashMap::from([(1, "CMS".to_string())]),
            metadata: create_test_metadata(),
        };
        let mut plugin = create_empty_technology();
        plugin.requires_category.push(1);
        ruleset
            .technologies
            .insert("Some Plugin".to_string(), plugin);
        let mut cms = create_empty_technology();
        cms.cats.push(1);
        ruleset.technologies.insert("WordPress".to_string(), cms);

        let mut only_plugin = HashSet::new();
        only_plugin.insert("Some Plugin".to_string());
        assert!(apply_technology_requires(&only_plugin, &ruleset).is_empty());

        only_plugin.insert("WordPress".to_string());
        let kept = apply_technology_requires(&only_plugin, &ruleset);
        assert!(kept.contains("Some Plugin"));
        assert!(kept.contains("WordPress"));
    }
}
