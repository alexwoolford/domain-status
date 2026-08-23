//! Shared helpers for map-shaped fingerprint signals (headers, etc.).

use std::collections::HashMap;

use crate::fingerprint::models::{FingerprintRuleset, Technology};
use crate::fingerprint::patterns::matches_pattern;

/// A technology name plus optional version extracted from a signal match.
#[derive(Debug, Clone)]
pub(crate) struct SignalMatch {
    pub tech_name: String,
    pub version: Option<String>,
}

/// Match technologies whose `select` map keys exist in `values`.
///
/// Empty pattern strings mean "key presence is enough" (Wappalyzer semantics).
pub(crate) fn match_string_map_signal(
    ruleset: &FingerprintRuleset,
    values: &HashMap<String, String>,
    select: impl Fn(&Technology) -> &HashMap<String, String>,
) -> Vec<SignalMatch> {
    let mut results = Vec::new();
    for (tech_name, tech) in &ruleset.technologies {
        let patterns = select(tech);
        if patterns.is_empty() {
            continue;
        }
        let mut matched = false;
        let mut version: Option<String> = None;
        for (key, pattern) in patterns {
            let Some(value) = values.get(key) else {
                continue;
            };
            if pattern.is_empty() {
                matched = true;
                break;
            }
            let result = matches_pattern(pattern, value);
            if result.matched {
                matched = true;
                if version.is_none() && result.version.is_some() {
                    version.clone_from(&result.version);
                }
                if version.is_some() {
                    break;
                }
            }
        }
        if matched {
            results.push(SignalMatch {
                tech_name: tech_name.clone(),
                version,
            });
        }
    }
    results
}
