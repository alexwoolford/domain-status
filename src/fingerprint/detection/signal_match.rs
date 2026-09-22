//! Shared helpers for map-shaped fingerprint signals (headers, etc.).

use std::collections::HashMap;

use crate::fingerprint::models::{FingerprintRuleset, Technology};

use super::source::DetectionSource;

/// A technology name plus optional version extracted from a signal match.
#[derive(Debug, Clone)]
pub(crate) struct SignalMatch {
    pub tech_name: String,
    pub version: Option<String>,
    pub source: DetectionSource,
}

/// Match technologies whose `select` map keys exist in `values`.
///
/// Empty pattern strings mean "key presence is enough" (Wappalyzer semantics).
/// `skip_key` drops keys that are not serving-stack evidence (CSP allowlists).
pub(crate) fn match_string_map_signal(
    ruleset: &FingerprintRuleset,
    values: &HashMap<String, String>,
    select: impl Fn(&Technology) -> &HashMap<String, String>,
    skip_key: impl Fn(&str) -> bool,
    source: DetectionSource,
) -> Vec<SignalMatch> {
    let mut results = Vec::new();
    for (tech_name, tech) in &ruleset.technologies {
        let prepared = tech.prepared();
        let patterns = select(tech);
        if patterns.is_empty() {
            continue;
        }
        let mut matched = false;
        let mut version: Option<String> = None;
        for key in patterns.keys() {
            if skip_key(key) {
                continue;
            }
            let Some(value) = values.get(key) else {
                continue;
            };
            let Some(compiled) = prepared.headers.get(key) else {
                continue;
            };
            if compiled.presence_only() {
                matched = true;
                break;
            }
            let result = compiled.evaluate(value);
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
                source,
            });
        }
    }
    results
}
