//! Patterns compiled once when a ruleset is finished.
//!
//! Matching then skips `parse_pattern`, `regex::escape`, and the process-wide
//! regex cache. Empty patterns, confidence below the minimum, invalid regexes,
//! and version capture keep the same results as [`super::matches_pattern`].

use std::collections::HashMap;

use crate::fingerprint::models::Technology;

use super::version::extract_version_from_template;
use super::{
    handle_empty_pattern, is_regex_pattern, parse_pattern, PatternMatchResult,
    MIN_PATTERN_CONFIDENCE,
};

/// One Wappalyzer pattern, parsed and compiled.
#[derive(Debug, Clone)]
pub(crate) enum CompiledPattern {
    /// Empty match text. `presence_only` is the raw `""` pattern, which stops
    /// header and cookie search before a later pattern can supply a version.
    Any {
        version_template: Option<String>,
        presence_only: bool,
    },
    /// `(?i)` regex, including escaped literals.
    Regex {
        regex: regex::Regex,
        version_template: Option<String>,
    },
}

impl CompiledPattern {
    /// Raw empty pattern: key presence is enough, and search stops.
    #[must_use]
    pub(crate) fn presence_only(&self) -> bool {
        matches!(
            self,
            Self::Any {
                presence_only: true,
                ..
            }
        )
    }

    /// Match `text` the same way [`super::matches_pattern`] would.
    #[must_use]
    pub(crate) fn evaluate(&self, text: &str) -> PatternMatchResult {
        match self {
            Self::Any {
                version_template, ..
            } => handle_empty_pattern(version_template.as_deref()),
            Self::Regex {
                regex,
                version_template,
            } => evaluate_regex(regex, version_template.as_deref(), text),
        }
    }
}

fn evaluate_regex(
    regex: &regex::Regex,
    version_template: Option<&str>,
    text: &str,
) -> PatternMatchResult {
    let Some(template) = version_template else {
        return PatternMatchResult {
            matched: regex.is_match(text),
            version: None,
        };
    };
    if let Some(captures) = regex.captures(text) {
        PatternMatchResult {
            matched: true,
            version: extract_version_from_template(&format!("version:{template}"), &captures),
        }
    } else {
        PatternMatchResult {
            matched: false,
            version: None,
        }
    }
}

/// Every signal on one technology, compiled.
#[derive(Debug, Clone)]
pub(crate) struct PreparedSignals {
    pub(crate) meta: HashMap<String, Vec<CompiledPattern>>,
    pub(crate) headers: HashMap<String, CompiledPattern>,
    pub(crate) cookies: HashMap<String, CompiledPattern>,
    pub(crate) dns: HashMap<String, Vec<CompiledPattern>>,
    pub(crate) cert_issuer: Vec<CompiledPattern>,
}

impl PreparedSignals {
    fn from_technology(tech: &Technology) -> Self {
        Self {
            meta: compile_list_map(&tech.meta),
            headers: compile_map(&tech.headers),
            cookies: compile_map(&tech.cookies),
            dns: compile_list_map(&tech.dns),
            cert_issuer: compile_list(&tech.cert_issuer),
        }
    }
}

impl Technology {
    /// Compiled patterns for this technology.
    ///
    /// The first call compiles them. [`crate::fingerprint::ruleset`] does that
    /// when a ruleset is finished, so a scan does not pay it per URL.
    #[must_use]
    pub(crate) fn prepared(&self) -> &PreparedSignals {
        if let Some(ready) = self.prepared.get() {
            return ready;
        }
        let compiled = PreparedSignals::from_technology(self);
        let _ = self.prepared.set(compiled);
        self.prepared
            .get()
            .unwrap_or_else(|| unreachable!("prepared signals stored before read"))
    }
}

/// `None` drops a pattern that can never match (low confidence or invalid regex).
pub(super) fn compile_pattern(pattern: &str) -> Option<CompiledPattern> {
    if pattern.is_empty() {
        return Some(CompiledPattern::Any {
            version_template: None,
            presence_only: true,
        });
    }

    let parsed = parse_pattern(pattern);
    if parsed.confidence < MIN_PATTERN_CONFIDENCE {
        return None;
    }
    if parsed.pattern_for_match.is_empty() {
        return Some(CompiledPattern::Any {
            version_template: parsed.version_template,
            presence_only: false,
        });
    }

    let (source, version_template) = if is_regex_pattern(&parsed.pattern_for_match) {
        (parsed.pattern_for_match, parsed.version_template)
    } else {
        (regex::escape(&parsed.pattern_for_match), None)
    };
    let regex = regex::Regex::new(&format!("(?i){source}")).ok()?;
    Some(CompiledPattern::Regex {
        regex,
        version_template,
    })
}

fn compile_list(patterns: &[String]) -> Vec<CompiledPattern> {
    patterns
        .iter()
        .filter_map(|pattern| compile_pattern(pattern))
        .collect()
}

fn compile_map(patterns: &HashMap<String, String>) -> HashMap<String, CompiledPattern> {
    patterns
        .iter()
        .filter_map(|(key, pattern)| {
            compile_pattern(pattern).map(|compiled| (key.clone(), compiled))
        })
        .collect()
}

fn compile_list_map(
    patterns: &HashMap<String, Vec<String>>,
) -> HashMap<String, Vec<CompiledPattern>> {
    patterns
        .iter()
        .map(|(key, values)| (key.clone(), compile_list(values)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::compile_pattern;
    use crate::fingerprint::patterns::matches_pattern;

    #[test]
    fn compiled_pattern_matches_matches_pattern() {
        let cases = [
            ("nginx", "nginx/1.18.0"),
            ("WordPress", "Powered by WordPress"),
            ("apache", "nginx/1.18.0"),
            ("^nginx", "nginx/1.18.0"),
            ("^nginx", "server: nginx/1.18.0"),
            ("", "anything"),
            (r"jquery\;confidence:49", "jquery.min.js"),
            (r"jquery\;confidence:50", "jquery.min.js"),
            (r"nginx/(\d+\.\d+)\;version:\1", "nginx/1.18.0"),
            (r"\;version:ga4", "anything"),
            ("[unclosed", "text with [unclosed bracket"),
            ("test{invalid", "text with test{invalid"),
        ];
        for (pattern, text) in cases {
            let direct = matches_pattern(pattern, text);
            let via = compile_pattern(pattern).map(|compiled| compiled.evaluate(text));
            let matched = via.as_ref().is_some_and(|result| result.matched);
            let version = via.and_then(|result| result.version);
            assert_eq!(direct.matched, matched, "{pattern} against {text}");
            assert_eq!(direct.version, version, "{pattern} against {text}");
        }
    }
}
