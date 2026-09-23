//! One automaton per body channel for patterns that are literal needles.
//!
//! Escaped punctuation such as `\.` is a needle, not a regex. Real regexes still
//! run in pattern order. A mandatory literal prefix skips a regex that cannot match.

use std::collections::HashMap;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

use crate::fingerprint::models::{FingerprintRuleset, Technology};

use super::compiled::compile_pattern;
use super::{
    handle_empty_pattern, is_regex_pattern, parse_pattern, CompiledPattern, PatternMatchResult,
    MIN_PATTERN_CONFIDENCE,
};

const MIN_PREFIX_LEN: usize = 4;

/// Which literal needles occurred in one haystack.
#[derive(Debug, Clone)]
pub(crate) struct HitSet {
    bits: Vec<u64>,
}

impl HitSet {
    fn empty() -> Self {
        Self { bits: Vec::new() }
    }

    fn contains(&self, id: u32) -> bool {
        let index = usize::try_from(id).unwrap_or(usize::MAX);
        let word = index / 64;
        let bit = index % 64;
        self.bits
            .get(word)
            .is_some_and(|slot| slot & (1_u64 << bit) != 0)
    }
}

fn set_bit(bits: &mut [u64], id: u32) {
    let index = usize::try_from(id).unwrap_or(usize::MAX);
    let word = index / 64;
    let bit = index % 64;
    if let Some(slot) = bits.get_mut(word) {
        *slot |= 1_u64 << bit;
    }
}

#[derive(Debug, Clone)]
enum BodyStep {
    Any {
        version_template: Option<String>,
    },
    Literal {
        needle_id: u32,
    },
    Regex {
        pattern: CompiledPattern,
        prefix_id: Option<u32>,
    },
}

#[derive(Debug, Clone, Default)]
struct TechBodyPlan {
    html: Vec<BodyStep>,
    script: Vec<BodyStep>,
    scripts: Vec<BodyStep>,
    url: Vec<BodyStep>,
}

#[derive(Debug, Clone)]
struct Channel {
    automaton: Option<AhoCorasick>,
    needles: Vec<String>,
}

impl Channel {
    fn empty() -> Self {
        Self {
            automaton: None,
            needles: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
struct Interner {
    to_id: HashMap<String, u32>,
    needles: Vec<String>,
}

impl Interner {
    fn intern(&mut self, needle: &str) -> Option<u32> {
        if let Some(id) = self.to_id.get(needle) {
            return Some(*id);
        }
        let id = u32::try_from(self.needles.len()).ok()?;
        self.needles.push(needle.to_string());
        self.to_id.insert(needle.to_string(), id);
        Some(id)
    }

    fn finish(self) -> Channel {
        if self.needles.is_empty() {
            return Channel::empty();
        }
        let automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(&self.needles)
            .expect("literal automaton builds from plain strings");
        Channel {
            automaton: Some(automaton),
            needles: self.needles,
        }
    }
}

/// Literal automata and per-technology steps for the four body channels.
#[derive(Debug, Clone)]
pub(crate) struct LiteralIndex {
    html: Channel,
    script: Channel,
    scripts: Channel,
    url: Channel,
    plans: HashMap<String, TechBodyPlan>,
}

impl LiteralIndex {
    fn build(technologies: &HashMap<String, Technology>) -> Self {
        let mut html_needles = Interner::default();
        let mut script_needles = Interner::default();
        let mut scripts_needles = Interner::default();
        let mut url_needles = Interner::default();
        let mut plans = HashMap::with_capacity(technologies.len());
        for (name, tech) in technologies {
            plans.insert(
                name.clone(),
                TechBodyPlan {
                    html: compile_steps(&tech.html, &mut html_needles),
                    script: compile_steps(&tech.script, &mut script_needles),
                    scripts: compile_steps(&tech.scripts, &mut scripts_needles),
                    url: compile_steps(&tech.url, &mut url_needles),
                },
            );
        }
        Self {
            html: html_needles.finish(),
            script: script_needles.finish(),
            scripts: scripts_needles.finish(),
            url: url_needles.finish(),
            plans,
        }
    }

    pub(crate) fn scan_html(&self, text: &str) -> HitSet {
        scan_channel(&self.html, text)
    }

    pub(crate) fn scan_script(&self, text: &str) -> HitSet {
        scan_channel(&self.script, text)
    }

    pub(crate) fn scan_scripts(&self, text: &str) -> HitSet {
        scan_channel(&self.scripts, text)
    }

    pub(crate) fn scan_url(&self, text: &str) -> HitSet {
        scan_channel(&self.url, text)
    }

    pub(crate) fn match_html(
        &self,
        tech: &str,
        hits: &HitSet,
        text: &str,
        matched: &mut bool,
        version: &mut Option<String>,
    ) -> bool {
        self.match_channel(tech, ChannelKind::Html, hits, text, matched, version)
    }

    pub(crate) fn match_script(
        &self,
        tech: &str,
        hits: &HitSet,
        text: &str,
        matched: &mut bool,
        version: &mut Option<String>,
    ) -> bool {
        self.match_channel(tech, ChannelKind::Script, hits, text, matched, version)
    }

    pub(crate) fn match_scripts(
        &self,
        tech: &str,
        hits: &HitSet,
        text: &str,
        matched: &mut bool,
        version: &mut Option<String>,
    ) -> bool {
        self.match_channel(tech, ChannelKind::Scripts, hits, text, matched, version)
    }

    pub(crate) fn match_url(
        &self,
        tech: &str,
        hits: &HitSet,
        text: &str,
        matched: &mut bool,
        version: &mut Option<String>,
    ) -> bool {
        self.match_channel(tech, ChannelKind::Url, hits, text, matched, version)
    }

    fn match_channel(
        &self,
        tech: &str,
        kind: ChannelKind,
        hits: &HitSet,
        text: &str,
        matched: &mut bool,
        version: &mut Option<String>,
    ) -> bool {
        let Some(plan) = self.plans.get(tech) else {
            return false;
        };
        let steps = match kind {
            ChannelKind::Html => plan.html.as_slice(),
            ChannelKind::Script => plan.script.as_slice(),
            ChannelKind::Scripts => plan.scripts.as_slice(),
            ChannelKind::Url => plan.url.as_slice(),
        };
        apply_steps(steps, hits, text, matched, version)
    }
}

#[derive(Clone, Copy)]
enum ChannelKind {
    Html,
    Script,
    Scripts,
    Url,
}

impl FingerprintRuleset {
    /// Literal index for this ruleset. The first call builds it.
    #[must_use]
    pub(crate) fn literals(&self) -> &LiteralIndex {
        if let Some(ready) = self.literals.get() {
            return ready;
        }
        let built = LiteralIndex::build(&self.technologies);
        let _ = self.literals.set(built);
        self.literals
            .get()
            .unwrap_or_else(|| unreachable!("literal index stored before read"))
    }
}

fn scan_channel(channel: &Channel, text: &str) -> HitSet {
    let Some(automaton) = &channel.automaton else {
        return HitSet::empty();
    };
    let words = channel.needles.len().div_ceil(64);
    let mut bits = vec![0_u64; words];
    for mat in automaton.find_iter(text) {
        let Ok(id) = u32::try_from(mat.pattern().as_usize()) else {
            continue;
        };
        set_bit(&mut bits, id);
    }
    HitSet { bits }
}

fn compile_steps(patterns: &[String], needles: &mut Interner) -> Vec<BodyStep> {
    patterns
        .iter()
        .filter_map(|pattern| compile_step(pattern, needles))
        .collect()
}

fn compile_step(raw: &str, needles: &mut Interner) -> Option<BodyStep> {
    if raw.is_empty() {
        return Some(BodyStep::Any {
            version_template: None,
        });
    }
    let parsed = parse_pattern(raw);
    if parsed.confidence < MIN_PATTERN_CONFIDENCE {
        return None;
    }
    if parsed.pattern_for_match.is_empty() {
        return Some(BodyStep::Any {
            version_template: parsed.version_template,
        });
    }
    let pat = parsed.pattern_for_match.as_str();
    if let Some(needle) = ascii_literal_needle(pat) {
        // Escaped punctuation is a needle, except when a version template needs the regex.
        if is_regex_pattern(pat) {
            if let Some(_version) = parsed.version_template.as_deref() {
                return regex_step(raw, prefix_id(&needle, needles));
            }
        }
        let needle_id = needles.intern(&needle)?;
        return Some(BodyStep::Literal { needle_id });
    }
    let prefix_id = mandatory_prefix(pat).and_then(|prefix| prefix_id(&prefix, needles));
    regex_step(raw, prefix_id)
}

fn prefix_id(prefix: &str, needles: &mut Interner) -> Option<u32> {
    needles.intern(&prefix.to_ascii_lowercase())
}

fn regex_step(raw: &str, prefix_id: Option<u32>) -> Option<BodyStep> {
    match compile_pattern(raw)? {
        CompiledPattern::Any {
            version_template, ..
        } => Some(BodyStep::Any { version_template }),
        pattern => Some(BodyStep::Regex { pattern, prefix_id }),
    }
}

/// Needle when the pattern is an ASCII substring, including escaped punctuation.
fn ascii_literal_needle(pat: &str) -> Option<String> {
    if !pat.is_ascii() {
        return None;
    }
    let needle = if is_regex_pattern(pat) {
        unescape_escaped_literal(pat)?
    } else {
        pat.to_string()
    };
    Some(needle.to_ascii_lowercase())
}

/// `Some` when every metacharacter is an escaped punctuation mark.
fn unescape_escaped_literal(pat: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = pat.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let escaped = chars.next()?;
            if !escaped.is_ascii() || escaped.is_ascii_alphanumeric() {
                return None;
            }
            out.push(escaped);
            continue;
        }
        if "^$[]()*+?{}|.".contains(ch) {
            return None;
        }
        out.push(ch);
    }
    Some(out)
}

/// Longest leading substring that every match must contain.
///
/// Stops at alternation, an optional character, or a real regex atom.
/// `foo?` yields `fo`, which is shorter than the prefilter minimum.
fn mandatory_prefix(pat: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = pat.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let escaped = chars.next()?;
            if !escaped.is_ascii() || escaped.is_ascii_alphanumeric() {
                break;
            }
            out.push(escaped);
            continue;
        }
        if ch == '|' {
            return None;
        }
        if matches!(ch, '(' | '[' | '.' | '^' | '$') {
            break;
        }
        if matches!(ch, '*' | '?' | '+' | '{') {
            let optional = match ch {
                '*' | '?' => true,
                '{' => chars.peek().copied() == Some('0'),
                _ => false,
            };
            if optional {
                out.pop();
            }
            break;
        }
        if !ch.is_ascii() {
            break;
        }
        out.push(ch);
    }
    if out.len() >= MIN_PREFIX_LEN {
        Some(out.to_ascii_lowercase())
    } else {
        None
    }
}

fn apply_steps(
    steps: &[BodyStep],
    hits: &HitSet,
    text: &str,
    matched: &mut bool,
    version: &mut Option<String>,
) -> bool {
    for step in steps {
        if apply_step(step, hits, text, matched, version) {
            return true;
        }
    }
    false
}

fn apply_step(
    step: &BodyStep,
    hits: &HitSet,
    text: &str,
    matched: &mut bool,
    version: &mut Option<String>,
) -> bool {
    let result = match step {
        BodyStep::Literal { needle_id } => {
            if hits.contains(*needle_id) {
                PatternMatchResult {
                    matched: true,
                    version: None,
                }
            } else {
                return false;
            }
        }
        BodyStep::Regex { pattern, prefix_id } => {
            if let Some(prefix_id) = prefix_id {
                if !hits.contains(*prefix_id) {
                    return false;
                }
            }
            pattern.evaluate(text)
        }
        BodyStep::Any { version_template } => handle_empty_pattern(version_template.as_deref()),
    };
    if result.matched {
        *matched = true;
        if version.is_none() {
            *version = result.version;
        }
        return version.is_some();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{ascii_literal_needle, mandatory_prefix, LiteralIndex};
    use crate::fingerprint::models::Technology;
    use crate::fingerprint::patterns::matches_pattern;
    use std::collections::HashMap;

    fn index_with(field: &str, pattern: &str) -> (LiteralIndex, String) {
        let mut tech = Technology::default();
        match field {
            "html" => tech.html = vec![pattern.to_string()],
            "script" => tech.script = vec![pattern.to_string()],
            "scripts" => tech.scripts = vec![pattern.to_string()],
            "url" => tech.url = vec![pattern.to_string()],
            _ => panic!("unknown field"),
        }
        let mut technologies = HashMap::new();
        technologies.insert("Widget".to_string(), tech);
        (LiteralIndex::build(&technologies), "Widget".to_string())
    }

    fn matched(index: &LiteralIndex, tech: &str, field: &str, text: &str) -> bool {
        let hits = match field {
            "html" => index.scan_html(text),
            "script" => index.scan_script(text),
            "scripts" => index.scan_scripts(text),
            "url" => index.scan_url(text),
            _ => panic!("unknown field"),
        };
        let mut matched = false;
        let mut version = None;
        match field {
            "html" => index.match_html(tech, &hits, text, &mut matched, &mut version),
            "script" => index.match_script(tech, &hits, text, &mut matched, &mut version),
            "scripts" => index.match_scripts(tech, &hits, text, &mut matched, &mut version),
            "url" => index.match_url(tech, &hits, text, &mut matched, &mut version),
            _ => false,
        };
        matched
    }

    #[test]
    fn escaped_dot_is_a_literal_needle() {
        assert_eq!(
            ascii_literal_needle(r"foo\.bar"),
            Some("foo.bar".to_string())
        );
        let (index, tech) = index_with("scripts", r"foo\.bar");
        assert!(matched(&index, &tech, "scripts", "xxFOO.BARyy"));
        assert!(!matched(&index, &tech, "scripts", "fooxbar"));
    }

    #[test]
    fn plain_pipe_stays_a_literal_substring() {
        let (index, tech) = index_with("html", "foo|bar");
        assert!(matched(&index, &tech, "html", "xxfoo|bar"));
        assert!(!matched(&index, &tech, "html", "foo"));
    }

    #[test]
    fn prefix_rules_skip_optional_and_alternation() {
        assert_eq!(mandatory_prefix(r"timeplot.*\.js"), Some("timeplot".into()));
        assert_eq!(mandatory_prefix(r"ab\.cd"), Some("ab.cd".into()));
        assert_eq!(mandatory_prefix(r"abcd\d+"), Some("abcd".into()));
        assert_eq!(mandatory_prefix(r"wxyz{0,1}"), None);
        assert_eq!(mandatory_prefix("foo?"), None);
        assert_eq!(mandatory_prefix(r"foo|bar\.com"), None);
        assert_eq!(mandatory_prefix("^nginx"), None);
    }

    #[test]
    fn optional_char_still_matches_without_a_prefix() {
        let (index, tech) = index_with("script", "foo?bar");
        assert!(matched(&index, &tech, "script", "fobar"));
        assert!(matched(&index, &tech, "script", "foobar"));
        assert!(!matched(&index, &tech, "script", "fbar"));
    }

    #[test]
    fn version_capture_still_runs_the_regex() {
        let (index, tech) = index_with("script", r"lib-(\d+\.\d+)\.js\;version:\1");
        let text = "https://cdn.example/lib-1.18.js";
        let hits = index.scan_script(text);
        let mut matched = false;
        let mut version = None;
        index.match_script(&tech, &hits, text, &mut matched, &mut version);
        assert!(matched);
        assert_eq!(version.as_deref(), Some("1.18"));
    }

    #[test]
    fn prefix_boundary_matches_matches_pattern() {
        // Optional `d` must not become a required prefix: `abcd?` matches `abc`.
        // A long left alternative must not hide the right side.
        let cases = [
            ("abcd?", "abc"),
            ("abcd?", "abcd"),
            (r"alphabet|other\.js", "other.js"),
            (r"alphabet|other\.js", "alphabet"),
            (r"marker\;confidence:49", "marker"),
            (r"marker\;confidence:50", "marker"),
            (r"marker\.js\;version:2", "marker.js"),
            (r"\d", "5"),
            (r"\d", "d"),
            (r"abcd\d+", "abcd9"),
            (r"wxyz{0,1}", "wxy"),
            (r"wxyz{0,1}", "wxyz"),
        ];
        for (pattern, text) in cases {
            let direct = matches_pattern(pattern, text);
            let (index, tech) = index_with("scripts", pattern);
            let hits = index.scan_scripts(text);
            let mut matched = false;
            let mut version = None;
            index.match_scripts(&tech, &hits, text, &mut matched, &mut version);
            assert_eq!(direct.matched, matched, "{pattern} against {text}");
            assert_eq!(direct.version, version, "{pattern} against {text}");
        }
    }

    #[test]
    fn regex_prefix_is_registered() {
        for pattern in [r"timeplot.*\.js", r"abcd.*"] {
            let mut needles = super::Interner::default();
            let _ = needles.intern("other");
            let step = super::compile_step(pattern, &mut needles).expect("pattern compiles");
            let super::BodyStep::Regex {
                prefix_id: Some(id),
                ..
            } = step
            else {
                panic!("{pattern} should keep a prefix");
            };
            let stored = needles
                .needles
                .get(usize::try_from(id).unwrap_or(usize::MAX))
                .map(String::as_str);
            let expected = super::mandatory_prefix(pattern).expect("prefix");
            assert_eq!(stored, Some(expected.as_str()), "{pattern}");
        }
    }

    #[test]
    fn existing_version_is_not_replaced() {
        let (index, tech) = index_with("script", r"lib-(\d+)\.js\;version:\1");
        let text = "lib-1.js";
        let hits = index.scan_script(text);
        let mut matched = false;
        let mut version = Some("9".to_string());
        index.match_script(&tech, &hits, text, &mut matched, &mut version);
        assert!(matched);
        assert_eq!(version.as_deref(), Some("9"));
    }

    #[test]
    fn second_literal_matches_on_its_own() {
        let mut tech = Technology::default();
        tech.scripts = vec!["alpha-needle".to_string(), "beta-needle".to_string()];
        let mut technologies = HashMap::new();
        technologies.insert("Widget".to_string(), tech);
        let index = LiteralIndex::build(&technologies);
        assert!(matched(&index, "Widget", "scripts", "xxalpha-needleyy"));
        assert!(matched(&index, "Widget", "scripts", "xxbeta-needleyy"));
        assert!(!matched(&index, "Widget", "scripts", "neither"));
    }

    #[test]
    fn prefixed_regex_misses_when_the_prefix_is_absent() {
        let (index, tech) = index_with("scripts", r"timeplot.*\.js");
        assert!(!matched(&index, &tech, "scripts", "other.js"));
        assert!(matched(&index, &tech, "scripts", "timeplot.v2.js"));
    }
}
