//! Gitleaks config parsing and compiled rules for secret detection.
//!
//! Loads the bundled gitleaks.toml, compiles regexes and allowlists,
//! and exposes a compiled config used by the secrets detector.
//!
//! Parsing preserves the association of `[[rules.allowlists]]` with the
//! preceding `[[rules]]` (same behavior as Gitleaks/Viper) by walking
//! the "rules" table in key order when it is a Table (mixed rules + allowlists).

use anyhow::{anyhow, Context, Result};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::sync::OnceLock;
use toml::Value;

/// Maximum compiled-regex size budget for gitleaks rules.
///
/// The `regex` crate's default cap is 10 MB. Several real gitleaks rules —
/// `generic-api-key`, `pypi-upload-token`, `vault-batch-token` — compile to
/// well over 10 MB because of large character-class alternations. Without
/// raising this they are silently dropped by `Regex::new` with a "Compiled
/// regex exceeds size limit" error and the bundled ruleset loses coverage
/// of those secret types entirely.
///
/// 64 MB comfortably covers every rule shipped in `config/gitleaks.toml`
/// (largest seen so far is ~24 MB compiled) while still bounding memory.
const REGEX_SIZE_LIMIT: usize = 64 * 1024 * 1024;

/// Compile a gitleaks-rule regex with a raised size limit so large alternation
/// patterns (`generic-api-key`, etc.) are not silently dropped.
fn compile_rule_regex(pattern: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
}

/// Raw TOML structure for the global allowlist (paths ignored for single-blob scan).
#[derive(Debug, Default, Deserialize)]
#[serde(rename = "allowlist")]
#[allow(dead_code)]
pub struct AllowlistRaw {
    pub paths: Option<Vec<String>>,
    pub regexes: Option<Vec<String>>,
    pub stopwords: Option<Vec<String>>,
}

/// Per-rule allowlist (paths ignored).
#[derive(Debug, Default, Deserialize, Clone)]
#[allow(dead_code)]
pub struct RuleAllowlistRaw {
    pub paths: Option<Vec<String>>,
    pub regexes: Option<Vec<String>>,
    pub stopwords: Option<Vec<String>>,
    #[serde(rename = "regexTarget")]
    pub regex_target: Option<String>,
    pub condition: Option<String>,
}

/// A single rule from gitleaks.toml (path and keywords optional for our use).
/// Some rules (e.g. pkcs12-file) have only `path` and no `regex`; we skip those.
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct RuleRaw {
    pub id: String,
    pub description: String,
    pub regex: Option<String>,
    pub entropy: Option<f64>,
    pub keywords: Option<Vec<String>>,
    #[serde(rename = "secretGroup")]
    pub secret_group: Option<u32>,
    pub path: Option<String>,
    pub allowlists: Option<Vec<RuleAllowlistRaw>>,
}

/// Top-level gitleaks config as in TOML.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct GitleaksConfigRaw {
    pub title: Option<String>,
    #[serde(rename = "minVersion")]
    pub min_version: Option<String>,
    pub allowlist: Option<AllowlistRaw>,
    pub rules: Vec<RuleRaw>,
}

/// Compiled global allowlist (regexes + stopwords only).
pub struct CompiledGlobalAllowlist {
    pub regexes: Vec<Regex>,
    pub stopwords: Vec<String>,
}

/// Match condition for allowlist criteria (Gitleaks: OR = any match skips, AND = all must match).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowlistCondition {
    Or,
    And,
}

/// Compiled per-rule allowlist.
/// `regex_target`: "line" | "match" | empty (default = secret). Controls what string allowlist regex/stopwords are tested against.
/// condition: AND = all criteria (path, regexes, stopwords) must match to skip; OR = any match skips. Path is N/A for single-blob scan.
pub struct CompiledRuleAllowlist {
    pub regexes: Vec<Regex>,
    pub stopwords: Vec<String>,
    pub regex_target: Option<String>,
    /// If true (AND), we require all criteria to match; path is treated as not matched for single-blob.
    pub condition_and: bool,
    /// If true, allowlist has path criteria; for single-blob we never match path.
    pub has_paths: bool,
}

/// A single compiled rule ready for scanning.
pub struct CompiledRule {
    pub id: String,
    pub regex: Regex,
    pub entropy: Option<f64>,
    /// Lowercased at load time. Kept for human inspection / overlay edits; the
    /// hot-path prefilter uses [`Self::keyword_pattern_ids`] instead.
    pub keywords: Option<Vec<String>>,
    /// Indices into [`KeywordPrefilter::pattern_to_id`] (the global Aho-Corasick
    /// automaton) for this rule's keywords. If `Some(non-empty)`, the rule is
    /// gated on at least one of these IDs being present in the body's matched
    /// keyword set; if `None` or empty, the rule has no keyword prefilter and
    /// always runs.
    pub keyword_pattern_ids: Option<Vec<u32>>,
    /// 1-based capture group index for secret extraction; None = first non-empty group.
    pub secret_group: Option<u32>,
    pub allowlists: Vec<CompiledRuleAllowlist>,
    /// If Some, rule is restricted to file paths matching this pattern (e.g. \.tf$). When scanning a single blob (e.g. HTML) with no path, such rules are skipped.
    pub path: Option<String>,
}

/// Single shared Aho-Corasick automaton over every distinct keyword in every
/// rule. Built once at config-load; used to compute the set of keyword IDs
/// that appear in a body in a single linear pass over the body bytes.
///
/// Why: Gitleaks rules use keyword prefilters (e.g. `["sgp_", "sourcegraph"]`)
/// to skip expensive regex evaluation on bodies that obviously can't match.
/// Naively, that's `O(rules x keywords x body_len)` per body. The shared
/// automaton collapses it to `O(body_len)` independent of rule count.
pub struct KeywordPrefilter {
    automaton: aho_corasick::AhoCorasick,
    /// Lowercased keyword -> automaton pattern ID. Used by tests and a future
    /// diagnostic helper; intentionally `pub` so external callers (e.g. a
    /// future `--explain-rule` CLI) can introspect.
    #[allow(dead_code)] // exposed for diagnostics; not yet read on the hot path
    pub pattern_to_id: std::collections::HashMap<String, u32>,
}

impl KeywordPrefilter {
    /// Returns the set of pattern IDs that appear (case-insensitively) in
    /// `body`. Caller passes this set to [`Self::any_id_present`] for each
    /// rule, avoiding any per-rule body scan.
    pub fn matched_pattern_ids(&self, body: &str) -> std::collections::HashSet<u32> {
        let mut found = std::collections::HashSet::new();
        for m in self.automaton.find_overlapping_iter(body) {
            // pattern_id() is u32 in aho-corasick 1.x and the cast is lossless;
            // this allow is only for the `as` (no truncation given u32 -> u32).
            #[allow(clippy::cast_possible_truncation)]
            let pid = m.pattern().as_u32();
            found.insert(pid);
        }
        found
    }

    /// Returns true if any of `rule_ids` is contained in `matched`.
    pub fn any_id_present(rule_ids: &[u32], matched: &std::collections::HashSet<u32>) -> bool {
        rule_ids.iter().any(|id| matched.contains(id))
    }
}

/// Full compiled config: global allowlist + rules + shared keyword prefilter.
pub struct GitleaksCompiled {
    pub global_allowlist: CompiledGlobalAllowlist,
    pub rules: Vec<CompiledRule>,
    /// `None` if there are no keywords across any rule (degenerate test
    /// fixtures). Production config always populates this.
    pub keyword_prefilter: Option<KeywordPrefilter>,
}

fn compile_allowlist_regexes(regexes: Option<Vec<String>>) -> Vec<Regex> {
    regexes
        .unwrap_or_default()
        .into_iter()
        .filter_map(|s| Regex::new(&s).ok())
        .collect()
}

fn compile_global_allowlist(raw: Option<AllowlistRaw>) -> CompiledGlobalAllowlist {
    let raw = raw.unwrap_or_default();
    CompiledGlobalAllowlist {
        regexes: compile_allowlist_regexes(raw.regexes),
        stopwords: raw.stopwords.unwrap_or_default(),
    }
}

fn parse_condition(condition: Option<&str>) -> AllowlistCondition {
    match condition.map(str::to_uppercase).as_deref() {
        Some("AND" | "&&") => AllowlistCondition::And,
        _ => AllowlistCondition::Or,
    }
}

fn compile_rule_allowlist(raw: &RuleAllowlistRaw) -> CompiledRuleAllowlist {
    let condition_and = parse_condition(raw.condition.as_deref()) == AllowlistCondition::And;
    let has_paths = raw.paths.as_ref().is_some_and(|p| !p.is_empty());
    CompiledRuleAllowlist {
        regexes: compile_allowlist_regexes(raw.regexes.clone()),
        stopwords: raw.stopwords.clone().unwrap_or_default(),
        regex_target: raw.regex_target.clone(),
        condition_and,
        has_paths,
    }
}

/// Single pass over rules Table: collect rules and allowlists in key order (`preserve_order`);
/// associate each allowlist block with the preceding [[rules]] (Gitleaks semantics).
fn rules_from_table(t: &toml::map::Map<String, Value>) -> Vec<RuleRaw> {
    let mut out: Vec<RuleRaw> = Vec::new();
    let mut pending_allowlists: Vec<RuleAllowlistRaw> = Vec::new();

    for (key, val) in t {
        if key == "allowlists" {
            if let Value::Array(arr) = val {
                for (i, tab) in arr.iter().enumerate() {
                    if let Value::Table(allow_t) = tab {
                        if let Some(a) = table_to_rule_allowlist(allow_t) {
                            if i == 0 {
                                if let Some(last) = out.last_mut() {
                                    last.allowlists.get_or_insert_with(Vec::new).push(a);
                                } else {
                                    pending_allowlists.push(a);
                                }
                            } else {
                                pending_allowlists.push(a);
                            }
                        }
                    }
                }
            }
            continue;
        }
        if key.parse::<usize>().is_err() {
            continue;
        }
        if let Value::Table(rule_t) = val {
            if let Some(mut r) = table_to_rule(rule_t) {
                if let Some(first) = pending_allowlists.first() {
                    r.allowlists = Some(vec![first.clone()]);
                    pending_allowlists = pending_allowlists.split_off(1);
                }
                out.push(r);
            }
        }
    }

    out
}

fn table_to_rule(t: &toml::map::Map<String, Value>) -> Option<RuleRaw> {
    let s = toml::to_string(&Value::Table(t.clone())).ok()?;
    toml::from_str(&s).ok()
}

fn table_to_rule_allowlist(t: &toml::map::Map<String, Value>) -> Option<RuleAllowlistRaw> {
    let s = toml::to_string(&Value::Table(t.clone())).ok()?;
    toml::from_str(&s).ok()
}

/// One entry in gitleaks.overrides.toml [[append]]: append an allowlist to a rule by id.
#[derive(Debug, Deserialize)]
struct AppendOverride {
    #[serde(rename = "rule_id")]
    rule_id: String,
    #[serde(rename = "regexTarget")]
    regex_target: Option<String>,
    pub paths: Option<Vec<String>>,
    pub regexes: Option<Vec<String>>,
    pub stopwords: Option<Vec<String>>,
    pub condition: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OverridesFile {
    append: Option<Vec<AppendOverride>>,
    rules: Option<Vec<RuleRaw>>,
}

fn merge_overrides_into_rules(rules: &mut Vec<CompiledRule>, overlay_toml: &str) {
    let file: OverridesFile = match toml::from_str(overlay_toml) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("Failed to parse gitleaks.overrides.toml: {e}");
            return;
        }
    };

    // Add entirely new rules from [[rules]] entries
    if let Some(new_rules) = file.rules {
        for r in new_rules {
            let Some(regex_str) = &r.regex else {
                log::debug!("Skipping override rule '{}': no regex", r.id);
                continue;
            };
            let regex = match Regex::new(regex_str) {
                Ok(re) => re,
                Err(e) => {
                    log::warn!("Skipping override rule '{}': invalid regex: {}", r.id, e);
                    continue;
                }
            };
            let allowlists = r
                .allowlists
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(compile_rule_allowlist)
                .collect();
            let keywords = r.keywords.as_ref().map(|kws| {
                kws.iter()
                    .map(|s| s.to_lowercase())
                    .collect::<Vec<String>>()
            });
            log::debug!("Adding override rule: {}", r.id);
            rules.push(CompiledRule {
                id: r.id,
                regex,
                entropy: r.entropy,
                keywords,
                keyword_pattern_ids: None, // assigned in build_keyword_prefilter
                secret_group: r.secret_group,
                allowlists,
                path: r.path.clone(),
            });
        }
    }

    // Append allowlists to existing rules from [[append]] entries
    if let Some(list) = file.append {
        for append in list {
            let allowlist_raw = RuleAllowlistRaw {
                paths: append.paths,
                regexes: append.regexes,
                stopwords: append.stopwords,
                regex_target: append.regex_target,
                condition: append.condition,
            };
            let compiled = compile_rule_allowlist(&allowlist_raw);
            if let Some(rule) = rules.iter_mut().find(|r| r.id == append.rule_id) {
                rule.allowlists.push(compiled);
            } else {
                log::debug!(
                    "Overrides reference rule_id '{}' which is not in config; skipping",
                    append.rule_id
                );
            }
        }
    }
}

/// Parse and compile the bundled gitleaks config.
///
/// Associates each `[[rules.allowlists]]` with the preceding `[[rules]]` by walking
/// the rules table in key order. Then merges `config/gitleaks.overrides.toml` if
/// present (web-specific allowlists, not overwritten by upstream refresh).
///
/// Returns an error if the bundled `config/gitleaks.toml` is malformed or contains
/// no compilable rules. Callers should invoke [`init_gitleaks`] eagerly during scan
/// initialization so any error surfaces as a clean startup failure rather than as
/// a panic on first secret-scan use.
fn load_compiled() -> Result<GitleaksCompiled> {
    let toml_str = include_str!("../../config/gitleaks.toml");
    let value: Value = toml::from_str(toml_str).context("Failed to parse gitleaks.toml")?;

    let global_allowlist = value.get("allowlist").and_then(|v| {
        toml::to_string(v)
            .ok()
            .and_then(|s| toml::from_str::<AllowlistRaw>(&s).ok())
    });
    let global_allowlist = compile_global_allowlist(global_allowlist);

    let rules_val = value
        .get("rules")
        .ok_or_else(|| anyhow!("gitleaks.toml must have [rules]"))?;
    let raw_rules: Vec<RuleRaw> = match rules_val {
        Value::Array(_) => {
            let raw: GitleaksConfigRaw =
                toml::from_str(toml_str).context("Failed to parse gitleaks.toml rules")?;
            raw.rules
        }
        Value::Table(t) => rules_from_table(t),
        _ => return Err(anyhow!("gitleaks.toml rules must be array or table")),
    };

    let mut rules: Vec<CompiledRule> = raw_rules
        .into_iter()
        .filter_map(|r| {
            let Some(regex_str) = &r.regex else {
                log::debug!("Skipping gitleaks rule '{}': no regex (path-only)", r.id);
                return None;
            };
            let regex = match compile_rule_regex(regex_str) {
                Ok(re) => re,
                Err(e) => {
                    log::warn!("Skipping gitleaks rule '{}': invalid regex: {}", r.id, e);
                    return None;
                }
            };
            let allowlists = r
                .allowlists
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(compile_rule_allowlist)
                .collect();
            let keywords = r.keywords.as_ref().map(|kws| {
                kws.iter()
                    .map(|s| s.to_lowercase())
                    .collect::<Vec<String>>()
            });
            Some(CompiledRule {
                id: r.id,
                regex,
                entropy: r.entropy,
                keywords,
                keyword_pattern_ids: None, // assigned in build_keyword_prefilter
                secret_group: r.secret_group,
                allowlists,
                path: r.path.clone(),
            })
        })
        .collect();

    if rules.is_empty() {
        return Err(anyhow!("gitleaks.toml produced no valid rules"));
    }

    // Apply overlay so web-specific allowlists (e.g. sourcegraph) are not lost when refreshing upstream gitleaks.toml.
    let overlay_toml = include_str!("../../config/gitleaks.overrides.toml");
    merge_overrides_into_rules(&mut rules, overlay_toml);

    let keyword_prefilter = build_keyword_prefilter(&mut rules);

    Ok(GitleaksCompiled {
        global_allowlist,
        rules,
        keyword_prefilter,
    })
}

/// Builds the shared keyword Aho-Corasick automaton from the union of every
/// rule's lowercased keywords, populating each rule's `keyword_pattern_ids`
/// in lock-step with the automaton's pattern indices.
///
/// Returns `None` if no rule has any keywords (degenerate / test-only).
fn build_keyword_prefilter(rules: &mut [CompiledRule]) -> Option<KeywordPrefilter> {
    use std::collections::HashMap;

    // Stable iteration order: rules already iterated in source order, and within
    // each rule the keyword list is the source order. Resulting pattern IDs are
    // therefore deterministic across builds.
    let mut pattern_to_id: HashMap<String, u32> = HashMap::new();
    let mut patterns: Vec<String> = Vec::new();

    for rule in rules.iter_mut() {
        let Some(kws) = rule.keywords.as_ref() else {
            continue;
        };
        let mut ids: Vec<u32> = Vec::with_capacity(kws.len());
        for kw in kws {
            if kw.is_empty() {
                continue;
            }
            let id = match pattern_to_id.get(kw) {
                Some(&id) => id,
                None => {
                    let id_usize = patterns.len();
                    let Ok(id) = u32::try_from(id_usize) else {
                        log::warn!("gitleaks keyword count exceeded u32; skipping prefilter");
                        return None;
                    };
                    patterns.push(kw.clone());
                    pattern_to_id.insert(kw.clone(), id);
                    id
                }
            };
            ids.push(id);
        }
        if !ids.is_empty() {
            ids.sort_unstable();
            ids.dedup();
            rule.keyword_pattern_ids = Some(ids);
        }
    }

    if patterns.is_empty() {
        return None;
    }

    let automaton = match aho_corasick::AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(aho_corasick::MatchKind::Standard)
        .build(&patterns)
    {
        Ok(a) => a,
        Err(e) => {
            // If we can't build the automaton, every rule must fall back to
            // running its regex unconditionally. Clear the pattern_ids so the
            // detector knows there's no prefilter to consult.
            log::warn!("Failed to build gitleaks keyword automaton: {e}; prefilter disabled");
            for rule in rules.iter_mut() {
                rule.keyword_pattern_ids = None;
            }
            return None;
        }
    };

    Some(KeywordPrefilter {
        automaton,
        pattern_to_id,
    })
}

/// Cached result of loading the bundled gitleaks config. Populated lazily by
/// [`gitleaks`] (or eagerly by [`init_gitleaks`] during scan init). The error
/// is held as a `String` because `anyhow::Error` is not directly storable in a
/// `OnceLock<Result<...>>` (it's neither `Clone` nor `Sync`-safe in the usual
/// way).
static GITLEAKS_RESULT: OnceLock<std::result::Result<GitleaksCompiled, String>> = OnceLock::new();

fn ensure_loaded() -> &'static std::result::Result<GitleaksCompiled, String> {
    GITLEAKS_RESULT.get_or_init(|| load_compiled().map_err(|e| format!("{e:?}")))
}

/// Eagerly load and validate the bundled gitleaks config.
///
/// Idempotent: subsequent calls return `Ok(())` without re-parsing.
///
/// # Errors
///
/// Returns an error if the bundled `config/gitleaks.toml` is malformed or
/// produces no compilable rules. Surface this from scan startup so any error
/// is reported as a clean failure rather than as a panic on first use.
pub fn init_gitleaks() -> Result<()> {
    match ensure_loaded() {
        Ok(_) => Ok(()),
        Err(s) => Err(anyhow!("{}", s)),
    }
}

/// Returns the loaded gitleaks ruleset, or an error string if loading failed.
///
/// Production callers should invoke [`init_gitleaks`] eagerly during scan
/// startup so any error surfaces as a clean startup failure. The lazy
/// fallback here exists for unit tests that exercise [`crate::parse::secrets`]
/// directly and never call `init_gitleaks`. Either way, the result is cached.
pub fn try_gitleaks() -> std::result::Result<&'static GitleaksCompiled, &'static str> {
    match ensure_loaded() {
        Ok(c) => Ok(c),
        Err(s) => Err(s.as_str()),
    }
}

/// Convenience accessor that panics if loading failed.
///
/// Useful for unit tests where setup-time failure is preferable to threading
/// `Result` through every test. Production code should prefer [`try_gitleaks`]
/// (or, better, gate scan startup on [`init_gitleaks`]).
///
/// # Panics
///
/// Panics if the bundled `config/gitleaks.toml` is malformed or compiles to
/// no valid rules. This indicates a developer-introduced bug, not runtime
/// input.
pub fn gitleaks() -> &'static GitleaksCompiled {
    match try_gitleaks() {
        Ok(c) => c,
        Err(e) => panic!(
            "BUG: bundled config/gitleaks.toml failed to load: {e}. \
             Use init_gitleaks() during scan startup to receive this as a Result."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use toml::map::Map;

    /// Rule/allowlist association: when rules are a Table, each [[rules.allowlists]] is associated with the preceding rule.
    /// We build the table in code so we control the structure (toml string [rules.0] + [rules.allowlists.0] may parse as array).
    #[test]
    fn test_rules_table_allowlist_association() {
        let mut rule_t = Map::new();
        rule_t.insert("id".into(), Value::String("test-rule".into()));
        rule_t.insert("description".into(), Value::String("Test".into()));
        rule_t.insert("regex".into(), Value::String("[A-Z]+".into()));

        let mut allow_t = Map::new();
        allow_t.insert(
            "regexes".into(),
            Value::Array(vec![Value::String(".+EXAMPLE$".into())]),
        );

        let mut rules_t = Map::new();
        rules_t.insert("0".into(), Value::Table(rule_t));
        rules_t.insert(
            "allowlists".into(),
            Value::Array(vec![Value::Table(allow_t)]),
        );

        let rules = rules_from_table(&rules_t);
        assert_eq!(rules.len(), 1, "expected one rule");
        let allowlists = rules[0]
            .allowlists
            .as_ref()
            .expect("rule should have allowlists");
        assert_eq!(allowlists.len(), 1, "expected one allowlist");
        let regexes = allowlists[0]
            .regexes
            .as_ref()
            .expect("allowlist should have regexes");
        assert_eq!(regexes.len(), 1);
        assert!(
            regexes[0].contains("EXAMPLE"),
            "allowlist regex should match EXAMPLE suffix, got {:?}",
            regexes[0]
        );
    }

    /// Regression guard: the bundled `gitleaks.toml` contains a few rules whose
    /// compiled regex is well over the `regex` crate's default 10 MB size limit.
    /// Without [`REGEX_SIZE_LIMIT`] raising the cap, `Regex::new` returns
    /// "Compiled regex exceeds size limit" and the rules are silently skipped —
    /// users lose detection of those secret types and only see a WARN line at
    /// startup. This test fails loudly if any of those rules vanish from the
    /// loaded ruleset.
    #[test]
    fn test_oversized_regex_rules_are_loaded() {
        let config = gitleaks();
        // These three rules were observed to exceed the default 10 MB regex
        // size limit and were being skipped before commit fix(parse/gitleaks).
        // Add new entries here whenever real upstream gitleaks updates push
        // additional rules over the threshold.
        for expected_id in ["generic-api-key", "pypi-upload-token", "vault-batch-token"] {
            assert!(
                config.rules.iter().any(|r| r.id == expected_id),
                "rule '{expected_id}' must be present in the bundled ruleset \
                 (was previously skipped due to compiled-regex size limit; \
                 see REGEX_SIZE_LIMIT in src/parse/gitleaks.rs)"
            );
        }
    }

    /// Regression: every loaded rule with non-empty keywords must have its
    /// `keyword_pattern_ids` populated. Without this, the prefilter would silently
    /// run every regex against every body even when keywords are present.
    #[test]
    fn test_keyword_prefilter_populated_for_keyworded_rules() {
        let config = gitleaks();
        let prefilter = config
            .keyword_prefilter
            .as_ref()
            .expect("production config must have a keyword prefilter");
        assert!(
            !prefilter.pattern_to_id.is_empty(),
            "prefilter should have populated patterns"
        );
        for rule in &config.rules {
            if let Some(kws) = &rule.keywords {
                if kws.iter().any(|k| !k.is_empty()) {
                    let ids = rule
                        .keyword_pattern_ids
                        .as_ref()
                        .unwrap_or_else(|| panic!("rule '{}' has keywords but no IDs", rule.id));
                    assert!(
                        !ids.is_empty(),
                        "rule '{}' has keywords but its IDs vec is empty",
                        rule.id
                    );
                    for id in ids {
                        assert!(
                            (*id as usize) < prefilter.pattern_to_id.len(),
                            "rule '{}' has out-of-range pattern id {id}",
                            rule.id
                        );
                    }
                }
            }
        }
    }

    /// Concurrency regression for the L-1 OnceLock-backed `try_gitleaks()`
    /// API: many threads calling it simultaneously before any prior call must
    /// all return `Ok` and observe the **same** `&'static GitleaksCompiled`
    /// (as compared by pointer identity). A race condition that double-built
    /// the config would either panic in `OnceLock::set` or hand out two
    /// distinct values - both would manifest as occasional flakes in
    /// production scan startup under high concurrency.
    ///
    /// Spawns 16 OS threads and joins. The `OnceLock` must serialise the first
    /// call deterministically.
    #[test]
    fn test_try_gitleaks_concurrent_first_call_returns_same_pointer() {
        use std::sync::Arc;
        use std::sync::Barrier;

        // Use 16 threads + a barrier so they all release simultaneously
        // (maximises the chance of catching a race).
        let n = 16usize;
        let barrier = Arc::new(Barrier::new(n));
        let mut handles = Vec::with_capacity(n);

        for _ in 0..n {
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                b.wait();
                let cfg = try_gitleaks().expect("config must load on every thread");
                std::ptr::from_ref(cfg) as usize
            }));
        }

        let pointers: Vec<usize> = handles
            .into_iter()
            .map(|h| h.join().expect("thread panicked"))
            .collect();

        let first = pointers[0];
        for (i, p) in pointers.iter().enumerate() {
            assert_eq!(
                *p, first,
                "thread {i} observed a different GitleaksCompiled pointer ({p:#x} vs first {first:#x}); \
                 OnceLock did not serialise the first call as expected"
            );
        }
    }

    /// Aho-Corasick produces the same set of pattern IDs regardless of casing
    /// in the body (gitleaks keywords are case-insensitive).
    #[test]
    fn test_keyword_prefilter_case_insensitive_match() {
        let config = gitleaks();
        let prefilter = config.keyword_prefilter.as_ref().expect("prefilter");
        // "akia" is a keyword on aws-access-token (gitleaks lowercases all keywords).
        // Build the AWS-shaped sample at runtime so the pre-commit gitleaks hook
        // doesn't flag a hard-coded credential-shaped literal in the source tree.
        let sample = format!("AKIA{}", "IOSFODNN7EXAMPL2");
        let upper_body = format!("blah {sample} trailing");
        let lower_body = format!("blah {} trailing", sample.to_ascii_lowercase());
        let upper = prefilter.matched_pattern_ids(&upper_body);
        let lower = prefilter.matched_pattern_ids(&lower_body);
        // Mixed-case variant: just lower-case the alpha chars in the suffix.
        let mixed_suffix: String = sample
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect();
        let mixed = prefilter.matched_pattern_ids(&format!("blah {mixed_suffix} trailing"));
        assert_eq!(upper, lower, "casing must not change matched id set");
        assert_eq!(lower, mixed);
        assert!(
            !upper.is_empty(),
            "the 'akia' keyword should fire on AKIA-prefixed strings"
        );
    }

    /// Overlay merge: gitleaks.overrides.toml appends allowlists to rules by `rule_id`. sourcegraph-access-token gets overlay allowlists.
    #[test]
    fn test_overlay_merge_appends_allowlists() {
        let config = gitleaks();
        let rule = config
            .rules
            .iter()
            .find(|r| r.id == "sourcegraph-access-token")
            .expect("sourcegraph-access-token rule should exist");
        assert!(
            !rule.allowlists.is_empty(),
            "sourcegraph-access-token should have allowlists from overlay (gitleaks.overrides.toml)"
        );
        // Overlay adds regexTarget = "line" and several regexes (e.g. id="[0-9a-fA-F]{40})
        let has_line_target = rule
            .allowlists
            .iter()
            .any(|a| a.regex_target.as_deref() == Some("line"));
        assert!(
            has_line_target,
            "overlay defines regexTarget = 'line' for sourcegraph"
        );
    }
}
