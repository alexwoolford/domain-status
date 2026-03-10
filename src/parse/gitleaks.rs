//! Gitleaks config parsing and compiled rules for secret detection.
//!
//! Loads the bundled gitleaks.toml, compiles regexes and allowlists,
//! and exposes a compiled config used by the secrets detector.
//!
//! Parsing preserves the association of `[[rules.allowlists]]` with the
//! preceding `[[rules]]` (same behavior as Gitleaks/Viper) by walking
//! the "rules" table in key order when it is a Table (mixed rules + allowlists).

use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;
use toml::Value;

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
    /// Lowercased at load time; if Some and non-empty, rule runs only when at least one keyword appears in fragment (Gitleaks prefilter).
    pub keywords: Option<Vec<String>>,
    /// 1-based capture group index for secret extraction; None = first non-empty group.
    pub secret_group: Option<u32>,
    pub allowlists: Vec<CompiledRuleAllowlist>,
    /// If Some, rule is restricted to file paths matching this pattern (e.g. \.tf$). When scanning a single blob (e.g. HTML) with no path, such rules are skipped.
    pub path: Option<String>,
}

/// Full compiled config: global allowlist + rules.
pub struct GitleaksCompiled {
    pub global_allowlist: CompiledGlobalAllowlist,
    pub rules: Vec<CompiledRule>,
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
    match condition.map(|s| s.to_uppercase()).as_deref() {
        Some("AND") | Some("&&") => AllowlistCondition::And,
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
            log::warn!("Failed to parse gitleaks.overrides.toml: {}", e);
            return;
        }
    };

    // Add entirely new rules from [[rules]] entries
    if let Some(new_rules) = file.rules {
        for r in new_rules {
            let regex_str = match &r.regex {
                Some(s) => s,
                None => {
                    log::debug!("Skipping override rule '{}': no regex", r.id);
                    continue;
                }
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

/// Parse and compile the bundled gitleaks config. Panics on parse or if no rules.
/// Associates each [[rules.allowlists]] with the preceding [[rules]] by walking the rules table in key order.
/// Then merges config/gitleaks.overrides.toml if present (web-specific allowlists, not overwritten by upstream refresh).
fn load_compiled() -> GitleaksCompiled {
    let toml_str = include_str!("../../config/gitleaks.toml");
    let value: Value =
        toml::from_str(toml_str).unwrap_or_else(|e| panic!("Failed to parse gitleaks.toml: {}", e));

    let global_allowlist = value.get("allowlist").and_then(|v| {
        toml::to_string(v)
            .ok()
            .and_then(|s| toml::from_str::<AllowlistRaw>(&s).ok())
    });
    let global_allowlist = compile_global_allowlist(global_allowlist);

    let rules_val = value.get("rules").expect("gitleaks.toml must have [rules]");
    let raw_rules: Vec<RuleRaw> = match rules_val {
        Value::Array(_) => {
            let raw: GitleaksConfigRaw = toml::from_str(toml_str)
                .unwrap_or_else(|e| panic!("Failed to parse gitleaks.toml rules: {}", e));
            raw.rules
        }
        Value::Table(t) => rules_from_table(t),
        _ => panic!("gitleaks.toml rules must be array or table"),
    };

    let mut rules: Vec<CompiledRule> = raw_rules
        .into_iter()
        .filter_map(|r| {
            let regex_str = match &r.regex {
                Some(s) => s,
                None => {
                    log::debug!("Skipping gitleaks rule '{}': no regex (path-only)", r.id);
                    return None;
                }
            };
            let regex = match Regex::new(regex_str) {
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
                secret_group: r.secret_group,
                allowlists,
                path: r.path.clone(),
            })
        })
        .collect();

    if rules.is_empty() {
        panic!("gitleaks.toml produced no valid rules");
    }

    // Apply overlay so web-specific allowlists (e.g. sourcegraph) are not lost when refreshing upstream gitleaks.toml.
    let overlay_toml = include_str!("../../config/gitleaks.overrides.toml");
    merge_overrides_into_rules(&mut rules, overlay_toml);

    GitleaksCompiled {
        global_allowlist,
        rules,
    }
}

/// Compiled gitleaks config, loaded once at first use.
pub static GITLEAKS: LazyLock<GitleaksCompiled> = LazyLock::new(load_compiled);

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

    /// Overlay merge: gitleaks.overrides.toml appends allowlists to rules by `rule_id`. sourcegraph-access-token gets overlay allowlists.
    #[test]
    fn test_overlay_merge_appends_allowlists() {
        let config = &GITLEAKS;
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
