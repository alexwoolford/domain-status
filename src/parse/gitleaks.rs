//! Gitleaks config parsing and compiled rules for secret detection.
//!
//! Loads the bundled gitleaks.toml, compiles regexes and allowlists,
//! and exposes a compiled config used by the secrets detector.

use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;

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
#[derive(Debug, Default, Deserialize)]
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
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct RuleRaw {
    pub id: String,
    pub description: String,
    pub regex: Option<String>,
    pub entropy: Option<f64>,
    pub keywords: Option<Vec<String>>,
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

/// Compiled per-rule allowlist.
pub struct CompiledRuleAllowlist {
    pub regexes: Vec<Regex>,
    pub stopwords: Vec<String>,
}

/// A single compiled rule ready for scanning.
pub struct CompiledRule {
    pub id: String,
    pub regex: Regex,
    pub entropy: Option<f64>,
    pub allowlists: Vec<CompiledRuleAllowlist>,
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

fn compile_rule_allowlist(raw: &RuleAllowlistRaw) -> CompiledRuleAllowlist {
    CompiledRuleAllowlist {
        regexes: compile_allowlist_regexes(raw.regexes.clone()),
        stopwords: raw.stopwords.clone().unwrap_or_default(),
    }
}

/// Parse and compile the bundled gitleaks config. Panics on parse or if no rules.
fn load_compiled() -> GitleaksCompiled {
    let toml_str = include_str!("../../config/gitleaks.toml");
    let raw: GitleaksConfigRaw =
        toml::from_str(toml_str).unwrap_or_else(|e| panic!("Failed to parse gitleaks.toml: {}", e));

    let global_allowlist = compile_global_allowlist(raw.allowlist);

    let rules: Vec<CompiledRule> = raw
        .rules
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
            Some(CompiledRule {
                id: r.id,
                regex,
                entropy: r.entropy,
                allowlists,
            })
        })
        .collect();

    if rules.is_empty() {
        panic!("gitleaks.toml produced no valid rules");
    }

    GitleaksCompiled {
        global_allowlist,
        rules,
    }
}

/// Compiled gitleaks config, loaded once at first use.
pub static GITLEAKS: LazyLock<GitleaksCompiled> = LazyLock::new(load_compiled);
