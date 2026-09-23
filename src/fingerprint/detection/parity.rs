//! Fixture parity: the literal index must agree with per-pattern `matches_pattern`.
//!
//! `matches_pattern` is the pre-automaton body matcher. These cases are the ones
//! a wrong prefix would skip, plus a version capture and a low-confidence drop.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;

use reqwest::header::HeaderMap;

use super::detect_technologies_blocking;
use crate::fingerprint::models::{FingerprintMetadata, FingerprintRuleset, Technology};
use crate::fingerprint::patterns::matches_pattern;

fn tech(html: &[&str], script: &[&str], scripts: &[&str], url: &[&str]) -> Technology {
    Technology {
        html: owned(html),
        script: owned(script),
        scripts: owned(scripts),
        url: owned(url),
        ..Default::default()
    }
}

fn owned(patterns: &[&str]) -> Vec<String> {
    patterns
        .iter()
        .map(|pattern| (*pattern).to_string())
        .collect()
}

fn ruleset() -> Arc<FingerprintRuleset> {
    Arc::new(FingerprintRuleset {
        literals: std::sync::OnceLock::new(),
        technologies: HashMap::from([
            ("Needle".into(), tech(&["alpha-needle"], &[], &[], &[])),
            ("Pipe".into(), tech(&["foo|bar"], &[], &[], &[])),
            (
                "Low".into(),
                tech(&[r"marker\;confidence:49"], &[], &[], &[]),
            ),
            ("Optional".into(), tech(&[], &["abcd?"], &[], &[])),
            ("Alt".into(), tech(&[], &[r"alphabet|other\.js"], &[], &[])),
            (
                "Versioned".into(),
                tech(&[], &[r"lib-(\d+\.\d+)\.js\;version:\1"], &[], &[]),
            ),
            (
                "FirstVersion".into(),
                tech(
                    &[],
                    &[r"pref-(\d+)\;version:\1", r"pref-(\d+)\;version:second"],
                    &[],
                    &[],
                ),
            ),
            ("Escaped".into(), tech(&[], &[], &[r"foo\.bar"], &[])),
            ("Prefix".into(), tech(&[], &[], &[r"timeplot.*\.js"], &[])),
            ("PageUrl".into(), tech(&[], &[], &[], &["cdn.example"])),
        ]),
        categories: HashMap::new(),
        metadata: FingerprintMetadata {
            source: "parity".into(),
            version: "0".into(),
            last_updated: SystemTime::now(),
        },
    })
}

/// Same channel order as the body matcher before the literal index.
fn oracle(
    ruleset: &FingerprintRuleset,
    html_body: &str,
    script_sources: &[String],
    inline_script_text: &str,
    url: &str,
) -> BTreeMap<String, (Option<String>, &'static str)> {
    let mut found = BTreeMap::new();
    for (name, tech) in &ruleset.technologies {
        if tech.html.is_empty()
            && tech.script.is_empty()
            && tech.scripts.is_empty()
            && tech.url.is_empty()
        {
            continue;
        }
        let mut matched = false;
        let mut version = None;
        let mut source = None;
        apply(
            &tech.html,
            html_body,
            "html",
            &mut matched,
            &mut version,
            &mut source,
        );
        if version.is_none() {
            for script_src in script_sources {
                let before = matched;
                let captured = apply(
                    &tech.script,
                    script_src,
                    "scriptSrc",
                    &mut matched,
                    &mut version,
                    &mut source,
                );
                if captured {
                    break;
                }
                if matched && !before && source.is_none() {
                    source = Some("scriptSrc");
                }
            }
        }
        if version.is_none() && !inline_script_text.is_empty() {
            apply(
                &tech.scripts,
                inline_script_text,
                "scripts",
                &mut matched,
                &mut version,
                &mut source,
            );
        }
        if version.is_none() {
            apply(
                &tech.url,
                url,
                "url",
                &mut matched,
                &mut version,
                &mut source,
            );
        }
        if matched {
            found.insert(name.clone(), (version, source.unwrap_or("html")));
        }
    }
    found
}

fn apply(
    patterns: &[String],
    text: &str,
    channel: &'static str,
    matched: &mut bool,
    version: &mut Option<String>,
    source: &mut Option<&'static str>,
) -> bool {
    for pattern in patterns {
        let result = matches_pattern(pattern, text);
        if !result.matched {
            continue;
        }
        *matched = true;
        if source.is_none() {
            *source = Some(channel);
        }
        if version.is_none() && result.version.is_some() {
            *version = result.version;
        }
        if version.is_some() {
            return true;
        }
    }
    false
}

fn detected(
    ruleset: &Arc<FingerprintRuleset>,
    html_body: &str,
    script_sources: &[String],
    inline_script_text: &str,
    url: &str,
) -> BTreeMap<String, (Option<String>, String)> {
    let techs = detect_technologies_blocking(
        ruleset,
        &HeaderMap::new(),
        &HashMap::new(),
        script_sources,
        html_body,
        url,
        &HashSet::new(),
        inline_script_text,
    )
    .expect("detect");
    techs
        .into_iter()
        .map(|tech| {
            (
                tech.name,
                (
                    tech.version,
                    tech.detection_source.expect("observed tech has a source"),
                ),
            )
        })
        .collect()
}

fn assert_same(
    html_body: &str,
    script_sources: &[&str],
    inline_script_text: &str,
    url: &str,
    expected: &[(&str, Option<&str>, &str)],
) {
    let ruleset = ruleset();
    let sources: Vec<String> = script_sources
        .iter()
        .map(|src| (*src).to_string())
        .collect();
    let oracle = oracle(&ruleset, html_body, &sources, inline_script_text, url);
    let detected = detected(&ruleset, html_body, &sources, inline_script_text, url);
    let expected: BTreeMap<_, _> = expected
        .iter()
        .map(|(name, version, source)| {
            (
                (*name).to_string(),
                (version.map(str::to_string), (*source).to_string()),
            )
        })
        .collect();
    let oracle: BTreeMap<_, _> = oracle
        .into_iter()
        .map(|(name, (version, source))| (name, (version, source.to_string())))
        .collect();
    assert_eq!(oracle, expected, "pre-automaton matcher");
    assert_eq!(detected, expected, "literal index");
}

#[test]
fn literal_index_matches_pre_automaton_matcher() {
    assert_same(
        "xxALPHA-NEEDLEyy xxfoo|bar marker",
        &[
            "abc",
            "other.js",
            "https://cdn.example/lib-1.18.js",
            "pref-7",
        ],
        "xxFOO.BARyy timeplot.v2.js",
        "https://cdn.example/page",
        &[
            ("Needle", None, "html"),
            ("Pipe", None, "html"),
            ("Optional", None, "scriptSrc"),
            ("Alt", None, "scriptSrc"),
            ("Versioned", Some("1.18"), "scriptSrc"),
            ("FirstVersion", Some("7"), "scriptSrc"),
            ("Escaped", None, "scripts"),
            ("Prefix", None, "scripts"),
            ("PageUrl", None, "url"),
        ],
    );
}

#[test]
fn misses_stay_misses() {
    assert_same(
        "foo marker",
        &["foo"],
        "fooxbar",
        "https://example.com/no-marker",
        &[],
    );
}
