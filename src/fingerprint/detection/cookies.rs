//! Cookie-based technology detection.
//!
//! This module matches technologies based on HTTP cookies,
//! following wappalyzergo's `checkCookies()` and `matchMapString(cookies, cookiesPart)` logic.

use std::collections::HashMap;

use crate::fingerprint::models::FingerprintRuleset;
use crate::fingerprint::patterns::matches_pattern;

/// Result of cookie matching for a single technology
#[derive(Debug, Clone)]
pub struct CookieMatchResult {
    pub tech_name: String,
    pub version: Option<String>,
}

/// Compile a wildcard cookie name (e.g. `_ga_*`) into an anchored regex.
///
/// Splits on `*` and `regex::escape`s each literal segment so that cookie names
/// containing regex metacharacters (e.g. `csrf.session`, `__Host-id`) match
/// literally rather than being mis-matched. Joins segments with `.*` and anchors
/// with `^...$`. Reuses the shared `REGEX_CACHE` (which also adds `(?i)` for
/// case-insensitive matching) so each unique pattern compiles only once across
/// the lifetime of the process.
///
/// Returns `None` only when regex compilation fails — practically never, since
/// we control all metacharacters via `regex::escape`.
fn wildcard_cookie_regex(cookie_name: &str) -> Option<regex::Regex> {
    let escaped: String = cookie_name
        .split('*')
        .map(regex::escape)
        .collect::<Vec<_>>()
        .join(".*");
    let cache_key = format!("cookie:{cookie_name}");
    crate::fingerprint::patterns::get_or_compile_regex(&format!("^{escaped}$"), &cache_key)
}

/// Checks all technologies against cookies and returns matches.
///
/// This matches wappalyzergo's `checkCookies()` → `matchMapString(cookies, cookiesPart)` flow.
/// Synchronous cookie check using a pre-fetched ruleset (for use on blocking threads).
pub(crate) fn check_cookies_with_ruleset(
    ruleset: &FingerprintRuleset,
    cookies: &HashMap<String, String>,
) -> Vec<CookieMatchResult> {
    let mut results = Vec::new();
    for (tech_name, tech) in &ruleset.technologies {
        if tech.cookies.is_empty() {
            continue;
        }
        let mut matched = false;
        let mut version: Option<String> = None;
        for (cookie_name, pattern) in &tech.cookies {
            if cookie_name.contains('*') {
                // Use the same shared, cached, metachar-escaped helper as the async
                // path: previously this branch built the regex via
                // `cookie_name.replace('*', ".*")` (no escaping) and compiled it on
                // every call inside this nested-loop hot path. That both mismatched
                // cookies whose names contain regex metacharacters (e.g. `csrf.session`,
                // `__Host-id`) and burned CPU on every URL processed.
                let Some(cookie_regex) = wildcard_cookie_regex(cookie_name) else {
                    continue;
                };
                for (actual_cookie_name, cookie_value) in cookies {
                    if cookie_regex.is_match(actual_cookie_name) {
                        if pattern.is_empty() {
                            matched = true;
                            break;
                        }
                        let result = matches_pattern(pattern, cookie_value);
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
                }
            } else if let Some(cookie_value) = cookies.get(cookie_name) {
                if pattern.is_empty() {
                    matched = true;
                    break;
                }
                let result = matches_pattern(pattern, cookie_value);
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
            if matched && version.is_some() {
                break;
            }
        }
        if matched {
            results.push(CookieMatchResult {
                tech_name: tech_name.clone(),
                version,
            });
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::models::{FingerprintMetadata, Technology};

    fn empty_tech() -> Technology {
        Technology::default()
    }

    fn ruleset_with(technologies: HashMap<String, Technology>) -> FingerprintRuleset {
        FingerprintRuleset {
            technologies,
            categories: HashMap::new(),
            metadata: FingerprintMetadata {
                source: "test".into(),
                version: "0".into(),
                last_updated: std::time::SystemTime::now(),
            },
        }
    }

    /// Empty cookie pattern means "cookie present" — Microsoft Advertising via `_uetsid`.
    #[test]
    fn test_cookies_microsoft_advertising_via_uetsid() {
        let mut tech = empty_tech();
        tech.cookies.insert("_uetsid".to_string(), String::new());
        let mut technologies = HashMap::new();
        technologies.insert("Microsoft Advertising".to_string(), tech);
        let ruleset = ruleset_with(technologies);

        let mut cookies = HashMap::new();
        cookies.insert("_uetsid".to_string(), "ABCDEF".to_string());

        let results = check_cookies_with_ruleset(&ruleset, &cookies);
        let tech_names: Vec<String> = results.iter().map(|r| r.tech_name.clone()).collect();
        assert!(
            tech_names.contains(&"Microsoft Advertising".to_string()),
            "Could not get correct match for Microsoft Advertising"
        );
    }

    /// Java (via `jsessionid`) and Laravel (via `laravel_session`) both detected
    /// when both cookies are present.
    #[test]
    fn test_cookies_java_and_laravel_both_present() {
        let mut java = empty_tech();
        java.cookies.insert("jsessionid".to_string(), String::new());
        let mut laravel = empty_tech();
        laravel
            .cookies
            .insert("laravel_session".to_string(), String::new());

        let mut technologies = HashMap::new();
        technologies.insert("Java".to_string(), java);
        technologies.insert("Laravel".to_string(), laravel);
        let ruleset = ruleset_with(technologies);

        let mut cookies = HashMap::new();
        cookies.insert("jsessionid".to_string(), "111".to_string());
        cookies.insert("XSRF-TOKEN".to_string(), "test".to_string());
        cookies.insert("laravel_session".to_string(), "eyJ*".to_string());

        let results = check_cookies_with_ruleset(&ruleset, &cookies);
        let tech_names: Vec<String> = results.iter().map(|r| r.tech_name.clone()).collect();
        assert!(
            tech_names.contains(&"Java".to_string()),
            "Could not get correct fingerprints for Java. Detected: {tech_names:?}"
        );
        assert!(
            tech_names.contains(&"Laravel".to_string()),
            "Could not get correct fingerprints for Laravel. Detected: {tech_names:?}"
        );
    }

    // --- wildcard_cookie_regex unit tests --------------------------------------------------
    //
    // These verify the escape + cache invariants of the shared helper directly,
    // without needing the global ruleset. Hits the bugs that the previous
    // sync `cookie_name.replace('*', ".*")` branch had.

    #[test]
    fn test_wildcard_cookie_regex_matches_glob_style() {
        let re = wildcard_cookie_regex("_ga_*").expect("compile");
        assert!(re.is_match("_ga_123456"));
        assert!(re.is_match("_GA_123456"), "should be case-insensitive");
        assert!(!re.is_match("not_ga_123"));
    }

    #[test]
    fn test_wildcard_cookie_regex_escapes_dot_metachar() {
        // `csrf.session` is a literal cookie name (with a dot). Without escaping,
        // the previous sync path's `replace('*', ".*")` left the dot as a regex
        // metachar so it would also match `csrfXsession`, `csrf-session`, etc.
        let re = wildcard_cookie_regex("csrf.session").expect("compile");
        assert!(re.is_match("csrf.session"));
        assert!(!re.is_match("csrfXsession"), "dot must be escaped");
        assert!(!re.is_match("csrf-session"), "dot must be escaped");
    }

    #[test]
    fn test_wildcard_cookie_regex_escapes_dash_and_brackets() {
        // `[`, `]`, `-`, `+`, `?` are all regex metachars that should be matched
        // literally when they appear in a cookie name.
        let re = wildcard_cookie_regex("__Host-id").expect("compile");
        assert!(re.is_match("__Host-id"));
        assert!(!re.is_match("__Hostxid"), "dash must be escaped");

        let re2 = wildcard_cookie_regex("a+b").expect("compile");
        assert!(re2.is_match("a+b"));
        assert!(!re2.is_match("aab"), "plus must be escaped");
    }

    #[test]
    fn test_wildcard_cookie_regex_anchored() {
        // Start anchor: `_ga_*` must NOT match `prefix_ga_123` (would happen if
        // the pattern were not anchored at the start).
        let re = wildcard_cookie_regex("_ga_*").expect("compile");
        assert!(!re.is_match("prefix_ga_123"));
        // Trailing wildcard correctly accepts any suffix.
        assert!(re.is_match("_ga_123"));
        assert!(re.is_match("_ga_123_more"));

        // End anchor: a non-trailing wildcard like `prefix_*_suffix` must require
        // the suffix to actually appear at the end of the string.
        let re_mid = wildcard_cookie_regex("prefix_*_suffix").expect("compile");
        assert!(re_mid.is_match("prefix_x_suffix"));
        assert!(re_mid.is_match("prefix_anything_in_here_suffix"));
        assert!(!re_mid.is_match("prefix_x_suffix_extra"));
    }

    /// Wildcard cookie name `_ga_*` matches `_ga_123456` — Google Analytics.
    #[test]
    fn test_cookies_wildcard_matches_google_analytics() {
        let mut tech = empty_tech();
        tech.cookies.insert("_ga_*".to_string(), String::new());
        let mut technologies = HashMap::new();
        technologies.insert("Google Analytics".to_string(), tech);
        let ruleset = ruleset_with(technologies);

        let mut cookies = HashMap::new();
        cookies.insert("_ga_123456".to_string(), "test".to_string());

        let results = check_cookies_with_ruleset(&ruleset, &cookies);
        let tech_names: Vec<String> = results.iter().map(|r| r.tech_name.clone()).collect();
        assert!(
            tech_names.contains(&"Google Analytics".to_string()),
            "Could not match Google Analytics via wildcard cookie, got: {tech_names:?}"
        );
    }
}
