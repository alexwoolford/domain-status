//! Parsing of `Strict-Transport-Security` (HSTS) header values.
//!
//! The raw HSTS header value is already stored verbatim in `url_security_headers`
//! (as `Strict-Transport-Security`), so no schema change is needed to retain the
//! original data. This module provides a small, unit-tested parser that turns that
//! raw value into structured fields (`max_age`, `include_subdomains`, `preload`) for
//! callers (e.g. future export/summary code) that want them without re-parsing the
//! header string themselves.

/// Structured representation of an HSTS header's directives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HstsDirectives {
    /// The `max-age` directive value in seconds, if present and parseable.
    pub max_age: Option<u64>,
    /// Whether the `includeSubDomains` directive was present.
    pub include_subdomains: bool,
    /// Whether the `preload` directive was present.
    pub preload: bool,
}

/// Parses a raw `Strict-Transport-Security` header value into structured directives.
///
/// Callers may pass the header value alone or a quoted / prefixed form such as
/// `Strict-Transport-Security: max-age=31536000`. Directives may be separated by
/// `;` or `,`. Directive names are matched case-insensitively per RFC 6797.
/// Unknown directives are ignored. `max-age` values that fail to parse as `u64`
/// are treated as absent. The raw header remains the storage source of truth.
pub fn parse_hsts_directive(value: &str) -> HstsDirectives {
    let normalized = normalize_hsts_value(value);
    let mut result = HstsDirectives::default();

    for segment in normalized.split(';') {
        apply_hsts_segment(segment, &mut result);
    }

    result
}

fn normalize_hsts_value(value: &str) -> String {
    let mut s = value.trim();
    if let Some(unquoted) = strip_matching_quotes(s) {
        s = unquoted.trim();
    }
    const PREFIX: &str = "strict-transport-security:";
    let lower = s.to_ascii_lowercase();
    if let Some(rest) = lower
        .strip_prefix(PREFIX)
        .and_then(|_| s.get(PREFIX.len()..))
    {
        rest.trim().to_string()
    } else {
        s.to_string()
    }
}

fn strip_matching_quotes(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    if bytes.len() < 2 {
        return None;
    }
    let (first, last) = (bytes[0], bytes[bytes.len() - 1]);
    if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
        Some(&s[1..s.len() - 1])
    } else {
        None
    }
}

fn apply_hsts_segment(segment: &str, result: &mut HstsDirectives) {
    if let Some(raw_age) = max_age_value(segment) {
        result.max_age = parse_max_age_number(raw_age);
    }
    apply_hsts_flags(segment, result);
}

fn max_age_value(segment: &str) -> Option<&str> {
    let lower = segment.to_ascii_lowercase();
    for key in ["max-age", "maxage"] {
        if let Some(pos) = lower.find(key) {
            let after_key = segment.get(pos + key.len()..)?.trim_start();
            if let Some(rest) = after_key.strip_prefix('=') {
                return Some(rest);
            }
        }
    }
    None
}

/// Digits in `max-age`, ignoring grouping commas/`_` and stopping at the next token.
fn parse_max_age_number(raw: &str) -> Option<u64> {
    let raw = raw.trim().trim_matches('"').trim();
    let mut digits = String::new();
    for c in raw.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
        } else if c == ',' || c == '_' {
            continue;
        } else if c.is_ascii_whitespace() {
            if digits.is_empty() {
                continue;
            }
            break;
        } else {
            break;
        }
    }
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

fn apply_hsts_flags(text: &str, result: &mut HstsDirectives) {
    for token in text.split(|c: char| !c.is_ascii_alphabetic()) {
        if token.eq_ignore_ascii_case("includesubdomains") {
            result.include_subdomains = true;
        } else if token.eq_ignore_ascii_case("preload") {
            result.preload = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hsts_directive_full() {
        let parsed = parse_hsts_directive("max-age=31536000; includeSubDomains; preload");
        assert_eq!(parsed.max_age, Some(31_536_000));
        assert!(parsed.include_subdomains);
        assert!(parsed.preload);
    }

    #[test]
    fn test_parse_hsts_directive_max_age_only() {
        let parsed = parse_hsts_directive("max-age=3600");
        assert_eq!(parsed.max_age, Some(3600));
        assert!(!parsed.include_subdomains);
        assert!(!parsed.preload);
    }

    #[test]
    fn test_parse_hsts_directive_case_insensitive() {
        let parsed = parse_hsts_directive("MAX-AGE=100; INCLUDESUBDOMAINS; PRELOAD");
        assert_eq!(parsed.max_age, Some(100));
        assert!(parsed.include_subdomains);
        assert!(parsed.preload);
    }

    #[test]
    fn test_parse_hsts_directive_empty() {
        let parsed = parse_hsts_directive("");
        assert_eq!(parsed, HstsDirectives::default());
    }

    #[test]
    fn test_parse_hsts_directive_invalid_max_age() {
        // Non-numeric max-age should be treated as absent, not panic
        let parsed = parse_hsts_directive("max-age=abc; preload");
        assert_eq!(parsed.max_age, None);
        assert!(parsed.preload);
    }

    #[test]
    fn test_parse_hsts_directive_whitespace_and_ordering() {
        let parsed = parse_hsts_directive("  preload ; max-age=100 ;includeSubDomains  ");
        assert_eq!(parsed.max_age, Some(100));
        assert!(parsed.include_subdomains);
        assert!(parsed.preload);
    }

    #[test]
    fn test_parse_hsts_directive_unknown_directives_ignored() {
        let parsed = parse_hsts_directive("max-age=100; unknown-directive; foo=bar");
        assert_eq!(parsed.max_age, Some(100));
        assert!(!parsed.include_subdomains);
        assert!(!parsed.preload);
    }

    #[test]
    fn test_parse_hsts_quoted_header_value() {
        let parsed = parse_hsts_directive("\"max-age=31536000; includeSubDomains\"");
        assert_eq!(parsed.max_age, Some(31_536_000));
        assert!(parsed.include_subdomains);
    }

    #[test]
    fn test_parse_hsts_header_name_prefix() {
        let parsed = parse_hsts_directive("Strict-Transport-Security: max-age=3600; preload");
        assert_eq!(parsed.max_age, Some(3600));
        assert!(parsed.preload);
    }

    #[test]
    fn test_parse_hsts_comma_separated_directives() {
        let parsed = parse_hsts_directive("max-age=31536000, includeSubDomains, preload");
        assert_eq!(parsed.max_age, Some(31_536_000));
        assert!(parsed.include_subdomains);
        assert!(parsed.preload);
    }

    #[test]
    fn test_parse_hsts_grouping_commas_in_max_age() {
        let parsed = parse_hsts_directive("max-age=7,889,238; includeSubDomains");
        assert_eq!(parsed.max_age, Some(7_889_238));
        assert!(parsed.include_subdomains);
    }

    #[test]
    fn test_parse_hsts_flexible_max_age_spacing() {
        let parsed = parse_hsts_directive("max-age = 31536000 ; includeSubDomains");
        assert_eq!(parsed.max_age, Some(31_536_000));
        assert!(parsed.include_subdomains);
    }
}
