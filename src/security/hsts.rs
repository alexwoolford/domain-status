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
/// The header is a semicolon-separated list of directives, e.g.:
/// `max-age=31536000; includeSubDomains; preload`
///
/// Directive names are matched case-insensitively per RFC 6797. Unknown directives
/// are ignored. `max-age` values that fail to parse as `u64` are treated as absent.
pub fn parse_hsts_directive(value: &str) -> HstsDirectives {
    let mut result = HstsDirectives::default();

    for part in value.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if let Some((name, val)) = part.split_once('=') {
            if name.trim().eq_ignore_ascii_case("max-age") {
                result.max_age = val.trim().trim_matches('"').parse::<u64>().ok();
            }
        } else if part.eq_ignore_ascii_case("includeSubDomains") {
            result.include_subdomains = true;
        } else if part.eq_ignore_ascii_case("preload") {
            result.preload = true;
        }
    }

    result
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
}
