//! Shared charset-aware body decoding for page and script responses.
//!
//! Page bodies enable HTML `<meta charset>` sniffing; script bodies skip it
//! (`meta_sniff: false`) because JS is not HTML.

use encoding_rs::{Encoding, UTF_8};

/// Decodes raw body bytes into a `String` using charset detection.
///
/// Picks the encoding by trying, in order:
/// 1. `charset=` parameter from the Content-Type header (RFC 7231 §3.1.1).
/// 2. Byte-Order-Mark sniffing (UTF-8 BOM `EF BB BF`, UTF-16 BE/LE).
/// 3. When `meta_sniff` is true: `<meta charset="…">` or
///    `<meta http-equiv="Content-Type" content="…">` in the first 1024 bytes.
/// 4. UTF-8 default.
///
/// Why this matters for secret detection: pages routinely declare or default
/// to UTF-8 while serving Windows-1252, ISO-8859-1, GBK, `Shift_JIS`, etc.
/// `String::from_utf8_lossy` replaces every non-UTF-8 byte with `U+FFFD`,
/// which can corrupt long base64/hex secrets. Charset-aware decoding via
/// `encoding_rs` produces faithful UTF-8 the regex engine can reason about.
pub(crate) fn decode_body(bytes: &[u8], content_type: Option<&str>, meta_sniff: bool) -> String {
    // 1. Content-Type charset
    let ct_charset = content_type.and_then(charset_from_content_type);
    if let Some(label) = ct_charset.as_deref() {
        if let Some(enc) = Encoding::for_label(label.as_bytes()) {
            let (cow, _, _) = enc.decode(bytes);
            return cow.into_owned();
        }
    }

    // 2. BOM
    if let Some(enc) = Encoding::for_bom(bytes).map(|(e, _bom_len)| e) {
        let (cow, _, _) = enc.decode(bytes);
        return cow.into_owned();
    }

    // 3. Optional <meta charset> sniffing (HTML living standard window).
    if meta_sniff {
        let prefix = &bytes[..bytes.len().min(1024)];
        if let Some(label) = sniff_meta_charset(prefix) {
            if let Some(enc) = Encoding::for_label(label.as_bytes()) {
                let (cow, _, _) = enc.decode(bytes);
                return cow.into_owned();
            }
        }
    }

    // 4. UTF-8 default.
    let (cow, _, _) = UTF_8.decode(bytes);
    cow.into_owned()
}

/// Parses the `charset` parameter out of a Content-Type header, if present.
pub(crate) fn charset_from_content_type(ct: &str) -> Option<String> {
    for part in ct.split(';').map(str::trim) {
        if let Some(rest) = part.strip_prefix("charset=").or_else(|| {
            if part.len() >= 8 && part[..8].eq_ignore_ascii_case("charset=") {
                Some(&part[8..])
            } else {
                None
            }
        }) {
            let trimmed = rest.trim().trim_matches(|c: char| c == '"' || c == '\'');
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Sniffs charset from `<meta charset>` / http-equiv Content-Type in a byte prefix.
fn sniff_meta_charset(prefix: &[u8]) -> Option<String> {
    use std::sync::LazyLock;
    static META_CHARSET_RE: LazyLock<regex::bytes::Regex> = LazyLock::new(|| {
        regex::bytes::RegexBuilder::new(
            r#"(?i)<meta[^>]+(?:charset\s*=\s*["']?([a-z0-9._:+-]+)|content\s*=\s*["'][^"'>]*?charset\s*=\s*([a-z0-9._:+-]+))"#,
        )
        .build()
        .expect("hardcoded meta charset regex")
    });

    META_CHARSET_RE.captures(prefix).and_then(|caps| {
        caps.get(1)
            .or_else(|| caps.get(2))
            .and_then(|m| std::str::from_utf8(m.as_bytes()).ok())
            .map(str::to_string)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_charset_from_content_type_utf8() {
        assert_eq!(
            charset_from_content_type("text/html; charset=utf-8"),
            Some("utf-8".to_string())
        );
        assert_eq!(
            charset_from_content_type("text/html;charset=Windows-1252"),
            Some("Windows-1252".to_string())
        );
    }

    #[test]
    fn test_charset_from_content_type_quoted() {
        assert_eq!(
            charset_from_content_type(r#"text/html; charset="iso-8859-1""#),
            Some("iso-8859-1".to_string())
        );
    }

    #[test]
    fn test_charset_from_content_type_case_insensitive() {
        assert_eq!(
            charset_from_content_type("text/html; CHARSET=UTF-8"),
            Some("UTF-8".to_string())
        );
    }

    #[test]
    fn test_charset_from_content_type_missing() {
        assert_eq!(charset_from_content_type("text/html"), None);
        assert_eq!(charset_from_content_type(""), None);
    }

    #[test]
    fn test_decode_body_uses_content_type_label() {
        let bytes = b"\x93hello\x94";
        let decoded = decode_body(bytes, Some("text/html; charset=windows-1252"), true);
        assert!(decoded.contains('\u{201C}'), "got {decoded:?}");
        assert!(!decoded.contains('\u{FFFD}'), "got {decoded:?}");
    }

    #[test]
    fn test_decode_body_falls_back_to_meta_tag() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            b"<html><head><meta charset=\"windows-1252\"><title>x</title></head><body>",
        );
        bytes.push(0x93);
        bytes.extend_from_slice(b"text");
        bytes.push(0x94);
        let decoded = decode_body(&bytes, Some("text/html"), true);
        assert!(decoded.contains('\u{201C}'), "got {decoded:?}");
    }

    #[test]
    fn test_decode_body_meta_http_equiv() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            b"<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1252\"></head><body>",
        );
        bytes.push(0x93);
        let decoded = decode_body(&bytes, None, true);
        assert!(decoded.contains('\u{201C}'), "got {decoded:?}");
    }

    #[test]
    fn test_decode_body_skips_meta_when_disabled() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"<meta charset=\"windows-1252\">");
        bytes.push(0x93);
        let with_sniff = decode_body(&bytes, None, true);
        let without_sniff = decode_body(&bytes, None, false);
        assert!(with_sniff.contains('\u{201C}'));
        assert!(without_sniff.contains('\u{FFFD}') || !without_sniff.contains('\u{201C}'));
    }

    #[test]
    fn test_decode_body_bom_utf16() {
        let bytes: &[u8] = &[0xFF, 0xFE, b'h', 0x00, b'i', 0x00];
        let decoded = decode_body(bytes, Some("text/html"), true);
        assert_eq!(decoded, "hi");
    }

    #[test]
    fn test_decode_body_default_utf8() {
        let bytes = b"hello";
        let decoded = decode_body(bytes, None, false);
        assert_eq!(decoded, "hello");
    }

    #[test]
    fn test_decode_body_unknown_label_falls_through() {
        let bytes = b"hello";
        let decoded = decode_body(bytes, Some("text/html; charset=not-a-real-thing"), false);
        assert_eq!(decoded, "hello");
    }

    #[test]
    fn test_sniff_meta_charset_finds_meta_charset_attr() {
        let body = b"<html><head><meta charset=\"shift_jis\"></head>";
        assert_eq!(sniff_meta_charset(body), Some("shift_jis".to_string()));
    }

    #[test]
    fn test_sniff_meta_charset_finds_http_equiv() {
        let body = b"<meta http-equiv=Content-Type content='text/html; charset=gb2312'>";
        assert_eq!(sniff_meta_charset(body), Some("gb2312".to_string()));
    }

    #[test]
    fn test_sniff_meta_charset_returns_none_when_absent() {
        let body = b"<html><head><title>x</title></head>";
        assert_eq!(sniff_meta_charset(body), None);
    }
}
