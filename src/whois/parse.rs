//! WHOIS data parsing and conversion.

use chrono::{DateTime, Utc};
use whois_service::{ParsedWhoisData, WhoisResponse};

use super::types::WhoisResult;

fn bound_raw_text(raw_text: &str) -> String {
    if raw_text.len() <= crate::config::MAX_WHOIS_RAW_TEXT_SIZE {
        return raw_text.to_string();
    }

    crate::utils::sanitize::truncate_utf8_with_suffix(
        raw_text,
        crate::config::MAX_WHOIS_RAW_TEXT_SIZE,
        "... (truncated raw WHOIS response)",
    )
}

/// Internal payload detached from the third-party WHOIS response type.
#[derive(Debug, Clone, Default)]
pub(crate) struct WhoisPayload {
    pub(crate) raw_text: String,
    pub(crate) parsed: Option<ParsedWhoisPayload>,
}

/// Internal parsed WHOIS data detached from the third-party parser model.
#[derive(Debug, Clone, Default)]
pub(crate) struct ParsedWhoisPayload {
    pub(crate) registrar: Option<String>,
    pub(crate) creation_date: Option<String>,
    pub(crate) expiration_date: Option<String>,
    pub(crate) updated_date: Option<String>,
    pub(crate) name_servers: Vec<String>,
    pub(crate) status: Vec<String>,
}

impl From<&ParsedWhoisData> for ParsedWhoisPayload {
    fn from(value: &ParsedWhoisData) -> Self {
        Self {
            registrar: value.registrar.clone(),
            creation_date: value.creation_date.clone(),
            expiration_date: value.expiration_date.clone(),
            updated_date: value.updated_date.clone(),
            name_servers: value.name_servers.clone(),
            status: value.status.clone(),
        }
    }
}

impl From<&WhoisResponse> for WhoisPayload {
    fn from(response: &WhoisResponse) -> Self {
        Self {
            raw_text: bound_raw_text(&response.raw_data),
            parsed: response.parsed_data.as_ref().map(ParsedWhoisPayload::from),
        }
    }
}

fn extract_raw_field(raw_text: &str, labels: &[&str]) -> Option<String> {
    raw_text.lines().find_map(|line| {
        let trimmed = line.trim();
        labels.iter().find_map(|label| {
            let (field_name, value) = trimmed.split_once(':')?;
            if !field_name.trim().eq_ignore_ascii_case(label) {
                return None;
            }
            let value = value.trim();
            (!value.is_empty()).then(|| value.to_string())
        })
    })
}

pub(crate) fn enrich_result_from_raw_text(mut result: WhoisResult) -> WhoisResult {
    let Some(raw_text) = result.raw_text.as_deref() else {
        return result;
    };

    if result.registrant_org.is_none() {
        result.registrant_org = extract_raw_field(
            raw_text,
            &[
                "Registrant Organization",
                "Registrant Org",
                "Registrant organisation",
            ],
        );
    }

    if result.registrant_country.is_none() {
        result.registrant_country =
            extract_raw_field(raw_text, &["Registrant Country", "Registrant Country Code"]);
    }

    result
}

/// Converts an internal WHOIS payload to our application result.
pub(crate) fn convert_payload(payload: &WhoisPayload) -> WhoisResult {
    let Some(parsed) = &payload.parsed else {
        return WhoisResult {
            raw_text: Some(payload.raw_text.clone()),
            ..Default::default()
        };
    };

    let creation_date = parsed
        .creation_date
        .as_ref()
        .and_then(|s| parse_whois_date(s));
    let expiration_date = parsed
        .expiration_date
        .as_ref()
        .and_then(|s| parse_whois_date(s));
    let updated_date = parsed
        .updated_date
        .as_ref()
        .and_then(|s| parse_whois_date(s));

    enrich_result_from_raw_text(WhoisResult {
        creation_date,
        expiration_date,
        updated_date,
        registrar: parsed.registrar.clone(),
        registrant_country: None,
        registrant_org: None,
        status: parsed.status.clone(),
        nameservers: parsed.name_servers.clone(),
        raw_text: Some(payload.raw_text.clone()),
    })
}

/// Converts a third-party WHOIS response into our internal result via the owned DTO.
pub(crate) fn convert_parsed_data(response: &WhoisResponse) -> WhoisResult {
    convert_payload(&WhoisPayload::from(response))
}

/// Parses a WHOIS date string, returning `None` for sentinel values like the Unix epoch
/// that registrars (e.g. Squarespace) use to mean "unknown".
fn parse_whois_date(date_str: &str) -> Option<DateTime<Utc>> {
    let dt = parse_date_string(date_str).or_else(|| {
        DateTime::parse_from_rfc3339(date_str)
            .ok()
            .map(|dt| dt.with_timezone(&Utc))
    })?;
    // Reject Unix epoch (1970-01-01T00:00:00Z) — registrars use it as a sentinel for "unknown"
    if dt.timestamp() == 0 {
        return None;
    }
    Some(dt)
}

/// Attempts to parse a date string in various formats
fn parse_date_string(date_str: &str) -> Option<DateTime<Utc>> {
    let formats = [
        "%Y-%m-%dT%H:%M:%S%.fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%d/%m/%Y",
    ];

    for format in &formats {
        if let Ok(dt) = DateTime::parse_from_str(date_str, format) {
            return Some(dt.with_timezone(&Utc));
        }
        if let Ok(naive_dt) = chrono::NaiveDateTime::parse_from_str(date_str, format) {
            return Some(naive_dt.and_utc());
        }
        if let Ok(naive_date) = chrono::NaiveDate::parse_from_str(date_str, format) {
            return Some(naive_date.and_hms_opt(0, 0, 0)?.and_utc());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_parse_date_string_iso8601_with_millis() {
        let date_str = "2024-01-15T10:30:45.123Z";
        let result = parse_date_string(date_str);
        assert!(result.is_some());
        let dt = result.unwrap();
        // Verify date via format string (year(), month(), day() are private in chrono)
        assert!(dt.format("%Y-%m-%d").to_string().starts_with("2024-01-15"));
    }

    #[test]
    fn test_parse_date_string_iso8601_without_millis() {
        let date_str = "2024-01-15T10:30:45Z";
        let result = parse_date_string(date_str);
        assert!(result.is_some());
        let dt = result.unwrap();
        assert!(dt.format("%Y-%m-%d").to_string().starts_with("2024-01-15"));
    }

    #[test]
    fn test_parse_date_string_space_separated() {
        let date_str = "2024-01-15 10:30:45";
        let result = parse_date_string(date_str);
        assert!(result.is_some());
        let dt = result.unwrap();
        assert!(dt.format("%Y-%m-%d").to_string().starts_with("2024-01-15"));
    }

    #[test]
    fn test_parse_date_string_date_only() {
        let date_str = "2024-01-15";
        let result = parse_date_string(date_str);
        assert!(result.is_some());
        let dt = result.unwrap();
        assert!(dt.format("%Y-%m-%d").to_string().starts_with("2024-01-15"));
        // Time should be midnight (verify via format)
        let time_str = dt.format("%H:%M:%S").to_string();
        assert_eq!(time_str, "00:00:00");
    }

    #[test]
    fn test_parse_date_string_dd_mmm_yyyy() {
        let date_str = "15-Jan-2024";
        let result = parse_date_string(date_str);
        assert!(result.is_some());
        let dt = result.unwrap();
        assert!(dt.format("%Y-%m-%d").to_string().starts_with("2024-01-15"));
    }

    #[test]
    fn test_parse_date_string_dd_slash_mm_slash_yyyy() {
        let date_str = "15/01/2024";
        let result = parse_date_string(date_str);
        assert!(result.is_some());
        let dt = result.unwrap();
        assert!(dt.format("%Y-%m-%d").to_string().starts_with("2024-01-15"));
    }

    #[test]
    fn test_parse_date_string_invalid() {
        let date_str = "not a date";
        let result = parse_date_string(date_str);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_date_string_empty() {
        let date_str = "";
        let result = parse_date_string(date_str);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_date_string_partial_match() {
        // Should not match partial strings
        let date_str = "2024-01";
        let result = parse_date_string(date_str);
        // This might parse as a date, but we test the behavior
        // If it parses, it should be valid
        if let Some(dt) = result {
            let date = dt.date_naive();
            assert!(date.format("%Y").to_string().starts_with("2024"));
        }
    }

    #[test]
    fn test_parse_whois_date_rejects_unix_epoch() {
        assert!(parse_whois_date("1970-01-01T00:00:00Z").is_none());
        assert!(parse_whois_date("1970-01-01").is_none());
        // Valid dates should still work
        assert!(parse_whois_date("2024-01-15T10:30:45Z").is_some());
    }

    /// Stronger value asserts: several existing date-parser tests only check
    /// `is_some()`. These verify the fields actually round-trip to the expected
    /// year/month/day/hour/min/sec — including fractional seconds, timezone
    /// offsets that must normalize to UTC, and the WHOIS-specific `dd-Mmm-yyyy`
    /// format that the chrono fallback handles.
    #[test]
    fn test_parse_whois_date_values_fractional_seconds() {
        let dt = parse_whois_date("2024-01-15T10:30:45.123456Z").expect("should parse");
        // Must normalize to UTC and preserve the wall-clock time.
        assert_eq!(
            dt.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2024-01-15 10:30:45"
        );
        // Fractional seconds: 123_456 us = 123_456_000 ns.
        assert_eq!(dt.timestamp_subsec_nanos(), 123_456_000);
    }

    #[test]
    fn test_parse_whois_date_values_with_offset_normalises_to_utc() {
        // 10:30:45 in +02:00 == 08:30:45 UTC.
        let dt = parse_whois_date("2024-01-15T10:30:45+02:00").expect("should parse");
        assert_eq!(
            dt.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2024-01-15 08:30:45"
        );
    }

    #[test]
    fn test_parse_whois_date_values_dd_mmm_yyyy() {
        let dt = parse_whois_date("15-Jan-2024").expect("should parse");
        // No time component in source -> midnight UTC.
        assert_eq!(
            dt.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2024-01-15 00:00:00"
        );
    }

    // --- bound_raw_text / UTF-8 truncation tests --------------------------------------------
    //
    // The WHOIS raw response is bounded before it hits the DB. The previous
    // changelog notes UTF-8 panics in this area, so it's worth pinning down the
    // boundary invariants explicitly: result must be valid UTF-8, must respect
    // the cap, and must not split a multi-byte codepoint.

    #[test]
    fn test_bound_raw_text_short_input_unchanged() {
        let input = "short whois response";
        assert_eq!(bound_raw_text(input), input);
    }

    #[test]
    fn test_bound_raw_text_long_input_is_capped_and_valid_utf8() {
        // Multi-byte codepoints (4-byte 🚀, 3-byte 测/试) so the byte length
        // exceeds char count; this is exactly the shape that triggers
        // "truncate at byte N landed mid-codepoint" panics.
        let unit = "abc🚀测试 ";
        let mut input = String::new();
        while input.len() <= crate::config::MAX_WHOIS_RAW_TEXT_SIZE + unit.len() {
            input.push_str(unit);
        }
        assert!(input.len() > crate::config::MAX_WHOIS_RAW_TEXT_SIZE);

        let bounded = bound_raw_text(&input);
        assert!(
            bounded.len() <= crate::config::MAX_WHOIS_RAW_TEXT_SIZE,
            "bounded length {} exceeds cap {}",
            bounded.len(),
            crate::config::MAX_WHOIS_RAW_TEXT_SIZE
        );
        // String guarantees valid UTF-8, but assert explicitly so a future
        // refactor that returned bytes wouldn't silently break this contract.
        assert!(
            std::str::from_utf8(bounded.as_bytes()).is_ok(),
            "bounded text must be valid UTF-8"
        );
        // The truncation suffix must land at the end (and be reachable, since
        // suffix.len() < cap).
        assert!(
            bounded.ends_with("(truncated raw WHOIS response)"),
            "expected truncation suffix at end of: {bounded:?}"
        );
    }

    #[test]
    fn test_bound_raw_text_truncation_lands_on_char_boundary() {
        // Build an input where the natural truncation byte falls inside a
        // 4-byte codepoint, to make sure the helper steps back to a boundary
        // rather than panicking.
        let mut input = "x".repeat(crate::config::MAX_WHOIS_RAW_TEXT_SIZE - 2);
        input.push('🚀'); // 4 bytes; pushes total to MAX + 2, so naive truncate at MAX would split it.
        input.push_str(" trailing junk");

        let bounded = bound_raw_text(&input);
        assert!(bounded.len() <= crate::config::MAX_WHOIS_RAW_TEXT_SIZE);
        assert!(
            bounded.is_char_boundary(bounded.len()),
            "bounded length {} must be on a UTF-8 char boundary",
            bounded.len()
        );
        // We don't care which side of the rocket the cut falls on — just that
        // the bytes form valid UTF-8 and the length is capped.
        assert!(std::str::from_utf8(bounded.as_bytes()).is_ok());
    }

    #[test]
    fn test_convert_payload_epoch_creation_date_becomes_none() {
        let payload = WhoisPayload {
            raw_text: "raw whois".to_string(),
            parsed: Some(ParsedWhoisPayload {
                registrar: Some("Squarespace Domains II LLC".to_string()),
                creation_date: Some("1970-01-01T00:00:00Z".to_string()),
                expiration_date: Some("2026-11-15T04:16:34Z".to_string()),
                updated_date: None,
                name_servers: vec![],
                status: vec![],
            }),
        };

        let result = convert_payload(&payload);
        assert!(
            result.creation_date.is_none(),
            "epoch-zero creation date should be treated as None"
        );
        assert!(
            result.expiration_date.is_some(),
            "valid expiration date should be preserved"
        );
    }

    #[test]
    fn test_convert_payload_maps_fields_and_dates() {
        let payload = WhoisPayload {
            raw_text: "raw whois".to_string(),
            parsed: Some(ParsedWhoisPayload {
                registrar: Some("Example Registrar".to_string()),
                creation_date: Some("2024-01-15T10:30:45Z".to_string()),
                expiration_date: Some("2025-01-15".to_string()),
                updated_date: Some("15-Jan-2024".to_string()),
                name_servers: vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()],
                status: vec!["clientTransferProhibited".to_string()],
            }),
        };

        let result = convert_payload(&payload);
        assert_eq!(result.registrar.as_deref(), Some("Example Registrar"));
        assert_eq!(result.registrant_org, None);
        assert_eq!(
            result.nameservers,
            vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()]
        );
        assert_eq!(result.status, vec!["clientTransferProhibited".to_string()]);
        assert_eq!(result.raw_text.as_deref(), Some("raw whois"));
        assert!(result.creation_date.is_some());
        assert!(result.expiration_date.is_some());
        assert!(result.updated_date.is_some());
    }

    #[test]
    fn test_convert_payload_with_only_raw_text() {
        let result = convert_payload(&WhoisPayload {
            raw_text: "raw only".to_string(),
            parsed: None,
        });

        assert_eq!(result.raw_text.as_deref(), Some("raw only"));
        assert!(result.registrar.is_none());
        assert!(result.creation_date.is_none());
    }

    #[test]
    fn test_convert_parsed_data_from_real_response_shape() {
        let response = WhoisResponse {
            domain: "example.com".to_string(),
            whois_server: "whois.example.com".to_string(),
            raw_data: "Registrant Organization: Example Org\nRegistrant Country: US\nraw response"
                .to_string(),
            parsed_data: Some(ParsedWhoisData {
                registrar: Some("Registrar".to_string()),
                creation_date: Some("2024-01-15T10:30:45Z".to_string()),
                expiration_date: None,
                updated_date: None,
                name_servers: vec!["ns1.example.com".to_string()],
                status: vec![],
                registrant_name: Some("Registrant".to_string()),
                registrant_email: None,
                admin_email: None,
                tech_email: None,
                created_ago: None,
                updated_ago: None,
                expires_in: None,
            }),
            cached: false,
            query_time_ms: 123,
            parsing_analysis: None,
        };

        let result = convert_parsed_data(&response);
        assert_eq!(result.registrar.as_deref(), Some("Registrar"));
        assert_eq!(result.registrant_org.as_deref(), Some("Example Org"));
        assert_eq!(result.registrant_country.as_deref(), Some("US"));
        assert_eq!(result.nameservers, vec!["ns1.example.com".to_string()]);
    }

    #[test]
    fn test_enrich_result_from_raw_text_backfills_stale_cache_values() {
        let result = enrich_result_from_raw_text(WhoisResult {
            raw_text: Some(
                "Registrant Organization: Example Org\nRegistrant Country: CA".to_string(),
            ),
            ..WhoisResult::default()
        });

        assert_eq!(result.registrant_org.as_deref(), Some("Example Org"));
        assert_eq!(result.registrant_country.as_deref(), Some("CA"));
    }

    #[test]
    fn test_convert_payload_truncates_oversized_raw_text() {
        let oversized = "x".repeat(crate::config::MAX_WHOIS_RAW_TEXT_SIZE + 128);
        let result = convert_parsed_data(&WhoisResponse {
            domain: "example.com".to_string(),
            whois_server: "whois.example.com".to_string(),
            raw_data: oversized,
            parsed_data: None,
            cached: false,
            query_time_ms: 10,
            parsing_analysis: None,
        });

        let raw_text = result.raw_text.expect("raw WHOIS text should exist");
        assert!(raw_text.len() <= crate::config::MAX_WHOIS_RAW_TEXT_SIZE);
        assert!(raw_text.contains("truncated raw WHOIS response"));
    }
}
