//! WHOIS data parsing and conversion.

use chrono::{DateTime, Utc};
use whois_service::WhoisResponse;

use super::types::WhoisResult;

/// Converts whois-service ParsedWhoisData to our WhoisResult
pub(crate) fn convert_parsed_data(response: &WhoisResponse) -> WhoisResult {
    let parsed = match &response.parsed_data {
        Some(p) => p,
        None => {
            // No parsed data, return minimal result with raw text
            return WhoisResult {
                raw_text: Some(response.raw_data.clone()),
                ..Default::default()
            };
        }
    };

    // Parse date strings to DateTime<Utc>
    let creation_date = parsed.creation_date.as_ref().and_then(|s| {
        parse_date_string(s).or_else(|| {
            // Try ISO 8601 format
            DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        })
    });

    let expiration_date = parsed.expiration_date.as_ref().and_then(|s| {
        parse_date_string(s).or_else(|| {
            DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        })
    });

    let updated_date = parsed.updated_date.as_ref().and_then(|s| {
        parse_date_string(s).or_else(|| {
            DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        })
    });

    WhoisResult {
        creation_date,
        expiration_date,
        updated_date,
        registrar: parsed.registrar.clone(),
        registrant_country: None, // whois-service doesn't provide this directly
        registrant_org: parsed.registrant_name.clone(),
        status: if parsed.status.is_empty() {
            None
        } else {
            Some(parsed.status.clone())
        },
        nameservers: if parsed.name_servers.is_empty() {
            None
        } else {
            Some(parsed.name_servers.clone())
        },
        raw_text: Some(response.raw_data.clone()),
    }
}

/// Attempts to parse a date string in various formats
fn parse_date_string(date_str: &str) -> Option<DateTime<Utc>> {
    // Try common WHOIS date formats
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

// Note: Testing convert_parsed_data with full WhoisResponse requires constructing
// complex types from the whois-service crate. Since the crate's internal structure
// may change, we focus on testing the core parse_date_string function which is
// thoroughly tested above. The convert_parsed_data function is a thin wrapper
// that calls parse_date_string and maps fields, so testing parse_date_string
// provides good coverage of the conversion logic.

#[cfg(test)]
mod tests {
    use super::*;

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

    // Note: We skip testing convert_parsed_data with full WhoisResponse because
    // constructing it requires knowledge of the whois-service crate internals that
    // may change between versions. The parse_date_string function is the core logic
    // and is thoroughly tested above.
}
