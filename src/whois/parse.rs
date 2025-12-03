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
