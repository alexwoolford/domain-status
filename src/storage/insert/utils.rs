//! Utility functions for database insert operations.
//!
//! This module provides helper functions for parsing and converting data
//! before insertion into the database.

use chrono::NaiveDateTime;

/// Converts a NaiveDateTime to milliseconds since Unix epoch.
pub(crate) fn naive_datetime_to_millis(datetime: Option<&NaiveDateTime>) -> Option<i64> {
    datetime.map(|dt| dt.and_utc().timestamp_millis())
}

/// Parses a JSON array string into a Vec<String>.
/// Returns None if the string is None or empty, or if parsing fails.
pub(crate) fn parse_json_array(json_str: &Option<String>) -> Option<Vec<String>> {
    let json_str = json_str.as_ref()?;
    if json_str.is_empty() {
        return None;
    }
    serde_json::from_str::<Vec<String>>(json_str).ok()
}

/// Detects the type of a TXT record based on its content.
/// Returns "SPF", "DMARC", "VERIFICATION", or "OTHER".
pub(crate) fn detect_txt_type(txt: &str) -> &'static str {
    let txt_lower = txt.to_lowercase();
    if txt_lower.starts_with("v=spf1") {
        "SPF"
    } else if txt_lower.starts_with("v=dmarc1") {
        "DMARC"
    } else if txt_lower.contains("google-site-verification")
        || txt_lower.contains("ms-verify")
        || txt_lower.contains("facebook-domain-verification")
        || txt_lower.contains("atlassian-domain-verification")
    {
        "VERIFICATION"
    } else {
        "OTHER"
    }
}

/// Parses an MX record string into priority and hostname.
/// Expected format: "10 mail.example.com" or just "mail.example.com" (default priority 0)
/// Returns None if parsing fails.
pub(crate) fn parse_mx_record(mx: &str) -> Option<(i32, String)> {
    let parts: Vec<&str> = mx.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    // Try to parse first part as priority
    if let Ok(priority) = parts[0].parse::<i32>() {
        if parts.len() >= 2 {
            Some((priority, parts[1].to_string()))
        } else {
            None
        }
    } else {
        // No priority specified, use default 0
        Some((0, parts[0].to_string()))
    }
}

/// Parses MX records from JSON array format.
/// Expected JSON format: [{"priority": 10, "hostname": "mail.example.com"}, ...]
/// Returns Vec of (priority, hostname) tuples.
pub(crate) fn parse_mx_json_array(json_str: &Option<String>) -> Option<Vec<(i32, String)>> {
    let json_str = json_str.as_ref()?;
    if json_str.is_empty() {
        return None;
    }

    // Try to parse as array of objects first
    if let Ok(mx_objects) = serde_json::from_str::<Vec<serde_json::Value>>(json_str) {
        let mut result = Vec::new();
        for obj in mx_objects {
            if let (Some(priority), Some(hostname)) = (
                obj.get("priority")
                    .and_then(|v| v.as_i64().map(|p| p as i32)),
                obj.get("hostname").and_then(|v| v.as_str()),
            ) {
                result.push((priority, hostname.to_string()));
            }
        }
        if !result.is_empty() {
            return Some(result);
        }
    }

    // Fallback: try parsing as array of strings
    if let Ok(mx_strings) = serde_json::from_str::<Vec<String>>(json_str) {
        let mut result = Vec::new();
        for mx_str in mx_strings {
            if let Some((priority, hostname)) = parse_mx_record(&mx_str) {
                result.push((priority, hostname));
            }
        }
        if !result.is_empty() {
            return Some(result);
        }
    }

    None
}
