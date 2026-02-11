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
            // SAFETY: Cast i64 to i32 for MX record priority
            // - MX priority is defined in RFC 5321 as an unsigned 16-bit value (0-65535)
            // - DNS servers enforce this constraint, so values > 65535 are invalid
            // - i32 can hold values up to 2^31-1 (2.1B), which is >> 65535
            // - If JSON contains invalid priority > i32::MAX, cast will truncate/wrap
            // - This is acceptable: invalid priorities are treated as errors during insertion
            #[allow(clippy::cast_possible_truncation)]
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

/// Builds a batch INSERT SQL query string for satellite tables.
///
/// This helper function reduces code duplication by generating the SQL query
/// string with proper placeholders. Each function still handles its own
/// binding logic since the value types differ.
///
/// # Arguments
///
/// * `table_name` - Name of the table to insert into
/// * `columns` - Column names (e.g., `["url_status_id", "nameserver"]`)
/// * `row_count` - Number of rows to insert
/// * `conflict_clause` - Optional conflict resolution clause (e.g., `"ON CONFLICT(...) DO NOTHING"`)
///
/// # Returns
///
/// The formatted SQL query string ready for binding.
///
/// # Example
///
/// ```rust,ignore
/// let query = build_batch_insert_query(
///     "url_nameservers",
///     &["url_status_id", "nameserver"],
///     2,
///     Some("ON CONFLICT(url_status_id, nameserver) DO NOTHING"),
/// );
/// // Returns: "INSERT INTO url_nameservers (url_status_id, nameserver) VALUES (?, ?), (?, ?) ON CONFLICT(...)"
/// ```
pub(crate) fn build_batch_insert_query(
    table_name: &str,
    columns: &[&str],
    row_count: usize,
    conflict_clause: Option<&str>,
) -> String {
    if row_count == 0 {
        return String::new();
    }

    let num_columns = columns.len();
    let placeholder = format!(
        "({})",
        (0..num_columns).map(|_| "?").collect::<Vec<_>>().join(", ")
    );
    let placeholders: Vec<String> = (0..row_count).map(|_| placeholder.clone()).collect();

    let mut query = format!(
        "INSERT INTO {} ({}) VALUES {}",
        table_name,
        columns.join(", "),
        placeholders.join(", ")
    );

    if let Some(conflict) = conflict_clause {
        query.push(' ');
        query.push_str(conflict);
    }

    query
}

/// Generic batch insert helper for key-value satellite tables.
///
/// This function eliminates code duplication across headers, DNS records, and other
/// satellite tables by providing a single implementation for batch insertion with
/// consistent error handling.
///
/// # Arguments
///
/// * `tx` - Database transaction
/// * `table_name` - Name of the table to insert into
/// * `parent_id_column` - Name of the parent ID column (e.g., "url_status_id")
/// * `key_column` - Name of the key column (e.g., "header_name", "nameserver")
/// * `value_column` - Name of the value column (e.g., "header_value")
/// * `parent_id` - The parent record ID
/// * `data` - Slice of (key, value) tuples to insert
/// * `conflict_clause` - Optional conflict resolution clause
///
/// # Returns
///
/// `Result<(), sqlx::Error>` - Ok on success, Err on database error
///
/// # Example
///
/// ```rust,ignore
/// let headers = vec![("Server", "nginx"), ("X-Powered-By", "PHP")];
/// insert_key_value_batch(
///     &mut tx,
///     "url_http_headers",
///     "url_status_id",
///     "header_name",
///     "header_value",
///     url_status_id,
///     &headers,
///     Some("ON CONFLICT(url_status_id, header_name) DO UPDATE SET header_value=excluded.header_value"),
/// ).await?;
/// ```
#[allow(clippy::too_many_arguments)] // 8 parameters needed for generic flexibility
pub(crate) async fn insert_key_value_batch<K, V>(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    table_name: &str,
    parent_id_column: &str,
    key_column: &str,
    value_column: &str,
    parent_id: i64,
    data: &[(K, V)],
    conflict_clause: Option<&str>,
) -> Result<(), sqlx::Error>
where
    K: for<'q> sqlx::Encode<'q, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite> + Clone,
    V: for<'q> sqlx::Encode<'q, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite> + Clone,
{
    if data.is_empty() {
        return Ok(());
    }

    // Build the SQL query
    let query = build_batch_insert_query(
        table_name,
        &[parent_id_column, key_column, value_column],
        data.len(),
        conflict_clause,
    );

    // Bind parameters
    let mut query_builder = sqlx::query(&query);
    for (key, value) in data {
        query_builder = query_builder
            .bind(parent_id)
            .bind(key.clone())
            .bind(value.clone());
    }

    // Execute
    query_builder.execute(&mut **tx).await?;

    Ok(())
}

/// Generic batch insert helper for single-column satellite tables.
///
/// This function is similar to `insert_key_value_batch` but for tables with
/// only one data column (e.g., nameservers, redirect chains).
///
/// # Arguments
///
/// * `tx` - Database transaction
/// * `table_name` - Name of the table to insert into
/// * `parent_id_column` - Name of the parent ID column (e.g., "url_status_id")
/// * `value_column` - Name of the value column (e.g., "nameserver")
/// * `parent_id` - The parent record ID
/// * `data` - Slice of values to insert
/// * `conflict_clause` - Optional conflict resolution clause
///
/// # Returns
///
/// `Result<(), sqlx::Error>` - Ok on success, Err on database error
pub(crate) async fn insert_single_column_batch<V>(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    table_name: &str,
    parent_id_column: &str,
    value_column: &str,
    parent_id: i64,
    data: &[V],
    conflict_clause: Option<&str>,
) -> Result<(), sqlx::Error>
where
    V: for<'q> sqlx::Encode<'q, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite> + Clone,
{
    if data.is_empty() {
        return Ok(());
    }

    // Build the SQL query
    let query = build_batch_insert_query(
        table_name,
        &[parent_id_column, value_column],
        data.len(),
        conflict_clause,
    );

    // Bind parameters
    let mut query_builder = sqlx::query(&query);
    for value in data {
        query_builder = query_builder.bind(parent_id).bind(value.clone());
    }

    // Execute
    query_builder.execute(&mut **tx).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    #[test]
    fn test_naive_datetime_to_millis_some() {
        let dt = NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap();
        let result = naive_datetime_to_millis(Some(&dt));
        assert!(result.is_some());
        // Verify it's a reasonable timestamp (milliseconds since epoch)
        let millis = result.unwrap();
        assert!(millis > 1_700_000_000_000); // Should be > Jan 1, 2024
        assert!(millis < 2_000_000_000_000); // Should be < year 2033
    }

    #[test]
    fn test_naive_datetime_to_millis_none() {
        assert_eq!(naive_datetime_to_millis(None), None);
    }

    #[test]
    fn test_parse_json_array_valid() {
        let json = Some(r#"["item1", "item2", "item3"]"#.to_string());
        let result = parse_json_array(&json);
        assert_eq!(
            result,
            Some(vec![
                "item1".to_string(),
                "item2".to_string(),
                "item3".to_string()
            ])
        );
    }

    #[test]
    fn test_parse_json_array_empty_string() {
        let json = Some("".to_string());
        assert_eq!(parse_json_array(&json), None);
    }

    #[test]
    fn test_parse_json_array_none() {
        assert_eq!(parse_json_array(&None), None);
    }

    #[test]
    fn test_parse_json_array_invalid_json() {
        let json = Some("not valid json".to_string());
        assert_eq!(parse_json_array(&json), None);
    }

    #[test]
    fn test_parse_json_array_not_array() {
        let json = Some(r#"{"key": "value"}"#.to_string());
        assert_eq!(parse_json_array(&json), None);
    }

    #[test]
    fn test_detect_txt_type_spf() {
        assert_eq!(
            detect_txt_type("v=spf1 include:_spf.google.com ~all"),
            "SPF"
        );
        assert_eq!(
            detect_txt_type("V=SPF1 include:_spf.google.com ~all"),
            "SPF"
        ); // Case insensitive
    }

    #[test]
    fn test_detect_txt_type_dmarc() {
        assert_eq!(detect_txt_type("v=dmarc1; p=none"), "DMARC");
        assert_eq!(detect_txt_type("V=DMARC1; p=quarantine"), "DMARC"); // Case insensitive
    }

    #[test]
    fn test_detect_txt_type_verification_google() {
        assert_eq!(
            detect_txt_type("google-site-verification=abc123"),
            "VERIFICATION"
        );
    }

    #[test]
    fn test_detect_txt_type_verification_ms() {
        assert_eq!(detect_txt_type("ms-verify=xyz789"), "VERIFICATION");
    }

    #[test]
    fn test_detect_txt_type_verification_facebook() {
        assert_eq!(
            detect_txt_type("facebook-domain-verification=def456"),
            "VERIFICATION"
        );
    }

    #[test]
    fn test_detect_txt_type_verification_atlassian() {
        assert_eq!(
            detect_txt_type("atlassian-domain-verification=ghi012"),
            "VERIFICATION"
        );
    }

    #[test]
    fn test_detect_txt_type_other() {
        assert_eq!(detect_txt_type("some other text record"), "OTHER");
        assert_eq!(detect_txt_type(""), "OTHER");
    }

    #[test]
    fn test_parse_mx_record_with_priority() {
        assert_eq!(
            parse_mx_record("10 mail.example.com"),
            Some((10, "mail.example.com".to_string()))
        );
        assert_eq!(
            parse_mx_record("0 mail.example.com"),
            Some((0, "mail.example.com".to_string()))
        );
        assert_eq!(
            parse_mx_record("100 smtp.example.com"),
            Some((100, "smtp.example.com".to_string()))
        );
    }

    #[test]
    fn test_parse_mx_record_without_priority() {
        assert_eq!(
            parse_mx_record("mail.example.com"),
            Some((0, "mail.example.com".to_string()))
        );
    }

    #[test]
    fn test_parse_mx_record_multiple_spaces() {
        assert_eq!(
            parse_mx_record("10   mail.example.com"),
            Some((10, "mail.example.com".to_string()))
        );
    }

    #[test]
    fn test_parse_mx_record_invalid() {
        assert_eq!(parse_mx_record(""), None);
        assert_eq!(parse_mx_record("10"), None); // Priority but no hostname
    }

    #[test]
    fn test_parse_mx_json_array_objects_format() {
        let json = Some(r#"[{"priority": 10, "hostname": "mail1.example.com"}, {"priority": 20, "hostname": "mail2.example.com"}]"#.to_string());
        let result = parse_mx_json_array(&json);
        assert_eq!(
            result,
            Some(vec![
                (10, "mail1.example.com".to_string()),
                (20, "mail2.example.com".to_string())
            ])
        );
    }

    #[test]
    fn test_parse_mx_json_array_strings_format() {
        let json = Some(r#"["10 mail1.example.com", "20 mail2.example.com"]"#.to_string());
        let result = parse_mx_json_array(&json);
        assert_eq!(
            result,
            Some(vec![
                (10, "mail1.example.com".to_string()),
                (20, "mail2.example.com".to_string())
            ])
        );
    }

    #[test]
    fn test_parse_mx_json_array_strings_without_priority() {
        let json = Some(r#"["mail1.example.com", "mail2.example.com"]"#.to_string());
        let result = parse_mx_json_array(&json);
        assert_eq!(
            result,
            Some(vec![
                (0, "mail1.example.com".to_string()),
                (0, "mail2.example.com".to_string())
            ])
        );
    }

    #[test]
    fn test_parse_mx_json_array_empty() {
        assert_eq!(parse_mx_json_array(&None), None);
        assert_eq!(parse_mx_json_array(&Some("".to_string())), None);
        assert_eq!(parse_mx_json_array(&Some("[]".to_string())), None);
    }

    #[test]
    fn test_parse_mx_json_array_invalid_json() {
        assert_eq!(parse_mx_json_array(&Some("not json".to_string())), None);
    }

    #[test]
    fn test_parse_mx_json_array_mixed_formats() {
        // Objects format takes precedence
        let json = Some(
            r#"[{"priority": 10, "hostname": "mail.example.com"}, "20 mail2.example.com"]"#
                .to_string(),
        );
        let result = parse_mx_json_array(&json);
        // Should parse objects first, ignore strings if objects found
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1); // Only the object entry
    }

    #[test]
    fn test_parse_mx_json_array_incomplete_object() {
        // Object missing priority or hostname should be skipped
        let json = Some(r#"[{"priority": 10}, {"hostname": "mail.example.com"}]"#.to_string());
        let result = parse_mx_json_array(&json);
        assert_eq!(result, None); // Empty result after filtering
    }
}
