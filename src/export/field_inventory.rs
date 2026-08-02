//! Capture ↔ export field inventory guards.
//!
//! Adding a `url_status` column or satellite table is easy to forget in one of
//! CSV / JSONL / Parquet / `MainRowData`. These checks pin the intentional
//! contract so CI fails when the flat exports drift from the capture schema.

#[cfg(test)]
/// `url_status` columns that must appear in flat CSV + Parquet exports and as
/// top-level JSONL keys.
///
/// Keep this list focused on fields consumers rely on in spreadsheets /
/// analytics; scan-internal completeness metrics stay DB-only by design
/// (see test-only `URL_STATUS_DB_ONLY`).
pub(crate) const URL_STATUS_REQUIRED_IN_FLAT_EXPORT: &[&str] = &[
    "initial_url",
    "final_url",
    "meta_robots",
    "ip_address",
    "title",
    "body_sha256",
    "canonical_url",
    "cert_fingerprint_sha256",
];

#[cfg(test)]
mod tests {
    use super::URL_STATUS_REQUIRED_IN_FLAT_EXPORT;
    use crate::export::csv::CSV_COLUMN_DEFS;
    use crate::export::parquet::build_schema;
    use crate::storage::insert::url::URL_STATUS_COLUMN_DEFS;

    /// Captured on `url_status` but intentionally omitted from flat CSV/Parquet.
    ///
    /// Query `SQLite` (or add an export later) if you need these. Listed here so the
    /// omission is deliberate rather than accidental drift.
    const URL_STATUS_DB_ONLY: &[&str] = &[
        "ssl_cert_valid_from_ms",
        "external_scripts_eligible",
        "external_scripts_scanned",
        "cert_serial_number",
        "cert_is_self_signed",
        "cert_is_wildcard",
        "cert_is_mismatched",
        "meta_refresh_url",
    ];

    /// Satellite tables persisted but not flattened into CSV/Parquet today.
    const SATELLITE_DB_ONLY: &[&str] = &["url_script_hosts"];

    fn csv_has_column(name: &str) -> bool {
        CSV_COLUMN_DEFS.iter().any(|c| c.name == name)
    }

    fn parquet_has(name: &str) -> bool {
        build_schema().field_with_name(name).is_ok()
    }

    fn url_status_has(name: &str) -> bool {
        URL_STATUS_COLUMN_DEFS.iter().any(|c| c.name == name)
    }

    #[test]
    fn required_url_status_fields_are_captured() {
        for name in URL_STATUS_REQUIRED_IN_FLAT_EXPORT {
            assert!(
                url_status_has(name),
                "{name} missing from URL_STATUS_COLUMN_DEFS"
            );
        }
    }

    #[test]
    fn required_fields_appear_in_csv_and_parquet() {
        let mut missing_csv = Vec::new();
        let mut missing_parquet = Vec::new();
        for name in URL_STATUS_REQUIRED_IN_FLAT_EXPORT {
            if !csv_has_column(name) {
                missing_csv.push(*name);
            }
            if !parquet_has(name) {
                missing_parquet.push(*name);
            }
        }
        assert!(
            missing_csv.is_empty(),
            "CSV missing required fields: {missing_csv:?}"
        );
        assert!(
            missing_parquet.is_empty(),
            "Parquet missing required fields: {missing_parquet:?}"
        );
    }

    #[test]
    fn csv_column_defs_have_unique_names() {
        let mut seen = std::collections::HashSet::new();
        for col in CSV_COLUMN_DEFS {
            assert!(
                seen.insert(col.name),
                "duplicate CSV column name: {}",
                col.name
            );
        }
        assert_eq!(
            CSV_COLUMN_DEFS.len(),
            83,
            "CSV column count drifted — add/remove via CSV_COLUMN_DEFS only"
        );
        assert_eq!(SATELLITE_DB_ONLY, &["url_script_hosts"]);
        let len = build_schema().fields().len();
        assert_eq!(len, 67, "parquet schema field count drifted: {len}");
    }

    #[test]
    fn db_only_fields_are_still_on_url_status() {
        for name in URL_STATUS_DB_ONLY {
            assert!(
                url_status_has(name),
                "documented DB-only field {name} missing from URL_STATUS_COLUMN_DEFS"
            );
            assert!(
                !csv_has_column(name),
                "{name} unexpectedly appeared in CSV — update URL_STATUS_DB_ONLY or export it"
            );
        }
    }
}
