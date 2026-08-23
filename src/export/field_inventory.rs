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
    use crate::export::fields::{
        self, flat_shared_fields, CSV_FIELD_ORDER, EXPORT_FIELDS, PARQUET_FIELD_ORDER,
    };
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
    const SATELLITE_DB_ONLY: &[&str] = &[];

    fn csv_has_column(name: &str) -> bool {
        fields::csv_column_names().any(|n| n == name)
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
            let parquet_name = flat_shared_fields()
                .find(|f| f.csv.as_ref().is_some_and(|c| c.name == *name))
                .and_then(|f| f.parquet.as_ref().map(|p| p.name))
                .unwrap_or(name);
            if !parquet_has(parquet_name) {
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
    fn flat_shared_fields_appear_in_csv_and_parquet() {
        let mut missing = Vec::new();
        for field in flat_shared_fields() {
            let csv_name = field.csv.as_ref().expect("flat_shared needs csv").name;
            let pq_name = field
                .parquet
                .as_ref()
                .expect("flat_shared needs parquet")
                .name;
            if !csv_has_column(csv_name) {
                missing.push(format!("csv:{csv_name}"));
            }
            if !parquet_has(pq_name) {
                missing.push(format!("parquet:{pq_name}"));
            }
        }
        assert!(missing.is_empty(), "flat shared field drift: {missing:?}");
    }

    #[test]
    fn csv_and_parquet_orders_match_registry() {
        let mut seen = std::collections::HashSet::new();
        for id in CSV_FIELD_ORDER {
            assert!(seen.insert(*id), "duplicate CSV field id: {id}");
            assert!(
                fields::field_by_id(id).csv.is_some(),
                "{id} in CSV_FIELD_ORDER but missing csv spec"
            );
        }
        assert_eq!(
            CSV_FIELD_ORDER.len(),
            91,
            "CSV column count drifted — edit EXPORT_FIELDS / CSV_FIELD_ORDER"
        );
        assert_eq!(SATELLITE_DB_ONLY, &[] as &[&str]);

        let mut seen_pq = std::collections::HashSet::new();
        for id in PARQUET_FIELD_ORDER {
            assert!(seen_pq.insert(*id), "duplicate Parquet field id: {id}");
            assert!(
                fields::field_by_id(id).parquet.is_some(),
                "{id} in PARQUET_FIELD_ORDER but missing parquet spec"
            );
        }
        let len = build_schema().fields().len();
        assert_eq!(len, 75, "parquet schema field count drifted: {len}");
        assert_eq!(PARQUET_FIELD_ORDER.len(), len);

        let parquet_only = PARQUET_FIELD_ORDER
            .iter()
            .filter(|id| fields::field_by_id(id).csv.is_none())
            .count();
        assert_eq!(
            EXPORT_FIELDS.len(),
            seen.len() + parquet_only,
            "EXPORT_FIELDS len should equal unique CSV ids + parquet-only ids"
        );
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
