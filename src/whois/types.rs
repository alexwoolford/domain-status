//! WHOIS data structures.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// WHOIS lookup result.
///
/// Fields are normalized into optional structured values because WHOIS and RDAP
/// responses are highly inconsistent across registries.
///
/// A missing scalar field (`None`) means the upstream source did not provide a
/// trustworthy value; it does not necessarily mean the domain itself lacks that
/// property.
///
/// `status` and `nameservers` are plain `Vec<String>` (possibly empty) rather
/// than `Option<Vec<String>>`. The `Option` form had three states (None, empty,
/// non-empty) which is one too many — callers had to handle "absent" and
/// "empty" separately even though both meant "no values to display". An empty
/// vector now expresses "the lookup completed but returned no entries" and the
/// downstream DB write path stores NULL for the empty case so the
/// "missing-vs-present" distinction is preserved at the storage layer.
///
/// # Examples
///
/// ```no_run
/// use domain_status::lookup_whois;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// if let Some(whois) = lookup_whois("example.com", None).await? {
///     println!("{} nameservers", whois.nameservers.len());
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct WhoisResult {
    /// Domain creation date when supplied by the upstream provider.
    pub creation_date: Option<DateTime<Utc>>,
    /// Domain expiration date when supplied by the upstream provider.
    pub expiration_date: Option<DateTime<Utc>>,
    /// Domain updated date when supplied by the upstream provider.
    pub updated_date: Option<DateTime<Utc>>,
    /// Registrar name.
    pub registrar: Option<String>,
    /// Registrant country code (typically ISO 3166-1 alpha-2).
    pub registrant_country: Option<String>,
    /// Registrant organization.
    ///
    /// This is intentionally distinct from a personal registrant name. The parser
    /// leaves it as `None` when it cannot confidently map an organization value.
    pub registrant_org: Option<String>,
    /// Domain status values such as `clientTransferProhibited`.
    /// Empty vector when the upstream source returned no values.
    pub status: Vec<String>,
    /// Nameservers extracted from WHOIS/RDAP payloads.
    /// Empty vector when the upstream source returned no values.
    pub nameservers: Vec<String>,
    /// Raw WHOIS text when available.
    pub raw_text: Option<String>,
}

/// Metadata about a cached WHOIS lookup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WhoisCacheEntry {
    pub(crate) result: WhoisCacheResult,
    pub(crate) cached_at: SystemTime,
    pub(crate) domain: String,
}

/// Serializable version of `WhoisResult` for caching
///
/// Note: `status` and `nameservers` stay `Option<Vec<String>>` on disk so
/// existing cache files (which used the old `WhoisResult` shape) keep
/// deserialising. The conversion to/from `WhoisResult` collapses
/// `None`/`Some(empty)` into `Vec::new()` and `Some(non-empty)` into the
/// vector verbatim, so the in-memory API is the simpler `Vec<String>`
/// (possibly empty) while the on-disk JSON is unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WhoisCacheResult {
    creation_date: Option<i64>,
    expiration_date: Option<i64>,
    updated_date: Option<i64>,
    registrar: Option<String>,
    registrant_country: Option<String>,
    registrant_org: Option<String>,
    status: Option<Vec<String>>,
    nameservers: Option<Vec<String>>,
    raw_text: Option<String>,
}

impl From<&WhoisResult> for WhoisCacheResult {
    fn from(result: &WhoisResult) -> Self {
        // Empty vec -> None on disk (preserves the existing JSON shape so old
        // cache files round-trip identically).
        let vec_to_opt = |v: &Vec<String>| -> Option<Vec<String>> {
            if v.is_empty() {
                None
            } else {
                Some(v.clone())
            }
        };
        WhoisCacheResult {
            creation_date: result.creation_date.map(|dt| dt.timestamp_millis()),
            expiration_date: result.expiration_date.map(|dt| dt.timestamp_millis()),
            updated_date: result.updated_date.map(|dt| dt.timestamp_millis()),
            registrar: result.registrar.clone(),
            registrant_country: result.registrant_country.clone(),
            registrant_org: result.registrant_org.clone(),
            status: vec_to_opt(&result.status),
            nameservers: vec_to_opt(&result.nameservers),
            raw_text: result.raw_text.clone(),
        }
    }
}

impl From<WhoisCacheResult> for WhoisResult {
    fn from(cache: WhoisCacheResult) -> Self {
        // Convert milliseconds to (secs, nanos) for DateTime::from_timestamp.
        //
        // If the cached value is unrepresentable as a `DateTime<Utc>` (e.g. a
        // corrupted or out-of-range integer), preserve `None` rather than
        // collapsing to 1970-01-01 via `unwrap_or_default()`. The previous
        // behaviour silently wrote a confidently-wrong creation/expiration date
        // to the database, which is harder to spot than a NULL.
        //
        // Use rem_euclid so negative timestamps (pre-1970) produce valid 0..999
        // sub-second ms.
        #[allow(clippy::cast_possible_truncation)] // rem_euclid(1000) is 0..999, * 1M fits in u32
        let ms_to_dt = |ms: i64| -> Option<DateTime<Utc>> {
            let nanos = (ms.rem_euclid(1000) * 1_000_000) as u32;
            DateTime::from_timestamp(ms.div_euclid(1000), nanos)
        };
        WhoisResult {
            creation_date: cache.creation_date.and_then(ms_to_dt),
            expiration_date: cache.expiration_date.and_then(ms_to_dt),
            updated_date: cache.updated_date.and_then(ms_to_dt),
            registrar: cache.registrar,
            registrant_country: cache.registrant_country,
            registrant_org: cache.registrant_org,
            // Old cache files store `null` for absent lists; in-memory API uses
            // an empty vector for both "absent" and "empty" — the distinction
            // is preserved at the storage boundary in WhoisCacheResult::from
            // and in the SQL write path in storage::insert::enrichment::whois.
            status: cache.status.unwrap_or_default(),
            nameservers: cache.nameservers.unwrap_or_default(),
            raw_text: cache.raw_text,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whois_cache_result_from_whois_result() {
        let whois_result = WhoisResult {
            creation_date: Some(chrono::Utc::now()),
            expiration_date: Some(chrono::Utc::now() + chrono::Duration::days(365)),
            updated_date: Some(chrono::Utc::now()),
            registrar: Some("Test Registrar".to_string()),
            registrant_country: Some("US".to_string()),
            registrant_org: Some("Test Org".to_string()),
            status: vec!["active".to_string()],
            nameservers: vec!["ns1.example.com".to_string()],
            raw_text: Some("Raw text".to_string()),
        };

        let cache_result: WhoisCacheResult = (&whois_result).into();
        // Convert back to verify round-trip
        let converted_back: WhoisResult = cache_result.into();
        assert!(converted_back.creation_date.is_some());
        assert!(converted_back.expiration_date.is_some());
        assert_eq!(converted_back.registrar, Some("Test Registrar".to_string()));
        assert_eq!(converted_back.registrant_country, Some("US".to_string()));
        assert_eq!(converted_back.status, vec!["active".to_string()]);
    }

    #[test]
    fn test_whois_cache_result_from_whois_result_none_fields() {
        let whois_result = WhoisResult::default();
        let cache_result: WhoisCacheResult = (&whois_result).into();
        // Convert back to verify round-trip
        let converted_back: WhoisResult = cache_result.into();
        assert!(converted_back.creation_date.is_none());
        assert!(converted_back.registrar.is_none());
    }

    /// Wire-compat check: existing on-disk cache JSON used `null` and
    /// `[...]` for `status`/`nameservers`. After tightening `WhoisResult` to
    /// plain `Vec<String>`, those old payloads must still deserialise to a
    /// sane `WhoisResult` (with `Vec::new()` standing in for both `null` and
    /// missing list entries) so the on-disk WHOIS cache survives the
    /// upgrade. Regression gate for D-2.
    #[test]
    fn test_whois_cache_json_compat_old_null_status_round_trips() {
        // Hand-crafted JSON that mirrors what the previous WhoisCacheResult
        // shape would have written for "no statuses, two nameservers".
        let raw = r#"{
            "creation_date": null,
            "expiration_date": null,
            "updated_date": null,
            "registrar": "Some Registrar",
            "registrant_country": null,
            "registrant_org": null,
            "status": null,
            "nameservers": ["ns1.example.com", "ns2.example.com"],
            "raw_text": null
        }"#;
        let cache: WhoisCacheResult =
            serde_json::from_str(raw).expect("legacy cache JSON must still deserialize");
        let result: WhoisResult = cache.into();
        assert_eq!(result.registrar.as_deref(), Some("Some Registrar"));
        assert!(result.status.is_empty(), "null on disk -> empty Vec");
        assert_eq!(
            result.nameservers,
            vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()]
        );
    }

    /// Wire-compat check the other direction: an in-memory `WhoisResult` with
    /// an empty status vector must serialise to JSON with `status: null` (not
    /// `status: []`) so existing exports/queries that distinguish "absent"
    /// from "explicit empty" keep behaving the same way after the API change.
    #[test]
    fn test_whois_cache_json_compat_empty_vec_serialises_as_null() {
        let result = WhoisResult {
            registrar: Some("R".to_string()),
            status: vec![], // empty list of WHOIS statuses
            nameservers: vec!["ns1.example.com".to_string()],
            ..WhoisResult::default()
        };
        let cache: WhoisCacheResult = (&result).into();
        let json: serde_json::Value = serde_json::to_value(&cache).expect("cache must serialise");
        assert_eq!(
            json["status"],
            serde_json::Value::Null,
            "empty in-memory Vec must persist as JSON null (preserves absent-vs-empty distinction)"
        );
        assert_eq!(
            json["nameservers"],
            serde_json::json!(["ns1.example.com"]),
            "non-empty Vec must persist as a JSON array"
        );
    }

    #[test]
    fn test_whois_cache_result_unrepresentable_timestamp_is_none() {
        // A corrupted or out-of-range millisecond integer must round-trip back to
        // `None`, not collapse to 1970-01-01 (which silently corrupts the data).
        // i64::MAX is well outside the range DateTime<Utc> can represent.
        let cache = WhoisCacheResult {
            creation_date: Some(i64::MAX),
            expiration_date: Some(i64::MIN),
            updated_date: Some(0),
            registrar: None,
            registrant_country: None,
            registrant_org: None,
            status: None,
            nameservers: None,
            raw_text: None,
        };
        let result: WhoisResult = cache.into();
        assert!(
            result.creation_date.is_none(),
            "i64::MAX ms must round-trip to None, not 1970-01-01"
        );
        assert!(
            result.expiration_date.is_none(),
            "i64::MIN ms must round-trip to None, not 1970-01-01"
        );
        // 0 ms is a valid timestamp (epoch) — should round-trip to Some(epoch).
        assert!(
            result.updated_date.is_some(),
            "0 ms is a valid timestamp and must round-trip to Some(epoch)"
        );
    }

    #[test]
    fn test_whois_cache_result_round_trip() {
        let original = WhoisResult {
            creation_date: Some(chrono::Utc::now()),
            expiration_date: Some(chrono::Utc::now() + chrono::Duration::days(365)),
            updated_date: Some(chrono::Utc::now()),
            registrar: Some("Test Registrar".to_string()),
            registrant_country: Some("US".to_string()),
            registrant_org: Some("Test Org".to_string()),
            status: vec!["active".to_string()],
            nameservers: vec!["ns1.example.com".to_string()],
            raw_text: Some("Raw text".to_string()),
        };

        // Convert to cache format and back
        let cache_result: WhoisCacheResult = (&original).into();
        let converted: WhoisResult = cache_result.into();

        // Verify all fields are preserved
        assert_eq!(converted.registrar, original.registrar);
        assert_eq!(converted.registrant_country, original.registrant_country);
        assert_eq!(converted.registrant_org, original.registrant_org);
        assert_eq!(converted.status, original.status);
        assert_eq!(converted.nameservers, original.nameservers);
        assert_eq!(converted.raw_text, original.raw_text);
        // Dates may have slight precision differences due to millis conversion, so just verify they exist
        assert!(converted.creation_date.is_some());
        assert!(converted.expiration_date.is_some());
        assert!(converted.updated_date.is_some());
    }
}
