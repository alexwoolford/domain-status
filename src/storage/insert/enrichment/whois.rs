//! WHOIS data insertion.

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;
use crate::storage::insert::retry::with_sqlite_retry;

/// Inserts WHOIS data into the database.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - Foreign key to `url_status.id`
/// * `whois` - WHOIS lookup result
pub async fn insert_whois_data(
    pool: &SqlitePool,
    url_status_id: i64,
    whois: &crate::whois::WhoisResult,
) -> Result<(), DatabaseError> {
    // Convert DateTime<Utc> to milliseconds since Unix epoch
    let creation_date_ms = whois.creation_date.map(|dt| dt.timestamp_millis());
    let expiration_date_ms = whois.expiration_date.map(|dt| dt.timestamp_millis());
    let updated_date_ms = whois.updated_date.map(|dt| dt.timestamp_millis());

    // Serialize status and nameservers to JSON.
    //
    // The in-memory API uses `Vec<String>` (possibly empty); on disk we keep
    // the "missing-vs-present" distinction by writing NULL when the vector is
    // empty rather than the empty-array literal `[]`. That preserves the
    // semantics existing exports rely on (`status_json IS NULL` means "lookup
    // returned no statuses" — same as before the API simplified).
    //
    // `serde_json::to_string` of `Vec<String>` cannot fail in practice (no
    // custom Serialize impls in the chain), but the previous `unwrap_or_default()`
    // would silently write an empty string ("") into the column on any future
    // bug, indistinguishable from a real empty list. Log + write NULL instead
    // so any regression is visible.
    fn vec_to_json_or_null(column: &str, url_status_id: i64, v: &[String]) -> Option<String> {
        if v.is_empty() {
            return None;
        }
        match serde_json::to_string(v) {
            Ok(json) => Some(json),
            Err(e) => {
                log::warn!(
                    "BUG: failed to serialize whois.{column} as JSON for url_status_id={url_status_id}: {e}; storing NULL"
                );
                None
            }
        }
    }
    let status_json = vec_to_json_or_null("status", url_status_id, &whois.status);
    let nameservers_json = vec_to_json_or_null("nameservers", url_status_id, &whois.nameservers);

    with_sqlite_retry(|| async {
        sqlx::query(
            "INSERT INTO url_whois (
                url_status_id, creation_date_ms, expiration_date_ms, updated_date_ms,
                registrar, registrant_country, registrant_org, whois_statuses, nameservers_json, raw_response
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(url_status_id) DO UPDATE SET
                creation_date_ms=excluded.creation_date_ms,
                expiration_date_ms=excluded.expiration_date_ms,
                updated_date_ms=excluded.updated_date_ms,
                registrar=excluded.registrar,
                registrant_country=excluded.registrant_country,
                registrant_org=excluded.registrant_org,
                whois_statuses=excluded.whois_statuses,
                nameservers_json=excluded.nameservers_json,
                raw_response=excluded.raw_response",
        )
        .bind(url_status_id)
        .bind(creation_date_ms)
        .bind(expiration_date_ms)
        .bind(updated_date_ms)
        .bind(&whois.registrar)
        .bind(&whois.registrant_country)
        .bind(&whois.registrant_org)
        .bind(&status_json)
        .bind(&nameservers_json)
        .bind(&whois.raw_text)
        .execute(pool)
        .await
        .map_err(DatabaseError::SqlError)?;

        Ok(())
    })
    .await
}
