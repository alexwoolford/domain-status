//! WHOIS data insertion.

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;

/// Inserts WHOIS data into the database.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - Foreign key to url_status.id
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

    // Serialize status and nameservers to JSON
    let status_json = whois
        .status
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap_or_default());
    let nameservers_json = whois
        .nameservers
        .as_ref()
        .map(|n| serde_json::to_string(n).unwrap_or_default());

    sqlx::query(
        "INSERT INTO url_whois (
            url_status_id, creation_date, expiration_date, updated_date,
            registrar, registrant_country, registrant_org, status, nameservers, raw_text
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(url_status_id) DO UPDATE SET
            creation_date=excluded.creation_date,
            expiration_date=excluded.expiration_date,
            updated_date=excluded.updated_date,
            registrar=excluded.registrar,
            registrant_country=excluded.registrant_country,
            registrant_org=excluded.registrant_org,
            status=excluded.status,
            nameservers=excluded.nameservers,
            raw_text=excluded.raw_text",
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
}

