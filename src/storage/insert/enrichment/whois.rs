//! WHOIS data insertion.

use sqlx::{Sqlite, Transaction};

use crate::error_handling::DatabaseError;

pub(crate) async fn insert_whois_data_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    whois: &crate::whois::WhoisResult,
) -> Result<(), DatabaseError> {
    let creation_date_ms = whois.creation_date.map(|dt| dt.timestamp_millis());
    let expiration_date_ms = whois.expiration_date.map(|dt| dt.timestamp_millis());
    let updated_date_ms = whois.updated_date.map(|dt| dt.timestamp_millis());

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
    .execute(&mut **tx)
    .await
    .map_err(DatabaseError::SqlError)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::insert::enrichment::commit_in_tx;
    use crate::storage::test_helpers::{create_test_pool, create_test_url_status_default};
    use crate::whois::WhoisResult;
    use sqlx::Row;

    #[tokio::test]
    async fn test_insert_whois_data_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;
        let whois = WhoisResult {
            registrar: Some("Example Registrar".to_string()),
            registrant_country: Some("US".to_string()),
            registrant_org: Some("Example Org".to_string()),
            raw_text: Some("raw whois".to_string()),
            ..WhoisResult::default()
        };

        commit_in_tx!(&pool, |tx| {
            insert_whois_data_in_tx(&mut tx, url_status_id, &whois).await
        })
        .expect("insert whois");

        let row = sqlx::query(
            "SELECT registrar, registrant_country, registrant_org, raw_response
             FROM url_whois WHERE url_status_id = ?",
        )
        .bind(url_status_id)
        .fetch_one(&pool)
        .await
        .expect("fetch whois");

        assert_eq!(
            row.get::<Option<String>, _>("registrar"),
            Some("Example Registrar".to_string())
        );
        assert_eq!(
            row.get::<Option<String>, _>("registrant_org"),
            Some("Example Org".to_string())
        );
        assert_eq!(
            row.get::<Option<String>, _>("raw_response"),
            Some("raw whois".to_string())
        );
    }
}
