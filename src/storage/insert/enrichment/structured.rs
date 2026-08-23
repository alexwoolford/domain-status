//! Structured data insertion.

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;
use crate::storage::insert::retry::with_sqlite_retry;
use crate::storage::insert::utils::build_batch_insert_query;

/// Inserts rows into `url_structured_data` for a single `data_type`.
async fn insert_structured_rows(
    pool: &SqlitePool,
    url_status_id: i64,
    data_type: &str,
    rows: &[(String, String)],
) -> Result<(), DatabaseError> {
    if rows.is_empty() {
        return Ok(());
    }

    let query = build_batch_insert_query(
        "url_structured_data",
        &[
            "url_status_id",
            "data_type",
            "property_name",
            "property_value",
        ],
        rows.len(),
        Some("ON CONFLICT(url_status_id, data_type, property_name, property_value) DO NOTHING"),
    );
    let mut query_builder = sqlx::query(&query);
    for (property_name, property_value) in rows {
        query_builder = query_builder
            .bind(url_status_id)
            .bind(data_type)
            .bind(property_name)
            .bind(property_value);
    }
    query_builder
        .execute(pool)
        .await
        .map_err(DatabaseError::from)?;
    Ok(())
}

/// Inserts structured data (JSON-LD, Open Graph, Twitter Cards, Schema.org) into the database.
pub async fn insert_structured_data(
    pool: &SqlitePool,
    url_status_id: i64,
    structured_data: &crate::parse::StructuredData,
) -> Result<(), DatabaseError> {
    with_sqlite_retry(|| async {
        let mut json_ld_rows = Vec::with_capacity(structured_data.json_ld.len());
        for json_ld_value in &structured_data.json_ld {
            let json_str = serde_json::to_string(json_ld_value).map_err(|e| {
                DatabaseError::SqlError(sqlx::Error::Protocol(format!(
                    "Failed to serialize JSON-LD: {e}"
                )))
            })?;
            json_ld_rows.push((String::new(), json_str));
        }
        insert_structured_rows(pool, url_status_id, "json_ld", &json_ld_rows).await?;

        let og_rows: Vec<(String, String)> = structured_data
            .open_graph
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        insert_structured_rows(pool, url_status_id, "open_graph", &og_rows).await?;

        let tw_rows: Vec<(String, String)> = structured_data
            .twitter_cards
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        insert_structured_rows(pool, url_status_id, "twitter_card", &tw_rows).await?;

        let schema_rows: Vec<(String, String)> = structured_data
            .schema_types
            .iter()
            .map(|t| (t.clone(), String::new()))
            .collect();
        insert_structured_rows(pool, url_status_id, "schema_type", &schema_rows).await?;

        Ok(())
    })
    .await
}
