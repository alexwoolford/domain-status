//! Structured data insertion.

use sqlx::{Sqlite, SqlitePool, Transaction};

use crate::error_handling::DatabaseError;
use crate::storage::insert::retry::with_sqlite_retry;
use crate::storage::insert::utils::build_batch_insert_query;

async fn insert_structured_rows(
    tx: &mut Transaction<'_, Sqlite>,
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
    let mut query_builder = crate::sql::query(query);
    for (property_name, property_value) in rows {
        query_builder = query_builder
            .bind(url_status_id)
            .bind(data_type)
            .bind(property_name)
            .bind(property_value);
    }
    query_builder
        .execute(&mut **tx)
        .await
        .map_err(DatabaseError::from)?;
    Ok(())
}

/// Inserts structured data (JSON-LD, Open Graph, Twitter Cards, Schema.org) into the database.
#[cfg_attr(not(test), allow(dead_code))] // Unit tests use the pool wrapper; production uses `_in_tx`.
pub async fn insert_structured_data(
    pool: &SqlitePool,
    url_status_id: i64,
    structured_data: &crate::parse::StructuredData,
) -> Result<(), DatabaseError> {
    with_sqlite_retry(|| async {
        let mut tx = pool.begin().await.map_err(DatabaseError::SqlError)?;
        insert_structured_data_in_tx(&mut tx, url_status_id, structured_data).await?;
        tx.commit().await.map_err(DatabaseError::SqlError)?;
        Ok(())
    })
    .await
}

pub(crate) async fn insert_structured_data_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    structured_data: &crate::parse::StructuredData,
) -> Result<(), DatabaseError> {
    let mut json_ld_rows = Vec::with_capacity(structured_data.json_ld.len());
    for json_ld_value in &structured_data.json_ld {
        let json_str = serde_json::to_string(json_ld_value).map_err(|e| {
            DatabaseError::SqlError(sqlx::Error::Protocol(format!(
                "Failed to serialize JSON-LD: {e}"
            )))
        })?;
        json_ld_rows.push(("@document".to_string(), json_str));
    }
    insert_structured_rows(tx, url_status_id, "json_ld", &json_ld_rows).await?;

    let og_rows: Vec<(String, String)> = structured_data
        .open_graph
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    insert_structured_rows(tx, url_status_id, "open_graph", &og_rows).await?;

    let tw_rows: Vec<(String, String)> = structured_data
        .twitter_cards
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    insert_structured_rows(tx, url_status_id, "twitter_card", &tw_rows).await?;

    let schema_rows: Vec<(String, String)> = structured_data
        .schema_types
        .iter()
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .map(|t| (t.to_string(), String::new()))
        .collect();
    insert_structured_rows(tx, url_status_id, "schema_type", &schema_rows).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::StructuredData;
    use crate::storage::test_helpers::{create_test_pool, create_test_url_status_default};
    use sqlx::Row;

    #[tokio::test]
    async fn test_insert_structured_data_skips_empty_schema_type() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;
        let structured_data = StructuredData {
            schema_types: vec![String::new(), "  ".to_string(), "WebPage".to_string()],
            ..StructuredData::default()
        };

        insert_structured_data(&pool, url_status_id, &structured_data)
            .await
            .expect("insert structured data");

        let rows = sqlx::query(
            "SELECT property_name FROM url_structured_data
             WHERE url_status_id = ? AND data_type = 'schema_type'",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("fetch schema_type rows");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get::<String, _>("property_name"), "WebPage");
    }

    #[tokio::test]
    async fn test_insert_json_ld_uses_document_property_name() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;
        let document = serde_json::json!({"@type": "WebPage", "name": "Example"});
        let structured_data = StructuredData {
            json_ld: vec![document.clone()],
            ..StructuredData::default()
        };

        insert_structured_data(&pool, url_status_id, &structured_data)
            .await
            .expect("insert structured data");

        let row = sqlx::query(
            "SELECT property_name, property_value FROM url_structured_data
             WHERE url_status_id = ? AND data_type = 'json_ld'",
        )
        .bind(url_status_id)
        .fetch_one(&pool)
        .await
        .expect("fetch json_ld row");

        assert_eq!(row.get::<String, _>("property_name"), "@document");
        assert_eq!(
            row.get::<String, _>("property_value"),
            serde_json::to_string(&document).expect("serialize fixture")
        );
    }
}
