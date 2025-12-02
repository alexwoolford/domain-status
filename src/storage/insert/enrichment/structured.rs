//! Structured data insertion.

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;

/// Inserts structured data (JSON-LD, Open Graph, Twitter Cards, Schema.org) into the database.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - Foreign key to url_status.id
/// * `structured_data` - Structured data extracted from HTML
pub async fn insert_structured_data(
    pool: &SqlitePool,
    url_status_id: i64,
    structured_data: &crate::parse::StructuredData,
) -> Result<(), DatabaseError> {
    // Insert JSON-LD scripts
    for json_ld_value in &structured_data.json_ld {
        let json_str = serde_json::to_string(json_ld_value).map_err(|e| {
            DatabaseError::SqlError(sqlx::Error::Protocol(format!(
                "Failed to serialize JSON-LD: {}",
                e
            )))
        })?;

        sqlx::query(
            "INSERT INTO url_structured_data (url_status_id, data_type, property_name, property_value)
             VALUES (?, 'json_ld', '', ?)",
        )
        .bind(url_status_id)
        .bind(json_str)
        .execute(pool)
        .await
        .map_err(DatabaseError::from)?;
    }

    // Insert Open Graph tags
    for (property, value) in &structured_data.open_graph {
        sqlx::query(
            "INSERT INTO url_structured_data (url_status_id, data_type, property_name, property_value)
             VALUES (?, 'open_graph', ?, ?)",
        )
        .bind(url_status_id)
        .bind(property)
        .bind(value)
        .execute(pool)
        .await
        .map_err(DatabaseError::from)?;
    }

    // Insert Twitter Card tags
    for (name, value) in &structured_data.twitter_cards {
        sqlx::query(
            "INSERT INTO url_structured_data (url_status_id, data_type, property_name, property_value)
             VALUES (?, 'twitter_card', ?, ?)",
        )
        .bind(url_status_id)
        .bind(name)
        .bind(value)
        .execute(pool)
        .await
        .map_err(DatabaseError::from)?;
    }

    // Insert Schema.org types
    for schema_type in &structured_data.schema_types {
        sqlx::query(
            "INSERT INTO url_structured_data (url_status_id, data_type, property_name, property_value)
             VALUES (?, 'schema_type', ?, '')",
        )
        .bind(url_status_id)
        .bind(schema_type)
        .execute(pool)
        .await
        .map_err(DatabaseError::from)?;
    }

    Ok(())
}

