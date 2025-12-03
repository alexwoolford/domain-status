//! Security warnings insertion.

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;

/// Inserts security warnings into the database.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - Foreign key to url_status.id
/// * `warnings` - Vector of security warnings
pub async fn insert_security_warnings(
    pool: &SqlitePool,
    url_status_id: i64,
    warnings: &[crate::security::SecurityWarning],
) -> Result<(), DatabaseError> {
    for warning in warnings {
        if let Err(e) = sqlx::query(
            "INSERT INTO url_security_warnings (url_status_id, warning_code, warning_description)
             VALUES (?, ?, ?)
             ON CONFLICT(url_status_id, warning_code) DO UPDATE SET
             warning_description=excluded.warning_description",
        )
        .bind(url_status_id)
        .bind(warning.code())
        .bind(warning.description())
        .execute(pool)
        .await
        {
            log::warn!(
                "Failed to insert security warning {} for url_status_id {}: {}",
                warning.code(),
                url_status_id,
                e
            );
        }
    }

    Ok(())
}
