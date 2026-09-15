//! Favicon data insertion.

use sqlx::{Sqlite, Transaction};

use crate::error_handling::DatabaseError;
use crate::fetch::favicon::FaviconData;

pub(crate) async fn insert_favicon_data_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    favicon: &FaviconData,
) -> Result<(), DatabaseError> {
    sqlx::query(
        "INSERT INTO url_favicons (url_status_id, favicon_url, hash)
             VALUES (?, ?, ?)
             ON CONFLICT(url_status_id) DO UPDATE SET
                favicon_url=excluded.favicon_url,
                hash=excluded.hash",
    )
    .bind(url_status_id)
    .bind(&favicon.favicon_url)
    .bind(favicon.hash)
    .execute(&mut **tx)
    .await
    .map_err(DatabaseError::SqlError)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;

    use crate::storage::insert::enrichment::commit_in_tx;
    use crate::storage::test_helpers::{create_test_pool, create_test_url_status_default};

    fn create_test_favicon() -> FaviconData {
        FaviconData {
            favicon_url: "https://example.com/favicon.ico".to_string(),
            hash: -123456789,
        }
    }

    #[tokio::test]
    async fn test_insert_favicon_data_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;
        let favicon = create_test_favicon();

        let result = commit_in_tx!(&pool, |tx| {
            insert_favicon_data_in_tx(&mut tx, url_status_id, &favicon).await
        });
        assert!(result.is_ok());

        let row = sqlx::query("SELECT favicon_url, hash FROM url_favicons WHERE url_status_id = ?")
            .bind(url_status_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch favicon data");

        assert_eq!(
            row.get::<String, _>("favicon_url"),
            "https://example.com/favicon.ico"
        );
        assert_eq!(row.get::<i32, _>("hash"), -123456789);
    }

    #[tokio::test]
    async fn test_insert_favicon_data_upsert() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;
        let mut favicon = create_test_favicon();

        let result1 = commit_in_tx!(&pool, |tx| {
            insert_favicon_data_in_tx(&mut tx, url_status_id, &favicon).await
        });
        assert!(result1.is_ok());

        favicon.hash = 999;
        favicon.favicon_url = "https://example.com/new-icon.png".to_string();
        let result2 = commit_in_tx!(&pool, |tx| {
            insert_favicon_data_in_tx(&mut tx, url_status_id, &favicon).await
        });
        assert!(result2.is_ok());

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_favicons WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count favicon records");
        assert_eq!(count, 1);

        let row = sqlx::query("SELECT hash FROM url_favicons WHERE url_status_id = ?")
            .bind(url_status_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch updated favicon data");
        assert_eq!(row.get::<i32, _>("hash"), 999);
    }
}
