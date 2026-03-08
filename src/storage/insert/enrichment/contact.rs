//! Contact link insertion.

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;
use crate::parse::ContactLink;

/// Inserts contact links (mailto/tel) into the database.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - Foreign key to `url_status.id`
/// * `links` - Vector of contact links extracted from HTML
pub async fn insert_contact_links(
    pool: &SqlitePool,
    url_status_id: i64,
    links: &[ContactLink],
) -> Result<(), DatabaseError> {
    for link in links {
        if let Err(e) = sqlx::query(
            "INSERT INTO url_contact_links (url_status_id, contact_type, contact_value, raw_href)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(url_status_id, contact_type, contact_value) DO UPDATE SET
             raw_href=excluded.raw_href",
        )
        .bind(url_status_id)
        .bind(link.contact_type.as_str())
        .bind(&link.value)
        .bind(&link.raw_href)
        .execute(pool)
        .await
        {
            log::warn!(
                "Failed to insert contact link {} ({}) for url_status_id {}: {}",
                link.value,
                link.contact_type.as_str(),
                url_status_id,
                e
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{ContactLink, ContactType};
    use sqlx::Row;

    use crate::storage::test_helpers::{create_test_pool, create_test_url_status_default};

    #[tokio::test]
    async fn test_insert_contact_links_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let links = vec![
            ContactLink {
                contact_type: ContactType::Email,
                value: "info@example.com".to_string(),
                raw_href: "mailto:info@example.com".to_string(),
            },
            ContactLink {
                contact_type: ContactType::Phone,
                value: "+1-800-555-1234".to_string(),
                raw_href: "tel:+1-800-555-1234".to_string(),
            },
        ];

        let result = insert_contact_links(&pool, url_status_id, &links).await;
        assert!(result.is_ok());

        let rows = sqlx::query(
            "SELECT contact_type, contact_value, raw_href FROM url_contact_links WHERE url_status_id = ? ORDER BY contact_type",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch contact links");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<String, _>("contact_type"), "email");
        assert_eq!(
            rows[0].get::<String, _>("contact_value"),
            "info@example.com"
        );
        assert_eq!(rows[1].get::<String, _>("contact_type"), "phone");
    }

    #[tokio::test]
    async fn test_insert_contact_links_empty() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let result = insert_contact_links(&pool, url_status_id, &[]).await;
        assert!(result.is_ok());

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_contact_links WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count");

        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_insert_contact_links_upsert() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let link = ContactLink {
            contact_type: ContactType::Email,
            value: "info@example.com".to_string(),
            raw_href: "mailto:info@example.com".to_string(),
        };

        insert_contact_links(&pool, url_status_id, &[link])
            .await
            .unwrap();

        // Insert again with different raw_href (should upsert)
        let link2 = ContactLink {
            contact_type: ContactType::Email,
            value: "info@example.com".to_string(),
            raw_href: "mailto:info@example.com?subject=Hello".to_string(),
        };

        insert_contact_links(&pool, url_status_id, &[link2])
            .await
            .unwrap();

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_contact_links WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        assert_eq!(count, 1);

        let row = sqlx::query("SELECT raw_href FROM url_contact_links WHERE url_status_id = ?")
            .bind(url_status_id)
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(
            row.get::<String, _>("raw_href"),
            "mailto:info@example.com?subject=Hello"
        );
    }
}
