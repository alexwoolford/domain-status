//! Exposed secret insertion.

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;
use crate::parse::ExposedSecret;

/// Inserts detected exposed secrets into the database.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - Foreign key to `url_status.id`
/// * `secrets` - Vector of exposed secrets detected in HTML
pub async fn insert_exposed_secrets(
    pool: &SqlitePool,
    url_status_id: i64,
    secrets: &[ExposedSecret],
) -> Result<(), DatabaseError> {
    for secret in secrets {
        if let Err(e) = sqlx::query(
            "INSERT INTO url_exposed_secrets (url_status_id, secret_type, matched_value, severity, location, context)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(url_status_id, secret_type, matched_value) DO UPDATE SET
             severity=excluded.severity, location=excluded.location, context=excluded.context",
        )
        .bind(url_status_id)
        .bind(&secret.secret_type)
        .bind(&secret.matched_value)
        .bind(secret.severity.as_str())
        .bind(&secret.location)
        .bind(&secret.context)
        .execute(pool)
        .await
        {
            log::warn!(
                "Failed to insert exposed secret ({}) for url_status_id {}: {}",
                secret.secret_type,
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
    use crate::parse::{ExposedSecret, SecretSeverity};
    use sqlx::Row;

    use crate::storage::test_helpers::{create_test_pool, create_test_url_status_default};

    #[tokio::test]
    async fn test_insert_exposed_secrets_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let secrets = vec![ExposedSecret {
            secret_type: "aws-access-token".to_string(),
            matched_value: "AKIAIOSFODNN7EXAMPLE".to_string(),
            context: "var key = AKIAIOSFODNN7EXAMPLE;".to_string(),
            severity: SecretSeverity::High,
            location: "inline_script".to_string(),
        }];

        let result = insert_exposed_secrets(&pool, url_status_id, &secrets).await;
        assert!(result.is_ok());

        let rows = sqlx::query(
            "SELECT secret_type, matched_value, severity, location, context FROM url_exposed_secrets WHERE url_status_id = ?",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get::<String, _>("secret_type"), "aws-access-token");
        assert_eq!(
            rows[0].get::<String, _>("matched_value"),
            "AKIAIOSFODNN7EXAMPLE"
        );
        assert_eq!(rows[0].get::<String, _>("severity"), "high");
        assert_eq!(rows[0].get::<String, _>("location"), "inline_script");
        assert_eq!(
            rows[0].get::<String, _>("context"),
            "var key = AKIAIOSFODNN7EXAMPLE;"
        );
    }

    #[tokio::test]
    async fn test_insert_exposed_secrets_empty() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let result = insert_exposed_secrets(&pool, url_status_id, &[]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_insert_exposed_secrets_multiple() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let secrets = vec![
            ExposedSecret {
                secret_type: "aws-access-token".to_string(),
                matched_value: "AKIAIOSFODNN7EXAMPLE".to_string(),
                context: "context1".to_string(),
                severity: SecretSeverity::High,
                location: "html_body".to_string(),
            },
            ExposedSecret {
                secret_type: "gcp-api-key".to_string(),
                matched_value: "AIzaSyA1234567890abcdefghijklmnopqrstuv".to_string(),
                context: "context2".to_string(),
                severity: SecretSeverity::Medium,
                location: "html_body".to_string(),
            },
        ];

        insert_exposed_secrets(&pool, url_status_id, &secrets)
            .await
            .unwrap();

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_exposed_secrets WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn test_insert_exposed_secrets_upsert() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let secret = ExposedSecret {
            secret_type: "aws-access-token".to_string(),
            matched_value: "AKIAIOSFODNN7EXAMPLE".to_string(),
            context: "original context".to_string(),
            severity: SecretSeverity::High,
            location: "html_body".to_string(),
        };

        insert_exposed_secrets(&pool, url_status_id, &[secret])
            .await
            .unwrap();

        // Upsert with updated context
        let secret2 = ExposedSecret {
            secret_type: "aws-access-token".to_string(),
            matched_value: "AKIAIOSFODNN7EXAMPLE".to_string(),
            context: "updated context".to_string(),
            severity: SecretSeverity::High,
            location: "html_body".to_string(),
        };

        insert_exposed_secrets(&pool, url_status_id, &[secret2])
            .await
            .unwrap();

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_exposed_secrets WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        assert_eq!(count, 1);

        let row = sqlx::query("SELECT context FROM url_exposed_secrets WHERE url_status_id = ?")
            .bind(url_status_id)
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(row.get::<String, _>("context"), "updated context");
    }
}
