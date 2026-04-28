//! Exposed secret insertion.

use sqlx::{Acquire, SqlitePool};

use crate::error_handling::DatabaseError;
use crate::parse::ExposedSecret;
use crate::storage::insert::retry::with_sqlite_retry;

/// Inserts detected exposed secrets and returns their database row IDs.
///
/// All inserts are wrapped in a single transaction so that a noisy page (a
/// hundred `generic-api-key` matches) commits with one fsync rather than N.
/// The returned IDs correspond 1:1 with the input `secrets` slice.
pub async fn insert_exposed_secrets(
    pool: &SqlitePool,
    url_status_id: i64,
    secrets: &[ExposedSecret],
) -> Result<Vec<i64>, DatabaseError> {
    if secrets.is_empty() {
        return Ok(Vec::new());
    }
    with_sqlite_retry(|| async {
        let mut conn = pool.acquire().await.map_err(DatabaseError::SqlError)?;
        let mut tx = conn.begin().await.map_err(DatabaseError::SqlError)?;
        let mut ids = Vec::with_capacity(secrets.len());
        for secret in secrets {
            let row: (i64,) = sqlx::query_as(
                "INSERT INTO url_exposed_secrets (url_status_id, secret_type, matched_value, severity, location, context)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON CONFLICT(url_status_id, secret_type, matched_value) DO UPDATE SET
                 severity=excluded.severity, location=excluded.location, context=excluded.context
                 RETURNING id",
            )
            .bind(url_status_id)
            .bind(&secret.secret_type)
            .bind(&secret.matched_value)
            .bind(secret.severity.as_str())
            .bind(secret.location.as_ref())
            .bind(&secret.context)
            .fetch_one(&mut *tx)
            .await
            .map_err(DatabaseError::SqlError)?;
            ids.push(row.0);
        }
        tx.commit().await.map_err(DatabaseError::SqlError)?;
        Ok(ids)
    })
    .await
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
            location: std::borrow::Cow::Borrowed("inline_script"),
            decoded_jwt: None,
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
                location: std::borrow::Cow::Borrowed("html_body"),
                decoded_jwt: None,
            },
            ExposedSecret {
                secret_type: "gcp-api-key".to_string(),
                matched_value: "AIzaSyA1234567890abcdefghijklmnopqrstuv".to_string(),
                context: "context2".to_string(),
                severity: SecretSeverity::Medium,
                location: std::borrow::Cow::Borrowed("html_body"),
                decoded_jwt: None,
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
            location: std::borrow::Cow::Borrowed("html_body"),
            decoded_jwt: None,
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
            location: std::borrow::Cow::Borrowed("html_body"),
            decoded_jwt: None,
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

    /// Critical regression for the H-3 transactional batch insert: if any
    /// INSERT inside the batch fails (FK violation, NOT NULL, etc.), the
    /// whole batch must roll back so we never leave half-written rows in
    /// the table. A naive implementation that committed each INSERT
    /// individually would leave the secrets *before* the failure point in
    /// the DB; the new tx-wrapped version must not.
    ///
    /// We enable FK enforcement on the test pool (production has it via
    /// `pragma("foreign_keys", "ON")` in `pool.rs`; the in-memory test pool
    /// uses `SQLite` defaults which are FK=OFF). With FKs on, a bogus
    /// `url_status_id` triggers an `SQLITE_CONSTRAINT_FOREIGNKEY` error.
    #[tokio::test]
    async fn test_insert_exposed_secrets_rolls_back_on_constraint_violation() {
        let pool = create_test_pool().await;
        // Enable FK enforcement for this test pool (in-memory pools default off).
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .expect("enable FKs");

        // First, do a SUCCESSFUL batch insert against a valid url_status_id
        // so the table has known good rows before the failing batch runs.
        let good_url_status_id = create_test_url_status_default(&pool).await;
        let pre_insert = vec![ExposedSecret {
            secret_type: "aws-access-token".to_string(),
            matched_value: "AKIAIOSFODNN7PRESET1".to_string(),
            context: "pre-existing row".to_string(),
            severity: SecretSeverity::High,
            location: std::borrow::Cow::Borrowed("html_body"),
            decoded_jwt: None,
        }];
        insert_exposed_secrets(&pool, good_url_status_id, &pre_insert)
            .await
            .expect("pre-insert succeeds");

        // Now run a FAILING batch: 3 secrets, all targeting a non-existent
        // url_status_id. The first will succeed at the per-row level inside
        // the tx, but the tx must roll back when commit hits the FK check
        // (or earlier if SQLite catches it on the INSERT itself).
        let nonexistent_id: i64 = 9_999_999;
        let failing_batch = vec![
            ExposedSecret {
                secret_type: "aws-access-token".to_string(),
                matched_value: "AKIAIOSFODNN7BAD0001".to_string(),
                context: "should not land".to_string(),
                severity: SecretSeverity::High,
                location: std::borrow::Cow::Borrowed("html_body"),
                decoded_jwt: None,
            },
            ExposedSecret {
                secret_type: "aws-access-token".to_string(),
                matched_value: "AKIAIOSFODNN7BAD0002".to_string(),
                context: "should not land".to_string(),
                severity: SecretSeverity::High,
                location: std::borrow::Cow::Borrowed("html_body"),
                decoded_jwt: None,
            },
            ExposedSecret {
                secret_type: "aws-access-token".to_string(),
                matched_value: "AKIAIOSFODNN7BAD0003".to_string(),
                context: "should not land".to_string(),
                severity: SecretSeverity::High,
                location: std::borrow::Cow::Borrowed("html_body"),
                decoded_jwt: None,
            },
        ];
        let result = insert_exposed_secrets(&pool, nonexistent_id, &failing_batch).await;
        assert!(
            result.is_err(),
            "FK violation must surface as Err, got {result:?}"
        );

        // The atomicity guarantee: NONE of the failing batch's matched_values
        // appear, AND the pre-existing row is still there.
        let bad_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM url_exposed_secrets WHERE matched_value LIKE 'AKIAIOSFODNN7BAD%'",
        )
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(
            bad_count, 0,
            "transaction must roll back on FK violation - no bad rows allowed"
        );

        let preset_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM url_exposed_secrets WHERE matched_value = 'AKIAIOSFODNN7PRESET1'",
        )
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(
            preset_count, 1,
            "pre-existing committed row must remain after the failing batch"
        );
    }

    /// Regression: `ExposedSecret.location` is `Cow<'static, str>` (since L-3).
    /// Both branches - `Cow::Borrowed("static-literal")` from the regular
    /// detector AND `Cow::Owned(format!("external_script:{url}"))` from the
    /// external-script scanner - must round-trip through sqlx as the exact
    /// same string we wrote. A bug here (deref to wrong type, accidental
    /// `to_string` of a placeholder, etc.) would produce silent data corruption:
    /// every external-script finding's location would be wrong.
    #[tokio::test]
    async fn test_insert_exposed_secrets_cow_location_round_trip() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        // Mix of borrowed (static) and owned (dynamic) Cow variants to
        // exercise both deref paths through sqlx::Bind.
        let dynamic_loc: std::borrow::Cow<'static, str> =
            std::borrow::Cow::Owned("external_script:https://cdn.example.com/app.js".to_string());
        let static_loc: std::borrow::Cow<'static, str> =
            std::borrow::Cow::Borrowed("inline_script");
        let empty_loc: std::borrow::Cow<'static, str> = std::borrow::Cow::Borrowed("");
        let unicode_loc: std::borrow::Cow<'static, str> =
            std::borrow::Cow::Owned("html_body:\u{1f512}".to_string());

        let secrets = vec![
            ExposedSecret {
                secret_type: "aws-access-token".to_string(),
                matched_value: "AKIAIOSFODNN7EXAMPL1".to_string(),
                context: "ctx1".to_string(),
                severity: SecretSeverity::High,
                location: dynamic_loc.clone(),
                decoded_jwt: None,
            },
            ExposedSecret {
                secret_type: "aws-access-token".to_string(),
                matched_value: "AKIAIOSFODNN7EXAMPL2".to_string(),
                context: "ctx2".to_string(),
                severity: SecretSeverity::High,
                location: static_loc.clone(),
                decoded_jwt: None,
            },
            ExposedSecret {
                secret_type: "aws-access-token".to_string(),
                matched_value: "AKIAIOSFODNN7EXAMPL3".to_string(),
                context: "ctx3".to_string(),
                severity: SecretSeverity::High,
                location: empty_loc.clone(),
                decoded_jwt: None,
            },
            ExposedSecret {
                secret_type: "aws-access-token".to_string(),
                matched_value: "AKIAIOSFODNN7EXAMPL4".to_string(),
                context: "ctx4".to_string(),
                severity: SecretSeverity::High,
                location: unicode_loc.clone(),
                decoded_jwt: None,
            },
        ];

        insert_exposed_secrets(&pool, url_status_id, &secrets)
            .await
            .expect("insert");

        let rows = sqlx::query(
            "SELECT matched_value, location FROM url_exposed_secrets WHERE url_status_id = ? ORDER BY matched_value",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("read-back");

        assert_eq!(rows.len(), 4, "all four secrets must be stored");

        // Map matched_value -> stored location for explicit per-row checks.
        let by_match: std::collections::HashMap<String, String> = rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("matched_value"),
                    r.get::<String, _>("location"),
                )
            })
            .collect();
        assert_eq!(
            by_match["AKIAIOSFODNN7EXAMPL1"],
            "external_script:https://cdn.example.com/app.js"
        );
        assert_eq!(by_match["AKIAIOSFODNN7EXAMPL2"], "inline_script");
        assert_eq!(by_match["AKIAIOSFODNN7EXAMPL3"], "");
        assert_eq!(by_match["AKIAIOSFODNN7EXAMPL4"], "html_body:\u{1f512}");
    }
}
