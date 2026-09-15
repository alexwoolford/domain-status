//! JWT claims insertion.

use sqlx::{Sqlite, Transaction};

use crate::error_handling::DatabaseError;
use crate::parse::jwt::DecodedJwt;

pub(crate) async fn insert_jwt_claims_batch_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    items: &[(i64, &DecodedJwt)],
) -> Result<(), DatabaseError> {
    for (exposed_secret_id, jwt) in items {
        sqlx::query(
            "INSERT INTO url_jwt_claims (
                    exposed_secret_id, header_json, payload_json,
                    algorithm, token_type, issuer, subject, audience,
                    expiration_ms, issued_at_ms, not_before_ms, jwt_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(exposed_secret_id) DO UPDATE SET
                    header_json=excluded.header_json,
                    payload_json=excluded.payload_json,
                    algorithm=excluded.algorithm,
                    token_type=excluded.token_type,
                    issuer=excluded.issuer,
                    subject=excluded.subject,
                    audience=excluded.audience,
                    expiration_ms=excluded.expiration_ms,
                    issued_at_ms=excluded.issued_at_ms,
                    not_before_ms=excluded.not_before_ms,
                    jwt_id=excluded.jwt_id",
        )
        .bind(exposed_secret_id)
        .bind(&jwt.header_json)
        .bind(&jwt.payload_json)
        .bind(&jwt.algorithm)
        .bind(&jwt.token_type)
        .bind(&jwt.issuer)
        .bind(&jwt.subject)
        .bind(&jwt.audience)
        .bind(jwt.expiration_ms)
        .bind(jwt.issued_at_ms)
        .bind(jwt.not_before_ms)
        .bind(&jwt.jwt_id)
        .execute(&mut **tx)
        .await
        .map_err(DatabaseError::SqlError)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{ExposedSecret, SecretSeverity};
    use crate::storage::insert::enrichment::{commit_in_tx, insert_exposed_secrets_in_tx};
    use crate::storage::test_helpers::{create_test_pool, create_test_url_status_default};

    #[tokio::test]
    async fn test_insert_jwt_claims_batch_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;
        let jwt = crate::parse::jwt::DecodedJwt {
            header_json: r#"{"alg":"none"}"#.to_string(),
            payload_json: r#"{"sub":"1"}"#.to_string(),
            algorithm: Some("none".to_string()),
            token_type: Some("JWT".to_string()),
            issuer: None,
            subject: Some("1".to_string()),
            audience: None,
            expiration_ms: None,
            issued_at_ms: None,
            not_before_ms: None,
            jwt_id: None,
        };
        let secrets = [ExposedSecret {
            secret_type: "jwt".to_string(),
            matched_value: "a.b.c".to_string(),
            context: "token".to_string(),
            severity: SecretSeverity::Medium,
            location: std::borrow::Cow::Borrowed("inline_script"),
            decoded_jwt: Some(jwt.clone()),
        }];
        let ids = commit_in_tx!(&pool, |tx| {
            insert_exposed_secrets_in_tx(&mut tx, url_status_id, &secrets).await
        })
        .expect("insert secret");
        commit_in_tx!(&pool, |tx| {
            insert_jwt_claims_batch_in_tx(&mut tx, &[(ids[0], &jwt)]).await
        })
        .expect("insert jwt claims");

        let algorithm: Option<String> =
            sqlx::query_scalar("SELECT algorithm FROM url_jwt_claims WHERE exposed_secret_id = ?")
                .bind(ids[0])
                .fetch_one(&pool)
                .await
                .expect("fetch jwt");
        assert_eq!(algorithm.as_deref(), Some("none"));
    }
}
