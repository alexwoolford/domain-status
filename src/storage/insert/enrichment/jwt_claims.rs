//! JWT claims insertion.

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;
use crate::parse::jwt::DecodedJwt;
use crate::storage::insert::retry::with_sqlite_retry;

/// Inserts decoded JWT claims for an exposed secret.
pub async fn insert_jwt_claims(
    pool: &SqlitePool,
    exposed_secret_id: i64,
    jwt: &DecodedJwt,
) -> Result<(), DatabaseError> {
    with_sqlite_retry(|| async {
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
        .execute(pool)
        .await
        .map_err(DatabaseError::SqlError)?;
        Ok(())
    })
    .await
}
