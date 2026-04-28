//! JWT claims insertion.

use sqlx::{Acquire, SqlitePool};

use crate::error_handling::DatabaseError;
use crate::parse::jwt::DecodedJwt;
use crate::storage::insert::retry::with_sqlite_retry;

/// Inserts a batch of decoded JWT claims in a single transaction.
///
/// Each item is `(exposed_secret_id, &DecodedJwt)`. With the older one-call-per-JWT
/// path, a page with several JWTs incurred one fsync per JWT; this variant
/// commits once for the whole batch.
pub async fn insert_jwt_claims_batch(
    pool: &SqlitePool,
    items: &[(i64, &DecodedJwt)],
) -> Result<(), DatabaseError> {
    if items.is_empty() {
        return Ok(());
    }
    with_sqlite_retry(|| async {
        let mut conn = pool.acquire().await.map_err(DatabaseError::SqlError)?;
        let mut tx = conn.begin().await.map_err(DatabaseError::SqlError)?;
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
            .execute(&mut *tx)
            .await
            .map_err(DatabaseError::SqlError)?;
        }
        tx.commit().await.map_err(DatabaseError::SqlError)?;
        Ok(())
    })
    .await
}
