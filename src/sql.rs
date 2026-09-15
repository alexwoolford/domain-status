//! `SQLx` 0.9 wrappers around `sqlx::AssertSqlSafe` for dynamic SQL that is not `'static`.
//!
//! Identifiers come from compile-time table/column lists; values stay bind parameters.

use sqlx::AssertSqlSafe;

/// Query whose SQL string was built from trusted identifiers (not user input).
#[must_use = "the query does nothing unless executed"]
pub(crate) fn query(
    sql: impl Into<String>,
) -> sqlx::query::Query<'static, sqlx::Sqlite, sqlx::sqlite::SqliteArguments> {
    sqlx::query(AssertSqlSafe(sql.into()))
}

/// Scalar query whose SQL string was built from trusted identifiers (not user input).
#[must_use = "the query does nothing unless executed"]
pub(crate) fn query_scalar<O>(
    sql: impl Into<String>,
) -> sqlx::query::QueryScalar<'static, sqlx::Sqlite, O, sqlx::sqlite::SqliteArguments>
where
    (O,): for<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow>,
    O: Send + Unpin,
{
    sqlx::query_scalar(AssertSqlSafe(sql.into()))
}
