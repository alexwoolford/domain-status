//! Database migration management.
//!
//! This module handles `SQLx` migrations embedded into the binary at compile time.
//! Migrations are extracted to a temporary directory at runtime and then executed.
//! This ensures migrations work for distributed binaries without requiring the
//! migrations directory to be present alongside the executable.

use std::path::Path;

use include_dir::{include_dir, Dir};
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;

use crate::error_handling::MigrationError;

// Embed migrations directory into the binary at compile time
static MIGRATIONS_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/migrations");

/// Runs `SQLx` migrations embedded in the binary.
///
/// This function extracts embedded migrations to a temporary directory and runs them.
/// This ensures migrations are always available, even when the binary is distributed
/// without the migrations directory.
///
/// In development builds, it uses the source migrations directory directly (faster).
/// In distributed binaries, it extracts embedded migrations to a temp directory
/// (wrapped in `spawn_blocking` to avoid blocking the tokio runtime).
///
/// # Examples
///
/// ```no_run
/// use domain_status::{init_db_pool_with_path, run_migrations};
/// use std::path::Path;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let pool = init_db_pool_with_path(Path::new("./domain_status.db"), 5).await?;
/// run_migrations(&pool).await?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
/// Returns [`MigrationError`] with a typed variant identifying the failure
/// mode (`SQLx` migration error, on-disk extraction I/O failure, or panicked
/// background task). The underlying error is exposed via `#[source]` so
/// callers can walk `std::error::Error::source()` (or use `anyhow::chain`)
/// to inspect causes — no `anyhow::Error` is leaked across the public API.
pub async fn run_migrations(pool: &Pool<Sqlite>) -> Result<(), MigrationError> {
    let source_migrations = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    if source_migrations.exists() {
        run_migrations_from_dir(pool, &source_migrations).await
    } else {
        run_migrations_embedded(pool).await
    }
}

/// Writes compile-time embedded migration files into `dest`.
///
/// Used by the shipped binary (no source `migrations/` directory) and by tests
/// that force that path.
pub(crate) fn extract_embedded_migrations(dest: &Path) -> Result<(), MigrationError> {
    std::fs::create_dir_all(dest).map_err(|e| MigrationError::ExtractIo {
        context: format!("creating migrations directory at {}", dest.display()),
        source: e,
    })?;

    for file in MIGRATIONS_DIR.files() {
        let file_path = dest.join(file.path());
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| MigrationError::ExtractIo {
                context: format!("creating migration parent directory {}", parent.display()),
                source: e,
            })?;
        }
        std::fs::write(&file_path, file.contents()).map_err(|e| MigrationError::ExtractIo {
            context: format!("writing embedded migration {}", file_path.display()),
            source: e,
        })?;
    }
    Ok(())
}

/// Release-binary path: extract embedded SQL to a tempdir, then migrate.
pub(crate) async fn run_migrations_embedded(pool: &Pool<Sqlite>) -> Result<(), MigrationError> {
    let temp_dir = TempDir::new().map_err(|e| MigrationError::ExtractIo {
        context: "creating tempdir for embedded migrations".to_string(),
        source: e,
    })?;
    let migrations_path = temp_dir.path().join("migrations");
    let migrations_path_for_task = migrations_path.clone();
    tokio::task::spawn_blocking(move || extract_embedded_migrations(&migrations_path_for_task))
        .await??;
    run_migrations_from_dir(pool, &migrations_path).await
}

async fn run_migrations_from_dir(pool: &Pool<Sqlite>, dir: &Path) -> Result<(), MigrationError> {
    let migrator = sqlx::migrate::Migrator::new(dir).await?;
    migrator.run(pool).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;
    use tempfile::{NamedTempFile, TempDir};

    /// `run_migrations` now returns a typed [`MigrationError`] instead of
    /// `anyhow::Error`. This test asserts that downstream callers can
    /// pattern-match on the variant to branch on the failure mode (the
    /// previous opaque-anyhow shape made this impossible without parsing
    /// error message strings).
    #[test]
    fn test_migration_error_typed_variants_are_matchable() {
        // Construct each variant and confirm callers can match on them.
        // This is the very thing the previous `Result<(), anyhow::Error>`
        // signature blocked, and is the reason the public API was retyped.
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "fixture");
        let extract_err = MigrationError::ExtractIo {
            context: "creating tempdir".to_string(),
            source: io,
        };
        match &extract_err {
            MigrationError::ExtractIo { context, source } => {
                assert!(context.contains("tempdir"));
                assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected ExtractIo, got {other:?}"),
        }
        // Source chain must reach the underlying io::Error.
        let source = std::error::Error::source(&extract_err)
            .expect("ExtractIo must expose its underlying source");
        assert!(source.downcast_ref::<std::io::Error>().is_some());
    }

    /// Characterization: `is_ok` on the dev `migrations/` branch only.
    #[tokio::test]
    async fn test_run_migrations_success_with_memory_db() {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test pool");
        let result = run_migrations(&pool).await;
        assert!(
            result.is_ok(),
            "Migrations should succeed on fresh database"
        );
    }

    /// Characterization: `is_ok` on the dev `migrations/` branch only.
    #[tokio::test]
    async fn test_run_migrations_success_with_file_db() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let db_path = temp_file.path();
        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .expect("Failed to create test pool");
        let result = run_migrations(&pool).await;
        assert!(result.is_ok(), "Migrations should succeed on file database");
    }

    /// Characterization: `is_ok` twice on the dev `migrations/` branch only.
    #[tokio::test]
    async fn test_run_migrations_idempotency() {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test pool");
        let result1 = run_migrations(&pool).await;
        assert!(result1.is_ok(), "First migration run should succeed");
        let result2 = run_migrations(&pool).await;
        assert!(
            result2.is_ok(),
            "Second migration run should succeed (idempotent)"
        );
    }

    /// Characterization: `is_ok` on the dev `migrations/` branch only.
    #[tokio::test]
    async fn test_run_migrations_succeeds_on_fresh_pool() {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test pool");
        let result = run_migrations(&pool).await;
        assert!(
            result.is_ok(),
            "Migrations should succeed on fresh database"
        );
    }

    /// Keep [`DATABASE.md`](../../../DATABASE.md) migration range honest when
    /// new SQL files land under `migrations/`.
    #[test]
    fn database_md_documents_latest_migration_file() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut sql_names: Vec<String> = std::fs::read_dir(root.join("migrations"))
            .expect("migrations dir")
            .filter_map(Result::ok)
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                name.ends_with(".sql").then_some(name)
            })
            .collect();
        sql_names.sort();
        assert!(
            !sql_names.is_empty(),
            "expected at least one migration SQL file"
        );
        let latest = sql_names.last().expect("non-empty");
        let database_md =
            std::fs::read_to_string(root.join("DATABASE.md")).expect("read DATABASE.md");
        assert!(
            database_md.contains(latest),
            "DATABASE.md must mention the latest migration file `{latest}` (found {} migrations)",
            sql_names.len()
        );
        assert_eq!(
            sql_names.len(),
            16,
            "migration count changed — update DATABASE.md intro and this assertion"
        );
    }

    async fn table_names(pool: &SqlitePool) -> Vec<String> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
             ORDER BY name",
        )
        .fetch_all(pool)
        .await
        .expect("sqlite_master");
        rows.into_iter().map(|(n,)| n).collect()
    }

    async fn table_info(
        pool: &SqlitePool,
        table: &str,
    ) -> Vec<(i64, String, String, i64, Option<String>, i64)> {
        sqlx::query_as(
            r#"SELECT cid, name, type, "notnull", dflt_value, pk FROM pragma_table_info(?1)"#,
        )
        .bind(table)
        .fetch_all(pool)
        .await
        .unwrap_or_else(|e| panic!("PRAGMA table_info({table}): {e}"))
    }

    /// Kills: `extract_embedded_migrations` writing a different set of `.sql`
    /// files than the on-disk `migrations/` directory (count ≠ 16).
    #[test]
    fn test_extract_embedded_migrations_writes_sixteen_sql_files() {
        let dest = TempDir::new().expect("tempdir");
        extract_embedded_migrations(dest.path()).expect("extract");
        let mut sql_names: Vec<String> = std::fs::read_dir(dest.path())
            .expect("read dest")
            .filter_map(Result::ok)
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                name.ends_with(".sql").then_some(name)
            })
            .collect();
        sql_names.sort();
        assert_eq!(
            sql_names.len(),
            16,
            "embedded extract must write 16 SQL files, got {sql_names:?}"
        );
    }

    /// Kills: `run_migrations_embedded` applying a different schema than the
    /// on-disk `run_migrations` path (table set or `PRAGMA table_info`).
    #[tokio::test]
    async fn test_embedded_schema_matches_on_disk_migrations() {
        let on_disk = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("on-disk pool");
        run_migrations(&on_disk).await.expect("on-disk migrate");

        let embedded = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("embedded pool");
        run_migrations_embedded(&embedded)
            .await
            .expect("embedded migrate");

        let on_disk_tables = table_names(&on_disk).await;
        let embedded_tables = table_names(&embedded).await;
        assert_eq!(
            on_disk_tables, embedded_tables,
            "embedded extract must create the same tables as on-disk migrations"
        );
        for table in &on_disk_tables {
            assert_eq!(
                table_info(&on_disk, table).await,
                table_info(&embedded, table).await,
                "PRAGMA table_info mismatch for {table}"
            );
        }
    }

    /// Kills: `extract_embedded_migrations` returning `Ok` (or a non-`ExtractIo`
    /// error) when `dest` cannot be created because a parent path is a file.
    #[test]
    fn test_extract_embedded_migrations_unwritable_parent_is_extract_io() {
        let tmp = TempDir::new().expect("tempdir");
        let blocker = tmp.path().join("not_a_directory");
        std::fs::write(&blocker, b"x").expect("write blocker");
        let dest = blocker.join("migrations");
        let err = extract_embedded_migrations(&dest).expect_err("file-as-parent must fail");
        match err {
            MigrationError::ExtractIo { context, .. } => {
                assert!(
                    context.contains(&dest.display().to_string())
                        || context.contains(&blocker.display().to_string()),
                    "ExtractIo context must name the dest path, got: {context}"
                );
            }
            other => panic!("expected ExtractIo, got {other:?}"),
        }
    }

    /// Kills: mapping a panicked `spawn_blocking` join with `.unwrap()` instead
    /// of `?` into [`MigrationError::BlockingTask`].
    #[tokio::test]
    async fn test_spawn_blocking_panic_is_blocking_task() {
        let result: Result<(), MigrationError> = async {
            tokio::task::spawn_blocking(|| -> Result<(), MigrationError> {
                panic!("extract boom");
            })
            .await??;
            Ok(())
        }
        .await;
        assert!(
            matches!(result, Err(MigrationError::BlockingTask(_))),
            "panicked extract task must surface as BlockingTask, got: {result:?}"
        );
    }
}
