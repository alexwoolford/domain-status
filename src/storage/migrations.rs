//! Database migration management.
//!
//! This module handles `SQLx` migrations embedded into the binary at compile time.
//! Migrations are extracted to a temporary directory at runtime and then executed.
//! This ensures migrations work for distributed binaries without requiring the
//! migrations directory to be present alongside the executable.

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
    // In development, try to use the source migrations directory first (faster)
    let source_migrations = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");

    if source_migrations.exists() {
        // Use source directory in development - migrations are available at build path
        let migrator = sqlx::migrate::Migrator::new(source_migrations.as_path()).await?;
        migrator.run(pool).await?;
        Ok(())
    } else {
        // Extract embedded migrations to temp directory for distributed binaries
        // Keep temp_dir in scope for the entire function to ensure files stay available
        let temp_dir = TempDir::new().map_err(|e| MigrationError::ExtractIo {
            context: "creating tempdir for embedded migrations".to_string(),
            source: e,
        })?;
        let migrations_path = temp_dir.path().join("migrations");

        // Wrap blocking filesystem operations in spawn_blocking to avoid blocking tokio runtime.
        // This is a one-time startup operation with small files, so impact is minimal.
        let migrations_path_for_task = migrations_path.clone();
        let extract_result = tokio::task::spawn_blocking(move || -> Result<(), MigrationError> {
            std::fs::create_dir_all(&migrations_path_for_task).map_err(|e| {
                MigrationError::ExtractIo {
                    context: format!(
                        "creating migrations directory at {}",
                        migrations_path_for_task.display()
                    ),
                    source: e,
                }
            })?;

            // Extract all migration files
            for file in MIGRATIONS_DIR.files() {
                let file_path = migrations_path_for_task.join(file.path());
                if let Some(parent) = file_path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| MigrationError::ExtractIo {
                        context: format!(
                            "creating migration parent directory {}",
                            parent.display()
                        ),
                        source: e,
                    })?;
                }
                std::fs::write(&file_path, file.contents()).map_err(|e| {
                    MigrationError::ExtractIo {
                        context: format!("writing embedded migration {}", file_path.display()),
                        source: e,
                    }
                })?;
            }
            Ok(())
        })
        .await?;
        extract_result?;

        // Run migrations from the temp directory
        // temp_dir stays alive for the entire function, so files remain accessible
        let migrator = sqlx::migrate::Migrator::new(migrations_path.as_path()).await?;
        migrator.run(pool).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;
    use tempfile::NamedTempFile;

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

    #[tokio::test]
    async fn test_run_migrations_success_with_memory_db() {
        // Test successful migration on a fresh memory database
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test pool");

        // This should succeed - migrations should run successfully
        let result = run_migrations(&pool).await;
        assert!(
            result.is_ok(),
            "Migrations should succeed on fresh database"
        );
    }

    #[tokio::test]
    async fn test_run_migrations_success_with_file_db() {
        // Test successful migration on a file-based database
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let db_path = temp_file.path();

        let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
            .await
            .expect("Failed to create test pool");

        // This should succeed - migrations should run successfully
        let result = run_migrations(&pool).await;
        assert!(result.is_ok(), "Migrations should succeed on file database");
    }

    #[tokio::test]
    async fn test_run_migrations_idempotency() {
        // Test that running migrations twice is safe (idempotent)
        // This is critical - migrations should be safe to run multiple times
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test pool");

        // Run migrations first time
        let result1 = run_migrations(&pool).await;
        assert!(result1.is_ok(), "First migration run should succeed");

        // Run migrations second time (should be idempotent)
        let result2 = run_migrations(&pool).await;
        assert!(
            result2.is_ok(),
            "Second migration run should succeed (idempotent)"
        );

        // Verify database schema is still correct after second run
        // This is tested implicitly by the fact that migrations use IF NOT EXISTS
        // and the second run doesn't fail
    }

    /// Smoke test that `run_migrations` succeeds against a fresh in-memory pool.
    ///
    /// In dev (where `migrations/` exists at the workspace root) this exercises
    /// the source-directory branch of `run_migrations`. In distributed binaries
    /// the embedded-extraction branch handles the same job; both end up running
    /// the same SQL, so this is the only branch easily exercisable from tests.
    /// The previous version of this test claimed to test the embedded path
    /// (which it cannot do without injecting a path), so it was renamed to
    /// reflect what it actually verifies.
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
}
