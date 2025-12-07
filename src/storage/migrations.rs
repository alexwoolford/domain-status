//! Database migration management.
//!
//! This module handles SQLx migrations embedded into the binary at compile time.
//! Migrations are extracted to a temporary directory at runtime and then executed.
//! This ensures migrations work for distributed binaries without requiring the
//! migrations directory to be present alongside the executable.

use include_dir::{include_dir, Dir};
use sqlx::{Pool, Sqlite};
use tempfile::TempDir;

// Embed migrations directory into the binary at compile time
static MIGRATIONS_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/migrations");

/// Runs SQLx migrations embedded in the binary.
///
/// This function extracts embedded migrations to a temporary directory and runs them.
/// This ensures migrations are always available, even when the binary is distributed
/// without the migrations directory.
///
/// In development builds, it uses the source migrations directory directly (faster).
/// In distributed binaries, it extracts embedded migrations to a temp directory.
pub async fn run_migrations(pool: &Pool<Sqlite>) -> Result<(), anyhow::Error> {
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
        let _temp_dir = TempDir::new()?;
        let migrations_path = _temp_dir.path().join("migrations");
        std::fs::create_dir_all(&migrations_path)?;

        // Extract all migration files
        for file in MIGRATIONS_DIR.files() {
            let file_path = migrations_path.join(file.path());
            if let Some(parent) = file_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&file_path, file.contents())?;
        }

        // Run migrations from the temp directory
        // _temp_dir stays alive for the entire function, so files remain accessible
        let migrator = sqlx::migrate::Migrator::new(migrations_path.as_path()).await?;
        migrator.run(pool).await?;
        Ok(())
    }
}
