// storage/migrations.rs
// Database migration management

use sqlx::{Pool, Sqlite};

/// Runs SQLx migrations located in the `migrations/` directory.
pub async fn run_migrations(pool: &Pool<Sqlite>) -> Result<(), anyhow::Error> {
    let migrations_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let migrator = sqlx::migrate::Migrator::new(migrations_dir.as_path()).await?;
    migrator.run(pool).await?;
    Ok(())
}
