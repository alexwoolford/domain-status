// database.rs
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::sync::Arc;

use chrono::NaiveDateTime;
use log::{error, info};
use sqlx::migrate::Migrator;
use sqlx::{Pool, Sqlite, SqlitePool};
#[cfg(test)]
use tempfile::tempdir;

use crate::config::DB_PATH;
use crate::error_handling::DatabaseError;

/// Represents a complete URL status record for database insertion.
///
/// Contains all data extracted from a URL check including HTTP response details,
/// HTML metadata, DNS information, TLS certificate data, and security headers.
///
/// # Database Schema
///
/// This struct maps directly to the `url_status` table. The `timestamp` field
/// is stored as milliseconds since Unix epoch. All string fields that can be
/// empty are stored as `TEXT NOT NULL` with empty strings as fallback.
pub struct UrlRecord {
    pub initial_domain: String,
    pub final_domain: String,
    pub ip_address: String,
    pub reverse_dns_name: Option<String>,
    pub status: u16,
    pub status_desc: String,
    pub response_time: f64,
    pub title: String,
    pub keywords: Option<String>,
    pub description: Option<String>,
    pub linkedin_slug: Option<String>,
    pub security_headers: String,
    pub tls_version: Option<String>,
    pub ssl_cert_subject: Option<String>,
    pub ssl_cert_issuer: Option<String>,
    pub ssl_cert_valid_from: Option<NaiveDateTime>,
    pub ssl_cert_valid_to: Option<NaiveDateTime>,
    pub oids: Option<String>,
    pub is_mobile_friendly: bool,
    pub timestamp: i64,
    pub redirect_chain: Option<String>,
}

pub async fn init_db_pool() -> Result<Arc<Pool<Sqlite>>, DatabaseError> {
    let db_path = std::env::var("URL_CHECKER_DB_PATH").unwrap_or_else(|_| DB_PATH.to_string());
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&db_path)
    {
        Ok(_) => info!("Database file created successfully."),
        Err(ref e) if e.kind() == ErrorKind::AlreadyExists => {
            info!("Database file already exists.")
        }
        Err(e) => {
            error!("Failed to create database file: {e}");
            return Err(DatabaseError::FileCreationError(e.to_string()));
        }
    }

    let pool = SqlitePool::connect(&format!("sqlite:{db_path}"))
        .await
        .map_err(|e| {
            error!("Failed to connect to database: {e}");
            DatabaseError::SqlError(e)
        })?;

    // Enable WAL mode
    sqlx::query("PRAGMA journal_mode=WAL")
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to set WAL mode: {e}");
            DatabaseError::SqlError(e)
        })?;

    Ok(Arc::new(pool))
}

/// Runs SQLx migrations located in the `migrations/` directory.
pub async fn run_migrations(pool: &Pool<Sqlite>) -> Result<(), anyhow::Error> {
    let migrations_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let migrator = Migrator::new(migrations_dir.as_path()).await?;
    migrator.run(pool).await?;
    Ok(())
}

/// Converts a NaiveDateTime to milliseconds since Unix epoch.
fn naive_datetime_to_millis(datetime: Option<&NaiveDateTime>) -> Option<i64> {
    datetime.map(|dt| dt.and_utc().timestamp_millis())
}

/// Inserts a `UrlRecord` into the database.
pub async fn insert_url_record(pool: &SqlitePool, record: &UrlRecord) -> Result<(), DatabaseError> {
    let valid_from_millis = naive_datetime_to_millis(record.ssl_cert_valid_from.as_ref());
    let valid_to_millis = naive_datetime_to_millis(record.ssl_cert_valid_to.as_ref());

    log::debug!(
        "Inserting UrlRecord: initial_domain={}",
        record.initial_domain
    );

    let result = sqlx::query(
        "INSERT INTO url_status (
            domain, final_domain, ip_address, reverse_dns_name, status, status_description,
            response_time, title, keywords, description, linkedin_slug, security_headers, tls_version, ssl_cert_subject,
            ssl_cert_issuer, ssl_cert_valid_from, ssl_cert_valid_to, oids, is_mobile_friendly, timestamp, redirect_chain
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(final_domain, timestamp) DO UPDATE SET
            domain=excluded.domain,
            ip_address=excluded.ip_address,
            reverse_dns_name=excluded.reverse_dns_name,
            status=excluded.status,
            status_description=excluded.status_description,
            response_time=excluded.response_time,
            title=excluded.title,
            keywords=excluded.keywords,
            description=excluded.description,
            linkedin_slug=excluded.linkedin_slug,
            security_headers=excluded.security_headers,
            tls_version=excluded.tls_version,
            ssl_cert_subject=excluded.ssl_cert_subject,
            ssl_cert_issuer=excluded.ssl_cert_issuer,
            ssl_cert_valid_from=excluded.ssl_cert_valid_from,
            ssl_cert_valid_to=excluded.ssl_cert_valid_to,
            oids=excluded.oids,
            is_mobile_friendly=excluded.is_mobile_friendly,
            redirect_chain=excluded.redirect_chain"
    )
        .bind(&record.initial_domain)
        .bind(&record.final_domain)
        .bind(&record.ip_address)
        .bind(&record.reverse_dns_name)
        .bind(record.status)
        .bind(&record.status_desc)
        .bind(record.response_time)
        .bind(&record.title)
        .bind(&record.keywords)
        .bind(&record.description)
        .bind(&record.linkedin_slug)
        .bind(&record.security_headers)
        .bind(&record.tls_version)
        .bind(&record.ssl_cert_subject)
        .bind(&record.ssl_cert_issuer)
        .bind(valid_from_millis)
        .bind(valid_to_millis)
        .bind(&record.oids)
        .bind(record.is_mobile_friendly)
        .bind(record.timestamp)
        .bind(&record.redirect_chain)
        .execute(pool)
        .await;

    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            log::error!(
                "Failed to insert UrlRecord for domain {}: {}",
                record.initial_domain,
                e
            );
            Err(DatabaseError::SqlError(e))
        }
    }
}

// removed legacy update_database in favor of UrlRecord

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_init_db_pool() {
        let _temp_dir = tempdir().expect("Failed to create temp dir");

        let pool = init_db_pool().await;
        assert!(pool.is_ok());
    }

    #[tokio::test]
    async fn test_run_migrations() {
        // Create a new temporary directory for each test run
        let temp_dir = tempdir().expect("Failed to create temp dir");

        // Make sure the temp directory exists and is writable
        assert!(temp_dir.path().exists());
        assert!(temp_dir.path().is_dir());

        // Generate a unique database file path
        let db_path = temp_dir.path().join("test.db");

        // Initialize the database pool with the new path
        let pool = SqlitePool::connect(&format!("sqlite:{}?mode=rwc", db_path.to_str().unwrap()))
            .await
            .expect("Failed to create test database pool");

        // Ensure WAL mode is set for better concurrency
        sqlx::query("PRAGMA journal_mode=WAL")
            .execute(&pool)
            .await
            .expect("Failed to set WAL mode for test database");

        // Run migrations
        let result = run_migrations(&pool).await;

        // Ensure that the table was created successfully
        assert!(result.is_ok());

        // Close the pool to release the database file lock
        drop(pool);
    }
}
