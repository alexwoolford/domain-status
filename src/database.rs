// database.rs
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::sync::Arc;

use chrono::NaiveDateTime;
use log::{error, info};
use reqwest::StatusCode;
use sqlx::{Pool, Sqlite, SqlitePool};

use crate::config::DB_PATH;
use crate::error_handling::DatabaseError;

pub async fn init_db_pool() -> Result<Arc<Pool<Sqlite>>, DatabaseError> {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(DB_PATH)
    {
        Ok(_) => info!("Database file created successfully."),
        Err(ref e) if e.kind() == ErrorKind::AlreadyExists => info!("Database file already exists."),
        Err(e) => {
            error!("Failed to create database file: {}", e);
            return Err(DatabaseError::FileCreationError(e.to_string()));
        },
    }

    let pool = SqlitePool::connect(&format!("sqlite:{}", DB_PATH))
        .await
        .map_err(|e| {
            error!("Failed to connect to database: {}", e);
            DatabaseError::SqlError(e)
        })?;

    // Enable WAL mode
    sqlx::query("PRAGMA journal_mode=WAL")
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to set WAL mode: {}", e);
            DatabaseError::SqlError(e)
        })?;

    Ok(Arc::new(pool))
}


/// Creates the 'url_status' table if it doesn't exist.
pub async fn create_table(pool: &Pool<Sqlite>) -> Result<(), anyhow::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS url_status (
        id INTEGER PRIMARY KEY,
        domain TEXT NOT NULL,
        final_domain TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        reverse_dns_name TEXT,
        status INTEGER NOT NULL,
        status_description TEXT NOT NULL,
        response_time NUMERIC(10, 2),
        title TEXT NOT NULL,
        keywords TEXT,
        description TEXT,
        linkedin_slug TEXT,
        security_headers TEXT NOT NULL,
        tls_version TEXT,
        ssl_cert_subject TEXT NOT NULL,
        ssl_cert_issuer TEXT NOT NULL,
        ssl_cert_valid_from INTEGER,
        ssl_cert_valid_to INTEGER,
        oids STRING,
        is_mobile_friendly BOOLEAN,
        timestamp INTEGER NOT NULL
    )",
    )
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::SqlError(e).into())
}

/// Converts a NaiveDateTime to milliseconds since Unix epoch.
fn naive_datetime_to_millis(datetime: Option<&NaiveDateTime>) -> Option<i64> {
    datetime.map(|dt| dt.and_utc().timestamp_millis())
}

/// Inserts a new URL status into the database.
pub async fn update_database(
    initial_domain: &str,
    final_domain: &str,
    ip_address: &str,
    reverse_dns_name: &Option<String>,
    status: &StatusCode,
    status_desc: &str,
    elapsed: f64,
    title: &str,
    keywords: Option<&str>,
    description: Option<&str>,
    linkedin_slug: Option<&str>,
    security_headers: &str,
    timestamp: i64,
    tls_version: &Option<String>,
    ssl_cert_subject: &Option<String>,
    ssl_cert_issuer: &Option<String>,
    ssl_cert_valid_from: Option<NaiveDateTime>,
    ssl_cert_valid_to: Option<NaiveDateTime>,
    oids: Option<String>,
    is_mobile_friendly: bool,
    pool: &SqlitePool,
) -> Result<(), DatabaseError> {
    let valid_from_millis = naive_datetime_to_millis(ssl_cert_valid_from.as_ref());
    let valid_to_millis = naive_datetime_to_millis(ssl_cert_valid_to.as_ref());

    let result = sqlx::query(
        "INSERT INTO url_status (
            domain, final_domain, ip_address, reverse_dns_name, status, status_description,
            response_time, title, keywords, description, linkedin_slug, security_headers, tls_version, ssl_cert_subject,
            ssl_cert_issuer, ssl_cert_valid_from, ssl_cert_valid_to, oids, is_mobile_friendly, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
        .bind(initial_domain)
        .bind(final_domain)
        .bind(ip_address)
        .bind(reverse_dns_name)
        .bind(status.as_u16())
        .bind(status_desc)
        .bind(elapsed)
        .bind(title)
        .bind(keywords)
        .bind(description)
        .bind(linkedin_slug)
        .bind(security_headers)
        .bind(tls_version)
        .bind(ssl_cert_subject)
        .bind(ssl_cert_issuer)
        .bind(valid_from_millis)
        .bind(valid_to_millis)
        .bind(oids)
        .bind(is_mobile_friendly)
        .bind(timestamp)
        .execute(pool)
        .await;

    match result {
        Ok(_) => {
            log::debug!("Record successfully inserted into the database");
            Ok(())
        }
        Err(e) => {
            log::error!("Failed to insert record into the database: {}", e);
            Err(DatabaseError::SqlError(e))
        }
    }
}
