//! Main URL record insertion.
//!
//! This module handles inserting URL status records and all related satellite tables
//! (technologies, nameservers, TXT records, MX records, headers, OIDs, redirect chain, SANs).

mod satellite;

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;

use super::super::models::UrlRecord;
use super::utils::naive_datetime_to_millis;

use satellite::{
    insert_certificate_sans, insert_http_headers, insert_mx_records, insert_nameservers,
    insert_oids, insert_redirect_chain, insert_security_headers, insert_technologies,
    insert_txt_records,
};

/// Inserts a `UrlRecord` into the database.
///
/// This function inserts data into:
/// 1. The main `url_status` table (fact table with atomic fields)
/// 2. Normalized child tables (url_technologies, url_nameservers, url_txt_records, url_mx_records, url_security_headers, url_http_headers, url_oids, url_redirect_chain)
///
/// All inserts are wrapped in a transaction for atomicity.
///
/// Note: Multi-valued fields (technologies, nameservers, txt_records, mx_records, security_headers, http_headers,
/// oids, redirect_chain) are stored only in normalized child tables, not as JSON in the main table.
/// This eliminates data duplication and establishes a single source of truth.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `record` - The URL record to insert
/// * `security_headers` - Security headers HashMap (will be inserted into url_security_headers table)
/// * `http_headers` - HTTP headers HashMap (will be inserted into url_http_headers table)
/// * `oids` - Vector of OID strings (will be inserted into url_oids table)
/// * `redirect_chain` - Vector of redirect URLs (will be inserted into url_redirect_chain table)
/// * `technologies` - Vector of detected technology names (will be inserted into url_technologies table)
/// * `subject_alternative_names` - Vector of DNS names from certificate SAN extension (will be inserted into url_certificate_sans table)
///
/// # Returns
///
/// Returns the `id` of the inserted (or updated) `url_status` record, or an error if insertion fails.
#[allow(clippy::too_many_arguments)] // URL record insertion requires many data sources
pub async fn insert_url_record(
    pool: &SqlitePool,
    record: &UrlRecord,
    security_headers: &std::collections::HashMap<String, String>,
    http_headers: &std::collections::HashMap<String, String>,
    oids: &std::collections::HashSet<String>,
    redirect_chain: &[String],
    technologies: &[String],
    subject_alternative_names: &[String],
) -> Result<i64, DatabaseError> {
    let valid_from_millis = naive_datetime_to_millis(record.ssl_cert_valid_from.as_ref());
    let valid_to_millis = naive_datetime_to_millis(record.ssl_cert_valid_to.as_ref());

    log::debug!(
        "Inserting UrlRecord: initial_domain={}",
        record.initial_domain
    );

    // Start transaction for atomic dual-write
    let mut tx = pool.begin().await.map_err(DatabaseError::SqlError)?;

    // 1. Insert into main url_status table
    // Use RETURNING clause to get the ID in a single query (SQLite 3.35.0+)
    // This eliminates the need for a separate SELECT query and improves performance
    let url_status_id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO url_status (
            domain, final_domain, ip_address, reverse_dns_name, status, status_description,
            response_time, title, keywords, description, tls_version, ssl_cert_subject,
            ssl_cert_issuer, ssl_cert_valid_from, ssl_cert_valid_to, is_mobile_friendly, timestamp,
            spf_record, dmarc_record, cipher_suite, key_algorithm, run_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            tls_version=excluded.tls_version,
            ssl_cert_subject=excluded.ssl_cert_subject,
            ssl_cert_issuer=excluded.ssl_cert_issuer,
            ssl_cert_valid_from=excluded.ssl_cert_valid_from,
            ssl_cert_valid_to=excluded.ssl_cert_valid_to,
            is_mobile_friendly=excluded.is_mobile_friendly,
            spf_record=excluded.spf_record,
            dmarc_record=excluded.dmarc_record,
            cipher_suite=excluded.cipher_suite,
            key_algorithm=excluded.key_algorithm,
            run_id=excluded.run_id
        RETURNING id",
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
    .bind(&record.tls_version)
    .bind(&record.ssl_cert_subject)
    .bind(&record.ssl_cert_issuer)
    .bind(valid_from_millis)
    .bind(valid_to_millis)
    .bind(record.is_mobile_friendly)
    .bind(record.timestamp)
    .bind(&record.spf_record)
    .bind(&record.dmarc_record)
    .bind(&record.cipher_suite)
    .bind(&record.key_algorithm)
    .bind(&record.run_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        log::error!(
            "Failed to insert UrlRecord for domain {}: {}",
            record.initial_domain,
            e
        );
        DatabaseError::SqlError(e)
    })?;

    // 2-10. Insert into satellite tables
    insert_technologies(&mut tx, url_status_id, technologies).await;
    insert_nameservers(&mut tx, url_status_id, &record.nameservers).await;
    insert_txt_records(&mut tx, url_status_id, &record.txt_records).await;
    insert_mx_records(&mut tx, url_status_id, &record.mx_records).await;
    insert_security_headers(&mut tx, url_status_id, security_headers).await;
    insert_http_headers(&mut tx, url_status_id, http_headers).await;
    insert_oids(&mut tx, url_status_id, oids).await;
    insert_redirect_chain(&mut tx, url_status_id, redirect_chain).await;
    insert_certificate_sans(&mut tx, url_status_id, subject_alternative_names).await;

    // Commit transaction
    tx.commit().await.map_err(DatabaseError::SqlError)?;

    Ok(url_status_id)
}

