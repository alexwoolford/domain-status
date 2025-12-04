//! Satellite table insertion helpers.

use sqlx::Sqlite;
use sqlx::Transaction;

use crate::fingerprint;

use super::super::utils::{detect_txt_type, parse_json_array, parse_mx_json_array};

/// Inserts technologies into url_technologies table.
pub(crate) async fn insert_technologies(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    technologies: &[String],
) {
    // Batch optimization: Pre-fetch categories for unique technologies to avoid
    // repeated ruleset lookups. This reduces lock contention since get_technology_category
    // acquires a read lock on the ruleset for each call.
    // Deduplicate technologies first (common case: same tech detected multiple times)
    let unique_techs: std::collections::HashSet<&str> =
        technologies.iter().map(|s| s.as_str()).collect();
    let mut category_map = std::collections::HashMap::new();
    for tech in &unique_techs {
        category_map.insert(*tech, fingerprint::get_technology_category(tech).await);
    }

    for tech in technologies {
        // Use pre-fetched category
        let category = category_map.get(tech.as_str()).cloned().flatten();

        if let Err(e) = sqlx::query(
            "INSERT INTO url_technologies (url_status_id, technology_name, technology_category)
             VALUES (?, ?, ?)
             ON CONFLICT(url_status_id, technology_name) DO NOTHING",
        )
        .bind(url_status_id)
        .bind(tech)
        .bind(&category)
        .execute(&mut **tx)
        .await
        {
            log::warn!(
                "Failed to insert technology '{}' for url_status_id {}: {}",
                tech,
                url_status_id,
                e
            );
        }
    }
}

/// Inserts nameservers into url_nameservers table.
pub(crate) async fn insert_nameservers(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    nameservers_json: &Option<String>,
) {
    if let Some(ns) = parse_json_array(nameservers_json) {
        for nameserver in ns {
            if let Err(e) = sqlx::query(
                "INSERT INTO url_nameservers (url_status_id, nameserver)
                 VALUES (?, ?)
                 ON CONFLICT(url_status_id, nameserver) DO NOTHING",
            )
            .bind(url_status_id)
            .bind(&nameserver)
            .execute(&mut **tx)
            .await
            {
                log::warn!(
                    "Failed to insert nameserver '{}' for url_status_id {}: {}",
                    nameserver,
                    url_status_id,
                    e
                );
            }
        }
    }
}

/// Inserts TXT records into url_txt_records table.
pub(crate) async fn insert_txt_records(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    txt_records_json: &Option<String>,
) {
    if let Some(txts) = parse_json_array(txt_records_json) {
        for txt in txts {
            let record_type = detect_txt_type(&txt);
            if let Err(e) = sqlx::query(
                "INSERT INTO url_txt_records (url_status_id, txt_record, record_type)
                 VALUES (?, ?, ?)",
            )
            .bind(url_status_id)
            .bind(&txt)
            .bind(record_type)
            .execute(&mut **tx)
            .await
            {
                log::warn!(
                    "Failed to insert TXT record for url_status_id {}: {}",
                    url_status_id,
                    e
                );
            }
        }
    }
}

/// Inserts MX records into url_mx_records table.
pub(crate) async fn insert_mx_records(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    mx_records_json: &Option<String>,
) {
    if let Some(mx_records) = parse_mx_json_array(mx_records_json) {
        for (priority, mail_exchange) in mx_records {
            if let Err(e) = sqlx::query(
                "INSERT INTO url_mx_records (url_status_id, priority, mail_exchange)
                 VALUES (?, ?, ?)
                 ON CONFLICT(url_status_id, priority, mail_exchange) DO NOTHING",
            )
            .bind(url_status_id)
            .bind(priority)
            .bind(&mail_exchange)
            .execute(&mut **tx)
            .await
            {
                log::warn!(
                    "Failed to insert MX record '{}' for url_status_id {}: {}",
                    mail_exchange,
                    url_status_id,
                    e
                );
            }
        }
    }
}

/// Inserts security headers into url_security_headers table.
pub(crate) async fn insert_security_headers(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    security_headers: &std::collections::HashMap<String, String>,
) {
    for (header_name, header_value) in security_headers {
        if let Err(e) = sqlx::query(
            "INSERT INTO url_security_headers (url_status_id, header_name, header_value)
             VALUES (?, ?, ?)
             ON CONFLICT(url_status_id, header_name) DO UPDATE SET
             header_value=excluded.header_value",
        )
        .bind(url_status_id)
        .bind(header_name)
        .bind(header_value)
        .execute(&mut **tx)
        .await
        {
            log::warn!(
                "Failed to insert security header '{}' for url_status_id {}: {}",
                header_name,
                url_status_id,
                e
            );
        }
    }
}

/// Inserts HTTP headers into url_http_headers table.
pub(crate) async fn insert_http_headers(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    http_headers: &std::collections::HashMap<String, String>,
) {
    for (header_name, header_value) in http_headers {
        if let Err(e) = sqlx::query(
            "INSERT INTO url_http_headers (url_status_id, header_name, header_value)
             VALUES (?, ?, ?)
             ON CONFLICT(url_status_id, header_name) DO UPDATE SET
             header_value=excluded.header_value",
        )
        .bind(url_status_id)
        .bind(header_name)
        .bind(header_value)
        .execute(&mut **tx)
        .await
        {
            log::warn!(
                "Failed to insert HTTP header '{}' for url_status_id {}: {}",
                header_name,
                url_status_id,
                e
            );
        }
    }
}

/// Inserts OIDs into url_oids table.
pub(crate) async fn insert_oids(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    oids: &std::collections::HashSet<String>,
) {
    for oid in oids {
        if let Err(e) = sqlx::query(
            "INSERT INTO url_oids (url_status_id, oid)
             VALUES (?, ?)
             ON CONFLICT(url_status_id, oid) DO NOTHING",
        )
        .bind(url_status_id)
        .bind(oid)
        .execute(&mut **tx)
        .await
        {
            log::warn!(
                "Failed to insert OID '{}' for url_status_id {}: {}",
                oid,
                url_status_id,
                e
            );
        }
    }
}

/// Inserts redirect chain into url_redirect_chain table.
pub(crate) async fn insert_redirect_chain(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    redirect_chain: &[String],
) {
    // Preserve sequence order (redirects happen in order)
    for (index, url) in redirect_chain.iter().enumerate() {
        let sequence_order = (index + 1) as i32; // 1-based ordering
        if let Err(e) = sqlx::query(
            "INSERT INTO url_redirect_chain (url_status_id, sequence_order, url)
             VALUES (?, ?, ?)
             ON CONFLICT(url_status_id, sequence_order) DO UPDATE SET
             url=excluded.url",
        )
        .bind(url_status_id)
        .bind(sequence_order)
        .bind(url)
        .execute(&mut **tx)
        .await
        {
            log::warn!(
                "Failed to insert redirect chain URL at position {}: {}",
                sequence_order,
                e
            );
        }
    }
}

/// Inserts certificate Subject Alternative Names (SANs) into url_certificate_sans table.
pub(crate) async fn insert_certificate_sans(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    subject_alternative_names: &[String],
) {
    // SANs are stored in a separate table to enable graph analysis (linking domains sharing certificates)
    for san in subject_alternative_names {
        if let Err(e) = sqlx::query(
            "INSERT INTO url_certificate_sans (url_status_id, domain_name)
             VALUES (?, ?)
             ON CONFLICT(url_status_id, domain_name) DO NOTHING",
        )
        .bind(url_status_id)
        .bind(san)
        .execute(&mut **tx)
        .await
        {
            log::warn!(
                "Failed to insert certificate SAN '{}' for url_status_id {}: {}",
                san,
                url_status_id,
                e
            );
        }
    }
}
