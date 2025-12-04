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

/// Inserts nameservers into url_nameservers table using batch insert.
pub(crate) async fn insert_nameservers(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    nameservers_json: &Option<String>,
) {
    if let Some(ns) = parse_json_array(nameservers_json) {
        if ns.is_empty() {
            return;
        }

        // Batch insert: build VALUES clause for all nameservers
        // SQLite supports up to 500 parameters per query, so we can safely batch
        let placeholders: Vec<String> = (0..ns.len()).map(|_| "(?, ?)".to_string()).collect();
        let query = format!(
            "INSERT INTO url_nameservers (url_status_id, nameserver)
             VALUES {}
             ON CONFLICT(url_status_id, nameserver) DO NOTHING",
            placeholders.join(", ")
        );

        let mut query_builder = sqlx::query(&query);
        for nameserver in &ns {
            query_builder = query_builder.bind(url_status_id).bind(nameserver);
        }

        if let Err(e) = query_builder.execute(&mut **tx).await {
            log::warn!(
                "Failed to batch insert {} nameservers for url_status_id {}: {}",
                ns.len(),
                url_status_id,
                e
            );
        }
    }
}

/// Inserts TXT records into url_txt_records table using batch insert.
pub(crate) async fn insert_txt_records(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    txt_records_json: &Option<String>,
) {
    if let Some(txts) = parse_json_array(txt_records_json) {
        if txts.is_empty() {
            return;
        }

        // Pre-compute record types for all TXT records
        let txt_with_types: Vec<(&String, &'static str)> =
            txts.iter().map(|txt| (txt, detect_txt_type(txt))).collect();

        // Batch insert: build VALUES clause for all TXT records
        let placeholders: Vec<String> = (0..txt_with_types.len())
            .map(|_| "(?, ?, ?)".to_string())
            .collect();
        let query = format!(
            "INSERT INTO url_txt_records (url_status_id, txt_record, record_type)
             VALUES {}",
            placeholders.join(", ")
        );

        let mut query_builder = sqlx::query(&query);
        for (txt, record_type) in &txt_with_types {
            query_builder = query_builder
                .bind(url_status_id)
                .bind(*txt)
                .bind(record_type);
        }

        if let Err(e) = query_builder.execute(&mut **tx).await {
            log::warn!(
                "Failed to batch insert {} TXT records for url_status_id {}: {}",
                txt_with_types.len(),
                url_status_id,
                e
            );
        }
    }
}

/// Inserts MX records into url_mx_records table using batch insert.
pub(crate) async fn insert_mx_records(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    mx_records_json: &Option<String>,
) {
    if let Some(mx_records) = parse_mx_json_array(mx_records_json) {
        if mx_records.is_empty() {
            return;
        }

        // Batch insert: build VALUES clause for all MX records
        let placeholders: Vec<String> = (0..mx_records.len())
            .map(|_| "(?, ?, ?)".to_string())
            .collect();
        let query = format!(
            "INSERT INTO url_mx_records (url_status_id, priority, mail_exchange)
             VALUES {}
             ON CONFLICT(url_status_id, priority, mail_exchange) DO NOTHING",
            placeholders.join(", ")
        );

        let mut query_builder = sqlx::query(&query);
        for (priority, mail_exchange) in &mx_records {
            query_builder = query_builder
                .bind(url_status_id)
                .bind(priority)
                .bind(mail_exchange);
        }

        if let Err(e) = query_builder.execute(&mut **tx).await {
            log::warn!(
                "Failed to batch insert {} MX records for url_status_id {}: {}",
                mx_records.len(),
                url_status_id,
                e
            );
        }
    }
}

/// Inserts security headers into url_security_headers table using batch insert.
pub(crate) async fn insert_security_headers(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    security_headers: &std::collections::HashMap<String, String>,
) {
    if security_headers.is_empty() {
        return;
    }

    // Convert HashMap to Vec for consistent ordering
    let headers: Vec<(&String, &String)> = security_headers.iter().collect();

    // Batch insert: build VALUES clause for all security headers
    let placeholders: Vec<String> = (0..headers.len())
        .map(|_| "(?, ?, ?)".to_string())
        .collect();
    let query = format!(
        "INSERT INTO url_security_headers (url_status_id, header_name, header_value)
         VALUES {}
         ON CONFLICT(url_status_id, header_name) DO UPDATE SET
         header_value=excluded.header_value",
        placeholders.join(", ")
    );

    let mut query_builder = sqlx::query(&query);
    for (header_name, header_value) in &headers {
        query_builder = query_builder
            .bind(url_status_id)
            .bind(*header_name)
            .bind(*header_value);
    }

    if let Err(e) = query_builder.execute(&mut **tx).await {
        log::warn!(
            "Failed to batch insert {} security headers for url_status_id {}: {}",
            headers.len(),
            url_status_id,
            e
        );
    }
}

/// Inserts HTTP headers into url_http_headers table using batch insert.
pub(crate) async fn insert_http_headers(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    http_headers: &std::collections::HashMap<String, String>,
) {
    if http_headers.is_empty() {
        return;
    }

    // Convert HashMap to Vec for consistent ordering
    let headers: Vec<(&String, &String)> = http_headers.iter().collect();

    // Batch insert: build VALUES clause for all HTTP headers
    let placeholders: Vec<String> = (0..headers.len())
        .map(|_| "(?, ?, ?)".to_string())
        .collect();
    let query = format!(
        "INSERT INTO url_http_headers (url_status_id, header_name, header_value)
         VALUES {}
         ON CONFLICT(url_status_id, header_name) DO UPDATE SET
         header_value=excluded.header_value",
        placeholders.join(", ")
    );

    let mut query_builder = sqlx::query(&query);
    for (header_name, header_value) in &headers {
        query_builder = query_builder
            .bind(url_status_id)
            .bind(*header_name)
            .bind(*header_value);
    }

    if let Err(e) = query_builder.execute(&mut **tx).await {
        log::warn!(
            "Failed to batch insert {} HTTP headers for url_status_id {}: {}",
            headers.len(),
            url_status_id,
            e
        );
    }
}

/// Inserts OIDs into url_oids table using batch insert.
pub(crate) async fn insert_oids(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    oids: &std::collections::HashSet<String>,
) {
    if oids.is_empty() {
        return;
    }

    // Convert HashSet to Vec for consistent ordering
    let oids_vec: Vec<&String> = oids.iter().collect();

    // Batch insert: build VALUES clause for all OIDs
    let placeholders: Vec<String> = (0..oids_vec.len()).map(|_| "(?, ?)".to_string()).collect();
    let query = format!(
        "INSERT INTO url_oids (url_status_id, oid)
         VALUES {}
         ON CONFLICT(url_status_id, oid) DO NOTHING",
        placeholders.join(", ")
    );

    let mut query_builder = sqlx::query(&query);
    for oid in &oids_vec {
        query_builder = query_builder.bind(url_status_id).bind(*oid);
    }

    if let Err(e) = query_builder.execute(&mut **tx).await {
        log::warn!(
            "Failed to batch insert {} OIDs for url_status_id {}: {}",
            oids_vec.len(),
            url_status_id,
            e
        );
    }
}

/// Inserts redirect chain into url_redirect_chain table using batch insert.
pub(crate) async fn insert_redirect_chain(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    redirect_chain: &[String],
) {
    if redirect_chain.is_empty() {
        return;
    }

    // Batch insert: build VALUES clause for all redirects
    // Preserve sequence order (redirects happen in order, 1-based)
    let placeholders: Vec<String> = (0..redirect_chain.len())
        .map(|_| "(?, ?, ?)".to_string())
        .collect();
    let query = format!(
        "INSERT INTO url_redirect_chain (url_status_id, sequence_order, url)
         VALUES {}
         ON CONFLICT(url_status_id, sequence_order) DO UPDATE SET
         url=excluded.url",
        placeholders.join(", ")
    );

    let mut query_builder = sqlx::query(&query);
    for (index, url) in redirect_chain.iter().enumerate() {
        let sequence_order = (index + 1) as i32; // 1-based ordering
        query_builder = query_builder
            .bind(url_status_id)
            .bind(sequence_order)
            .bind(url);
    }

    if let Err(e) = query_builder.execute(&mut **tx).await {
        log::warn!(
            "Failed to batch insert {} redirect chain URLs for url_status_id {}: {}",
            redirect_chain.len(),
            url_status_id,
            e
        );
    }
}

/// Inserts certificate Subject Alternative Names (SANs) into url_certificate_sans table using batch insert.
pub(crate) async fn insert_certificate_sans(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    subject_alternative_names: &[String],
) {
    if subject_alternative_names.is_empty() {
        return;
    }

    // SANs are stored in a separate table to enable graph analysis (linking domains sharing certificates)
    // Batch insert: build VALUES clause for all SANs
    let placeholders: Vec<String> = (0..subject_alternative_names.len())
        .map(|_| "(?, ?)".to_string())
        .collect();
    let query = format!(
        "INSERT INTO url_certificate_sans (url_status_id, domain_name)
         VALUES {}
         ON CONFLICT(url_status_id, domain_name) DO NOTHING",
        placeholders.join(", ")
    );

    let mut query_builder = sqlx::query(&query);
    for san in subject_alternative_names {
        query_builder = query_builder.bind(url_status_id).bind(san);
    }

    if let Err(e) = query_builder.execute(&mut **tx).await {
        log::warn!(
            "Failed to batch insert {} certificate SANs for url_status_id {}: {}",
            subject_alternative_names.len(),
            url_status_id,
            e
        );
    }
}
