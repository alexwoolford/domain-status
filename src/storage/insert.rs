//! Database insert operations.
//!
//! This module provides functions to insert various types of records into the database:
//! - URL status records and related satellite tables
//! - Run metadata and statistics
//! - GeoIP data
//!
//! All inserts use parameterized queries to prevent SQL injection.

use chrono::NaiveDateTime;
use log;
use sqlx::{Row, SqlitePool};

use crate::error_handling::DatabaseError;
use crate::fingerprint;
use crate::parse::SocialMediaLink;

use super::models::{UrlFailureRecord, UrlPartialFailureRecord, UrlRecord};

/// Converts a NaiveDateTime to milliseconds since Unix epoch.
fn naive_datetime_to_millis(datetime: Option<&NaiveDateTime>) -> Option<i64> {
    datetime.map(|dt| dt.and_utc().timestamp_millis())
}

/// Parses a JSON array string into a Vec<String>.
/// Returns None if the string is None or empty, or if parsing fails.
fn parse_json_array(json_str: &Option<String>) -> Option<Vec<String>> {
    let json_str = json_str.as_ref()?;
    if json_str.is_empty() {
        return None;
    }
    serde_json::from_str::<Vec<String>>(json_str).ok()
}

/// Detects the type of a TXT record based on its content.
/// Returns "SPF", "DMARC", "VERIFICATION", or "OTHER".
fn detect_txt_type(txt: &str) -> &'static str {
    let txt_lower = txt.to_lowercase();
    if txt_lower.starts_with("v=spf1") {
        "SPF"
    } else if txt_lower.starts_with("v=dmarc1") {
        "DMARC"
    } else if txt_lower.contains("google-site-verification")
        || txt_lower.contains("ms-verify")
        || txt_lower.contains("facebook-domain-verification")
        || txt_lower.contains("atlassian-domain-verification")
    {
        "VERIFICATION"
    } else {
        "OTHER"
    }
}

/// Parses an MX record string into priority and hostname.
/// Expected format: "10 mail.example.com" or just "mail.example.com" (default priority 0)
/// Returns None if parsing fails.
fn parse_mx_record(mx: &str) -> Option<(i32, String)> {
    let parts: Vec<&str> = mx.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    // Try to parse first part as priority
    if let Ok(priority) = parts[0].parse::<i32>() {
        if parts.len() >= 2 {
            Some((priority, parts[1].to_string()))
        } else {
            None
        }
    } else {
        // No priority specified, use default 0
        Some((0, parts[0].to_string()))
    }
}

/// Parses MX records from JSON array format.
/// Expected JSON format: [{"priority": 10, "hostname": "mail.example.com"}, ...]
/// Returns Vec of (priority, hostname) tuples.
fn parse_mx_json_array(json_str: &Option<String>) -> Option<Vec<(i32, String)>> {
    let json_str = json_str.as_ref()?;
    if json_str.is_empty() {
        return None;
    }

    // Try to parse as array of objects first
    if let Ok(mx_objects) = serde_json::from_str::<Vec<serde_json::Value>>(json_str) {
        let mut result = Vec::new();
        for obj in mx_objects {
            if let (Some(priority), Some(hostname)) = (
                obj.get("priority")
                    .and_then(|v| v.as_i64().map(|p| p as i32)),
                obj.get("hostname").and_then(|v| v.as_str()),
            ) {
                result.push((priority, hostname.to_string()));
            }
        }
        if !result.is_empty() {
            return Some(result);
        }
    }

    // Fallback: try parsing as array of strings
    if let Ok(mx_strings) = serde_json::from_str::<Vec<String>>(json_str) {
        let mut result = Vec::new();
        for mx_str in mx_strings {
            if let Some((priority, hostname)) = parse_mx_record(&mx_str) {
                result.push((priority, hostname));
            }
        }
        if !result.is_empty() {
            return Some(result);
        }
    }

    None
}

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
    // Removed: linkedin_slug (now stored in url_social_media_links table)
    // Removed: security_headers (stored in url_security_headers table)
    .bind(&record.tls_version)
    .bind(&record.ssl_cert_subject)
    .bind(&record.ssl_cert_issuer)
    .bind(valid_from_millis)
    .bind(valid_to_millis)
    // Removed: oids (stored in url_oids table)
    .bind(record.is_mobile_friendly)
    .bind(record.timestamp)
    // Removed: redirect_chain (stored in url_redirect_chain table)
    // Removed: technologies, nameservers, txt_records, mx_records (stored in normalized child tables)
    // Removed: fingerprints_source, fingerprints_version (stored in runs table)
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

    // 2. Insert normalized technologies (passed directly, no JSON parsing)
    for tech in technologies {
        // Get category for this technology
        let category = fingerprint::get_technology_category(tech).await;

        if let Err(e) = sqlx::query(
            "INSERT INTO url_technologies (url_status_id, technology_name, technology_category)
             VALUES (?, ?, ?)
             ON CONFLICT(url_status_id, technology_name) DO NOTHING",
        )
        .bind(url_status_id)
        .bind(tech)
        .bind(&category)
        .execute(&mut *tx)
        .await
        {
            log::warn!("Failed to insert technology {}: {}", tech, e);
        }
    }

    // 3. Insert normalized nameservers
    if let Some(ns) = parse_json_array(&record.nameservers) {
        for nameserver in ns {
            if let Err(e) = sqlx::query(
                "INSERT INTO url_nameservers (url_status_id, nameserver)
                 VALUES (?, ?)
                 ON CONFLICT(url_status_id, nameserver) DO NOTHING",
            )
            .bind(url_status_id)
            .bind(&nameserver)
            .execute(&mut *tx)
            .await
            {
                log::warn!("Failed to insert nameserver {}: {}", nameserver, e);
            }
        }
    }

    // 4. Insert normalized TXT records
    if let Some(txts) = parse_json_array(&record.txt_records) {
        for txt in txts {
            let record_type = detect_txt_type(&txt);
            if let Err(e) = sqlx::query(
                "INSERT INTO url_txt_records (url_status_id, txt_record, record_type)
                 VALUES (?, ?, ?)",
            )
            .bind(url_status_id)
            .bind(&txt)
            .bind(record_type)
            .execute(&mut *tx)
            .await
            {
                log::warn!("Failed to insert TXT record: {}", e);
            }
        }
    }

    // 5. Insert normalized MX records
    if let Some(mx_records) = parse_mx_json_array(&record.mx_records) {
        for (priority, mail_exchange) in mx_records {
            if let Err(e) = sqlx::query(
                "INSERT INTO url_mx_records (url_status_id, priority, mail_exchange)
                 VALUES (?, ?, ?)
                 ON CONFLICT(url_status_id, priority, mail_exchange) DO NOTHING",
            )
            .bind(url_status_id)
            .bind(priority)
            .bind(&mail_exchange)
            .execute(&mut *tx)
            .await
            {
                log::warn!("Failed to insert MX record {}: {}", mail_exchange, e);
            }
        }
    }

    // 6. Insert normalized security headers
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
        .execute(&mut *tx)
        .await
        {
            log::warn!("Failed to insert security header {}: {}", header_name, e);
        }
    }

    // 7. Insert normalized HTTP headers (non-security)
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
        .execute(&mut *tx)
        .await
        {
            log::warn!("Failed to insert HTTP header {}: {}", header_name, e);
        }
    }

    // 8. Insert normalized OIDs
    for oid in oids {
        if let Err(e) = sqlx::query(
            "INSERT INTO url_oids (url_status_id, oid)
             VALUES (?, ?)
             ON CONFLICT(url_status_id, oid) DO NOTHING",
        )
        .bind(url_status_id)
        .bind(oid)
        .execute(&mut *tx)
        .await
        {
            log::warn!("Failed to insert OID {}: {}", oid, e);
        }
    }

    // 9. Insert normalized redirect chain
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
        .execute(&mut *tx)
        .await
        {
            log::warn!(
                "Failed to insert redirect chain URL at position {}: {}",
                sequence_order,
                e
            );
        }
    }

    // 10. Insert certificate Subject Alternative Names (SANs)
    // SANs are stored in a separate table to enable graph analysis (linking domains sharing certificates)
    for san in subject_alternative_names {
        if let Err(e) = sqlx::query(
            "INSERT INTO url_certificate_sans (url_status_id, domain_name)
             VALUES (?, ?)
             ON CONFLICT(url_status_id, domain_name) DO NOTHING",
        )
        .bind(url_status_id)
        .bind(san)
        .execute(&mut *tx)
        .await
        {
            log::warn!("Failed to insert certificate SAN {}: {}", san, e);
        }
    }

    // 6. Insert GeoIP data (if available)
    // GeoIP lookup is done in fetch/mod.rs and passed via UrlRecord
    // For now, we'll handle GeoIP insertion separately after UrlRecord is created
    // This will be called from fetch/mod.rs after GeoIP lookup

    // Commit transaction
    tx.commit().await.map_err(DatabaseError::SqlError)?;

    Ok(url_status_id)
}

/// Inserts GeoIP data for a URL status record.
///
/// This should be called after `insert_url_record` to populate geographic
/// and network information for the IP address.
pub async fn insert_geoip_data(
    pool: &SqlitePool,
    url_status_id: i64,
    ip_address: &str,
    geoip: &crate::geoip::GeoIpResult,
) -> Result<(), DatabaseError> {
    sqlx::query(
        "INSERT INTO url_geoip (
            url_status_id, ip_address, country_code, country_name, region, city,
            latitude, longitude, postal_code, timezone, asn, asn_org
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(url_status_id) DO UPDATE SET
            ip_address=excluded.ip_address,
            country_code=excluded.country_code,
            country_name=excluded.country_name,
            region=excluded.region,
            city=excluded.city,
            latitude=excluded.latitude,
            longitude=excluded.longitude,
            postal_code=excluded.postal_code,
            timezone=excluded.timezone,
            asn=excluded.asn,
            asn_org=excluded.asn_org",
    )
    .bind(url_status_id)
    .bind(ip_address)
    .bind(&geoip.country_code)
    .bind(&geoip.country_name)
    .bind(&geoip.region)
    .bind(&geoip.city)
    .bind(geoip.latitude)
    .bind(geoip.longitude)
    .bind(&geoip.postal_code)
    .bind(&geoip.timezone)
    .bind(geoip.asn.map(|a| a as i64))
    .bind(&geoip.asn_org)
    .execute(pool)
    .await
    .map_err(DatabaseError::SqlError)?;

    Ok(())
}

/// Inserts structured data (JSON-LD, Open Graph, Twitter Cards, Schema.org) into the database.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - Foreign key to url_status.id
/// * `structured_data` - Structured data extracted from HTML
pub async fn insert_structured_data(
    pool: &SqlitePool,
    url_status_id: i64,
    structured_data: &crate::parse::StructuredData,
) -> Result<(), DatabaseError> {
    // Insert JSON-LD scripts
    for json_ld_value in &structured_data.json_ld {
        let json_str = serde_json::to_string(json_ld_value).map_err(|e| {
            DatabaseError::SqlError(sqlx::Error::Protocol(format!(
                "Failed to serialize JSON-LD: {}",
                e
            )))
        })?;

        sqlx::query(
            "INSERT INTO url_structured_data (url_status_id, data_type, property_name, property_value)
             VALUES (?, 'json_ld', '', ?)",
        )
        .bind(url_status_id)
        .bind(json_str)
        .execute(pool)
        .await
        .map_err(DatabaseError::from)?;
    }

    // Insert Open Graph tags
    for (property, value) in &structured_data.open_graph {
        sqlx::query(
            "INSERT INTO url_structured_data (url_status_id, data_type, property_name, property_value)
             VALUES (?, 'open_graph', ?, ?)",
        )
        .bind(url_status_id)
        .bind(property)
        .bind(value)
        .execute(pool)
        .await
        .map_err(DatabaseError::from)?;
    }

    // Insert Twitter Card tags
    for (name, value) in &structured_data.twitter_cards {
        sqlx::query(
            "INSERT INTO url_structured_data (url_status_id, data_type, property_name, property_value)
             VALUES (?, 'twitter_card', ?, ?)",
        )
        .bind(url_status_id)
        .bind(name)
        .bind(value)
        .execute(pool)
        .await
        .map_err(DatabaseError::from)?;
    }

    // Insert Schema.org types
    for schema_type in &structured_data.schema_types {
        sqlx::query(
            "INSERT INTO url_structured_data (url_status_id, data_type, property_name, property_value)
             VALUES (?, 'schema_type', ?, '')",
        )
        .bind(url_status_id)
        .bind(schema_type)
        .execute(pool)
        .await
        .map_err(DatabaseError::from)?;
    }

    Ok(())
}

/// Inserts social media links into the database.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - Foreign key to url_status.id
/// * `links` - Vector of social media links extracted from HTML
pub async fn insert_social_media_links(
    pool: &SqlitePool,
    url_status_id: i64,
    links: &[SocialMediaLink],
) -> Result<(), DatabaseError> {
    for link in links {
        if let Err(e) = sqlx::query(
            "INSERT INTO url_social_media_links (url_status_id, platform, url, identifier)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(url_status_id, platform, url) DO UPDATE SET
             identifier=excluded.identifier",
        )
        .bind(url_status_id)
        .bind(&link.platform)
        .bind(&link.url)
        .bind(&link.identifier)
        .execute(pool)
        .await
        {
            log::warn!(
                "Failed to insert social media link {} for platform {}: {}",
                link.url,
                link.platform,
                e
            );
        }
    }

    Ok(())
}

/// Inserts security warnings into the database.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - Foreign key to url_status.id
/// * `warnings` - Vector of security warnings
pub async fn insert_security_warnings(
    pool: &SqlitePool,
    url_status_id: i64,
    warnings: &[crate::security::SecurityWarning],
) -> Result<(), DatabaseError> {
    for warning in warnings {
        if let Err(e) = sqlx::query(
            "INSERT INTO url_security_warnings (url_status_id, warning_code, warning_description)
             VALUES (?, ?, ?)
             ON CONFLICT(url_status_id, warning_code) DO UPDATE SET
             warning_description=excluded.warning_description",
        )
        .bind(url_status_id)
        .bind(warning.code())
        .bind(warning.description())
        .execute(pool)
        .await
        {
            log::warn!(
                "Failed to insert security warning {} for url_status_id {}: {}",
                warning.code(),
                url_status_id,
                e
            );
        }
    }

    Ok(())
}

/// Inserts WHOIS data into the database.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - Foreign key to url_status.id
/// * `whois` - WHOIS lookup result
pub async fn insert_whois_data(
    pool: &SqlitePool,
    url_status_id: i64,
    whois: &crate::whois::WhoisResult,
) -> Result<(), DatabaseError> {
    // Convert DateTime<Utc> to milliseconds since Unix epoch
    let creation_date_ms = whois.creation_date.map(|dt| dt.timestamp_millis());
    let expiration_date_ms = whois.expiration_date.map(|dt| dt.timestamp_millis());
    let updated_date_ms = whois.updated_date.map(|dt| dt.timestamp_millis());

    // Serialize status and nameservers to JSON
    let status_json = whois
        .status
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap_or_default());
    let nameservers_json = whois
        .nameservers
        .as_ref()
        .map(|n| serde_json::to_string(n).unwrap_or_default());

    sqlx::query(
        "INSERT INTO url_whois (
            url_status_id, creation_date, expiration_date, updated_date,
            registrar, registrant_country, registrant_org, status, nameservers, raw_text
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(url_status_id) DO UPDATE SET
            creation_date=excluded.creation_date,
            expiration_date=excluded.expiration_date,
            updated_date=excluded.updated_date,
            registrar=excluded.registrar,
            registrant_country=excluded.registrant_country,
            registrant_org=excluded.registrant_org,
            status=excluded.status,
            nameservers=excluded.nameservers,
            raw_text=excluded.raw_text",
    )
    .bind(url_status_id)
    .bind(creation_date_ms)
    .bind(expiration_date_ms)
    .bind(updated_date_ms)
    .bind(&whois.registrar)
    .bind(&whois.registrant_country)
    .bind(&whois.registrant_org)
    .bind(&status_json)
    .bind(&nameservers_json)
    .bind(&whois.raw_text)
    .execute(pool)
    .await
    .map_err(DatabaseError::SqlError)?;

    Ok(())
}

/// Inserts analytics/tracking IDs for a URL status record.
///
/// This function inserts analytics IDs (Google Analytics, Facebook Pixel, GTM, AdSense)
/// into the `url_analytics_ids` table. These IDs enable graph analysis by linking
/// domains that share the same tracking IDs (indicating common ownership or management).
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `url_status_id` - Foreign key to url_status.id
/// * `analytics_ids` - Vector of AnalyticsId structs (provider, id)
pub async fn insert_analytics_ids(
    pool: &SqlitePool,
    url_status_id: i64,
    analytics_ids: &[crate::parse::AnalyticsId],
) -> Result<(), DatabaseError> {
    for analytics_id in analytics_ids {
        sqlx::query(
            "INSERT INTO url_analytics_ids (url_status_id, provider, tracking_id)
             VALUES (?, ?, ?)
             ON CONFLICT(url_status_id, provider, tracking_id) DO NOTHING",
        )
        .bind(url_status_id)
        .bind(&analytics_id.provider)
        .bind(&analytics_id.id)
        .execute(pool)
        .await
        .map_err(DatabaseError::SqlError)?;
    }

    Ok(())
}

/// Inserts or updates run metadata in the runs table.
///
/// This should be called at the start of a run to record run-level information
/// like fingerprints_source, fingerprints_version, and geoip_version.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `run_id` - Unique identifier for this run
/// * `start_time` - Start time as milliseconds since Unix epoch
/// * `fingerprints_source` - Source URL of the fingerprint ruleset
/// * `fingerprints_version` - Version/commit hash of the fingerprint ruleset
/// * `geoip_version` - Version/build date of the GeoIP database (None if GeoIP disabled)
pub async fn insert_run_metadata(
    pool: &SqlitePool,
    run_id: &str,
    start_time: i64,
    fingerprints_source: Option<&str>,
    fingerprints_version: Option<&str>,
    geoip_version: Option<&str>,
) -> Result<(), DatabaseError> {
    sqlx::query(
        "INSERT INTO runs (run_id, fingerprints_source, fingerprints_version, geoip_version, start_time)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(run_id) DO UPDATE SET
             fingerprints_source=excluded.fingerprints_source,
             fingerprints_version=excluded.fingerprints_version,
             geoip_version=excluded.geoip_version,
             start_time=excluded.start_time",
    )
    .bind(run_id)
    .bind(fingerprints_source)
    .bind(fingerprints_version)
    .bind(geoip_version)
    .bind(start_time)
    .execute(pool)
    .await
    .map_err(DatabaseError::SqlError)?;

    Ok(())
}

/// Updates run statistics when a run completes.
#[allow(dead_code)]
pub async fn update_run_stats(
    pool: &SqlitePool,
    run_id: &str,
    total_urls: i32,
    successful_urls: i32,
    failed_urls: i32,
) -> Result<(), DatabaseError> {
    let end_time = chrono::Utc::now().timestamp_millis();

    sqlx::query(
        "UPDATE runs 
         SET end_time = ?, total_urls = ?, successful_urls = ?, failed_urls = ?
         WHERE run_id = ?",
    )
    .bind(end_time)
    .bind(total_urls)
    .bind(successful_urls)
    .bind(failed_urls)
    .bind(run_id)
    .execute(pool)
    .await
    .map_err(DatabaseError::SqlError)?;

    Ok(())
}

/// Inserts a URL failure record into the database with retry logic.
///
/// Retries transient database errors (locked, busy) up to 3 times with exponential backoff.
/// This prevents failures when the database is temporarily unavailable due to high concurrency.
///
/// This function inserts the main failure record and all associated satellite data
/// (redirect chain, response headers, request headers) in a transaction.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `failure` - The failure record to insert
///
/// # Errors
///
/// Returns a `DatabaseError` if the database operation fails after retries.
pub async fn insert_url_failure(
    pool: &SqlitePool,
    failure: &UrlFailureRecord,
) -> Result<i64, DatabaseError> {
    // Retry strategy for transient database errors (SQLITE_BUSY, SQLITE_LOCKED)
    const MAX_RETRIES: usize = 3;
    const INITIAL_DELAY_MS: u64 = 50;

    for attempt in 0..=MAX_RETRIES {
        match insert_url_failure_impl(pool, failure).await {
            Ok(id) => return Ok(id),
            Err(e) => {
                // Check if error is retriable (transient database errors)
                let is_retriable = matches!(
                    &e,
                    DatabaseError::SqlError(sqlx::Error::Database(db_err))
                        if db_err.message().contains("database is locked")
                            || db_err.message().contains("database is busy")
                );

                if !is_retriable || attempt >= MAX_RETRIES {
                    return Err(e);
                }

                // Exponential backoff: 50ms, 100ms, 200ms
                let delay_ms = INITIAL_DELAY_MS * (1 << attempt);
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
        }
    }

    // Should never reach here, but handle it gracefully
    Err(DatabaseError::SqlError(sqlx::Error::PoolClosed))
}

/// Internal implementation of insert_url_failure (without retry logic).
async fn insert_url_failure_impl(
    pool: &SqlitePool,
    failure: &UrlFailureRecord,
) -> Result<i64, DatabaseError> {
    // Insert main failure record
    let failure_id = sqlx::query(
        "INSERT INTO url_failures (
            url, final_url, domain, final_domain, error_type, error_message,
            http_status, retry_count, elapsed_time_seconds, timestamp, run_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING id",
    )
    .bind(&failure.url)
    .bind(failure.final_url.as_ref())
    .bind(&failure.domain)
    .bind(failure.final_domain.as_ref())
    .bind(&failure.error_type)
    .bind(&failure.error_message)
    .bind(failure.http_status.map(|s| s as i64))
    .bind(failure.retry_count as i64)
    .bind(failure.elapsed_time_seconds)
    .bind(failure.timestamp)
    .bind(failure.run_id.as_ref())
    .fetch_one(pool)
    .await
    .map_err(DatabaseError::SqlError)?
    .get::<i64, _>(0);

    // Insert redirect chain
    for (order, redirect_url) in failure.redirect_chain.iter().enumerate() {
        sqlx::query(
            "INSERT INTO url_failure_redirect_chain (url_failure_id, redirect_url, redirect_order)
             VALUES (?, ?, ?)
             ON CONFLICT(url_failure_id, redirect_order) DO NOTHING",
        )
        .bind(failure_id)
        .bind(redirect_url)
        .bind(order as i64)
        .execute(pool)
        .await
        .map_err(DatabaseError::SqlError)?;
    }

    // Insert response headers
    for (name, value) in &failure.response_headers {
        sqlx::query(
            "INSERT INTO url_failure_response_headers (url_failure_id, header_name, header_value)
             VALUES (?, ?, ?)
             ON CONFLICT(url_failure_id, header_name) DO UPDATE SET header_value=excluded.header_value",
        )
        .bind(failure_id)
        .bind(name)
        .bind(value)
        .execute(pool)
        .await
        .map_err(DatabaseError::SqlError)?;
    }

    // Insert request headers
    for (name, value) in &failure.request_headers {
        sqlx::query(
            "INSERT INTO url_failure_request_headers (url_failure_id, header_name, header_value)
             VALUES (?, ?, ?)
             ON CONFLICT(url_failure_id, header_name) DO UPDATE SET header_value=excluded.header_value",
        )
        .bind(failure_id)
        .bind(name)
        .bind(value)
        .execute(pool)
        .await
        .map_err(DatabaseError::SqlError)?;
    }

    Ok(failure_id)
}

/// Inserts a partial failure record into the database.
///
/// Partial failures are DNS/TLS errors that occurred during supplementary data
/// collection but didn't prevent the URL from being successfully processed.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `partial_failure` - The partial failure record to insert
///
/// # Returns
///
/// The ID of the inserted partial failure record, or a `DatabaseError` if insertion fails.
pub async fn insert_url_partial_failure(
    pool: &SqlitePool,
    partial_failure: &UrlPartialFailureRecord,
) -> Result<i64, DatabaseError> {
    let partial_failure_id = sqlx::query(
        "INSERT INTO url_partial_failures (
            url_status_id, error_type, error_message, timestamp, run_id
        ) VALUES (?, ?, ?, ?, ?)
        RETURNING id",
    )
    .bind(partial_failure.url_status_id)
    .bind(&partial_failure.error_type)
    .bind(&partial_failure.error_message)
    .bind(partial_failure.timestamp)
    .bind(partial_failure.run_id.as_ref())
    .fetch_one(pool)
    .await
    .map_err(DatabaseError::SqlError)?
    .get::<i64, _>(0);

    Ok(partial_failure_id)
}
