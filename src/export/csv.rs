//! CSV export functionality.
//!
//! Exports domain_status data to CSV format (simplified, flattened view).
//! One row per URL with all related data flattened into columns.

use anyhow::{Context, Result};
use csv::Writer;
use futures::TryStreamExt;
use sqlx::Row;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::storage::init_db_pool_with_path;

/// Exports data to CSV format.
///
/// # Arguments
///
/// * `db_path` - Path to the SQLite database
/// * `output` - Output file path (or stdout if None)
/// * `run_id` - Optional filter by run ID
/// * `domain` - Optional filter by domain
/// * `status` - Optional filter by HTTP status code
/// * `since` - Optional filter by timestamp (milliseconds since epoch)
///
/// # Returns
///
/// Returns the number of records exported, or an error if export fails.
pub async fn export_csv(
    db_path: &Path,
    output: Option<&PathBuf>,
    run_id: Option<&str>,
    domain: Option<&str>,
    status: Option<u16>,
    since: Option<i64>,
) -> Result<usize> {
    // Initialize database pool
    let pool = init_db_pool_with_path(db_path)
        .await
        .context("Failed to initialize database pool")?;

    // Build query with filters using sqlx QueryBuilder
    let mut query_builder = sqlx::QueryBuilder::new(
        "SELECT us.id, us.domain, us.final_domain, us.ip_address, us.reverse_dns_name,
                us.status, us.status_description, us.response_time, us.title, us.keywords,
                us.description, us.is_mobile_friendly, us.tls_version, us.ssl_cert_subject,
                us.ssl_cert_issuer, us.ssl_cert_valid_to, us.cipher_suite, us.key_algorithm,
                us.spf_record, us.dmarc_record, us.timestamp, us.run_id
         FROM url_status us",
    );

    // Add WHERE clauses
    let mut has_where = false;
    if let Some(run_id) = run_id {
        query_builder.push(" WHERE us.run_id = ");
        query_builder.push_bind(run_id);
        has_where = true;
    }
    if let Some(domain) = domain {
        if has_where {
            query_builder.push(" AND ");
        } else {
            query_builder.push(" WHERE ");
            has_where = true;
        }
        query_builder.push("(us.domain = ");
        query_builder.push_bind(domain);
        query_builder.push(" OR us.final_domain = ");
        query_builder.push_bind(domain);
        query_builder.push(")");
    }
    if let Some(status) = status {
        if has_where {
            query_builder.push(" AND ");
        } else {
            query_builder.push(" WHERE ");
            has_where = true;
        }
        query_builder.push("us.status = ");
        query_builder.push_bind(status);
    }
    if let Some(since) = since {
        if has_where {
            query_builder.push(" AND ");
        } else {
            query_builder.push(" WHERE ");
        }
        query_builder.push("us.timestamp >= ");
        query_builder.push_bind(since);
    }

    query_builder.push(" ORDER BY us.timestamp DESC");

    // Create CSV writer (use trait object to handle both File and Stdout)
    let mut writer: Writer<Box<dyn Write>> = if let Some(output_path) = output {
        let file = std::fs::File::create(output_path).context(format!(
            "Failed to create output file: {}",
            output_path.display()
        ))?;
        Writer::from_writer(Box::new(file) as Box<dyn Write>)
    } else {
        Writer::from_writer(Box::new(io::stdout()) as Box<dyn Write>)
    };

    // Write CSV header
    writer.write_record([
        "url",
        "initial_domain",
        "final_domain",
        "ip_address",
        "reverse_dns",
        "status",
        "status_description",
        "response_time_ms",
        "title",
        "keywords",
        "description",
        "is_mobile_friendly",
        "redirect_count",
        "final_redirect_url",
        "technologies",
        "technology_count",
        "tls_version",
        "ssl_cert_subject",
        "ssl_cert_issuer",
        "ssl_cert_valid_to",
        "cipher_suite",
        "key_algorithm",
        "certificate_sans",
        "certificate_san_count",
        "oids",
        "oid_count",
        "nameserver_count",
        "txt_record_count",
        "mx_record_count",
        "spf_record",
        "dmarc_record",
        "analytics_ids",
        "analytics_count",
        "social_media_links",
        "social_media_count",
        "security_warnings",
        "security_warning_count",
        "structured_data_types",
        "structured_data_count",
        "http_headers",
        "http_header_count",
        "security_headers",
        "security_header_count",
        "geoip_country_code",
        "geoip_country_name",
        "geoip_region",
        "geoip_city",
        "geoip_latitude",
        "geoip_longitude",
        "geoip_asn",
        "geoip_asn_org",
        "whois_registrar",
        "whois_creation_date",
        "whois_expiration_date",
        "whois_registrant_country",
        "timestamp",
        "run_id",
    ])?;

    // Query URL records with streaming
    // Use query builder to safely handle parameter binding
    let query = query_builder.build();
    let mut rows = query.fetch(&*pool);

    let mut record_count = 0;

    // Process each URL record
    while let Some(row) = rows.try_next().await? {
        let url_status_id: i64 = row.get("id");
        let initial_domain: String = row.get("domain");
        let final_domain: String = row.get("final_domain");
        let ip_address: String = row.get("ip_address");
        let reverse_dns: Option<String> = row.get("reverse_dns_name");
        let status: u16 = row.get("status");
        let status_desc: String = row.get("status_description");
        let response_time: f64 = row.get("response_time");
        let title: String = row.get("title");
        let keywords: Option<String> = row.get("keywords");
        let description: Option<String> = row.get("description");
        let is_mobile_friendly: bool = row.get("is_mobile_friendly");
        let tls_version: Option<String> = row.get("tls_version");
        let ssl_cert_subject: Option<String> = row.get("ssl_cert_subject");
        let ssl_cert_issuer: Option<String> = row.get("ssl_cert_issuer");
        let ssl_cert_valid_to: Option<i64> = row.get("ssl_cert_valid_to");
        let cipher_suite: Option<String> = row.get("cipher_suite");
        let key_algorithm: Option<String> = row.get("key_algorithm");
        let spf_record: Option<String> = row.get("spf_record");
        let dmarc_record: Option<String> = row.get("dmarc_record");
        let timestamp: i64 = row.get("timestamp");
        let run_id: Option<String> = row.get("run_id");

        // Query related data for this URL
        // Redirects
        let redirect_rows = sqlx::query(
            "SELECT url, sequence_order FROM url_redirect_chain
             WHERE url_status_id = ? ORDER BY sequence_order",
        )
        .bind(url_status_id)
        .fetch_all(&*pool)
        .await?;

        let redirect_count = redirect_rows.len();
        let final_redirect_url = redirect_rows
            .last()
            .map(|r| r.get::<String, _>("url"))
            .unwrap_or_else(|| final_domain.clone());

        // Technologies
        let tech_rows = sqlx::query(
            "SELECT technology_name FROM url_technologies
             WHERE url_status_id = ? ORDER BY technology_name",
        )
        .bind(url_status_id)
        .fetch_all(&*pool)
        .await?;

        let technologies: Vec<String> = tech_rows
            .iter()
            .map(|r| r.get::<String, _>("technology_name"))
            .collect();
        let technology_count = technologies.len();
        let technologies_str = technologies.join(",");

        // Nameservers count
        let nameserver_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_nameservers WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&*pool)
                .await?;

        // TXT records count
        let txt_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_txt_records WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&*pool)
                .await?;

        // MX records count
        let mx_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_mx_records WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&*pool)
                .await?;

        // Certificate SANs
        let san_rows = sqlx::query(
            "SELECT domain_name FROM url_certificate_sans
             WHERE url_status_id = ? ORDER BY domain_name",
        )
        .bind(url_status_id)
        .fetch_all(&*pool)
        .await?;

        let certificate_sans: Vec<String> = san_rows
            .iter()
            .map(|r| r.get::<String, _>("domain_name"))
            .collect();
        let certificate_san_count = certificate_sans.len();
        let certificate_sans_str = certificate_sans.join(",");

        // OIDs
        let oid_rows = sqlx::query(
            "SELECT oid FROM url_oids
             WHERE url_status_id = ? ORDER BY oid",
        )
        .bind(url_status_id)
        .fetch_all(&*pool)
        .await?;

        let oids: Vec<String> = oid_rows.iter().map(|r| r.get::<String, _>("oid")).collect();
        let oid_count = oids.len();
        let oids_str = oids.join(",");

        // Analytics IDs
        let analytics_rows = sqlx::query(
            "SELECT provider, tracking_id FROM url_analytics_ids
             WHERE url_status_id = ? ORDER BY provider, tracking_id",
        )
        .bind(url_status_id)
        .fetch_all(&*pool)
        .await?;

        let analytics_ids: Vec<String> = analytics_rows
            .iter()
            .map(|r| {
                let provider: String = r.get("provider");
                let tracking_id: String = r.get("tracking_id");
                format!("{}:{}", provider, tracking_id)
            })
            .collect();
        let analytics_count = analytics_ids.len();
        let analytics_ids_str = analytics_ids.join(",");

        // Social Media Links
        let social_rows = sqlx::query(
            "SELECT platform, url FROM url_social_media_links
             WHERE url_status_id = ? ORDER BY platform, url",
        )
        .bind(url_status_id)
        .fetch_all(&*pool)
        .await?;

        let social_media_links: Vec<String> = social_rows
            .iter()
            .map(|r| {
                let platform: String = r.get("platform");
                let url: String = r.get("url");
                format!("{}:{}", platform, url)
            })
            .collect();
        let social_media_count = social_media_links.len();
        let social_media_links_str = social_media_links.join(",");

        // Security Warnings
        let warning_rows = sqlx::query(
            "SELECT warning_code FROM url_security_warnings
             WHERE url_status_id = ? ORDER BY warning_code",
        )
        .bind(url_status_id)
        .fetch_all(&*pool)
        .await?;

        let security_warnings: Vec<String> = warning_rows
            .iter()
            .map(|r| r.get::<String, _>("warning_code"))
            .collect();
        let security_warning_count = security_warnings.len();
        let security_warnings_str = security_warnings.join(",");

        // Structured Data (count by type)
        let structured_rows = sqlx::query(
            "SELECT DISTINCT data_type FROM url_structured_data
             WHERE url_status_id = ? ORDER BY data_type",
        )
        .bind(url_status_id)
        .fetch_all(&*pool)
        .await?;

        let structured_data_types: Vec<String> = structured_rows
            .iter()
            .map(|r| r.get::<String, _>("data_type"))
            .collect();
        let structured_data_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_structured_data WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&*pool)
                .await?;
        let structured_data_types_str = structured_data_types.join(",");

        // HTTP Headers (key headers only: Content-Type, Server, X-Powered-By, etc.)
        let http_header_rows = sqlx::query(
            "SELECT header_name, header_value FROM url_http_headers
             WHERE url_status_id = ?
             AND header_name IN ('Content-Type', 'Server', 'X-Powered-By', 'X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security', 'Content-Security-Policy')
             ORDER BY header_name"
        )
        .bind(url_status_id)
        .fetch_all(&*pool)
        .await?;

        let http_headers: Vec<String> = http_header_rows
            .iter()
            .map(|r| {
                let name: String = r.get("header_name");
                let value: String = r.get("header_value");
                format!("{}:{}", name, value)
            })
            .collect();
        let http_header_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_http_headers WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&*pool)
                .await?;
        let http_headers_str = http_headers.join(",");

        // Security Headers (key headers only)
        let security_header_rows = sqlx::query(
            "SELECT header_name, header_value FROM url_security_headers
             WHERE url_status_id = ?
             AND header_name IN ('Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security', 'Referrer-Policy', 'Permissions-Policy')
             ORDER BY header_name"
        )
        .bind(url_status_id)
        .fetch_all(&*pool)
        .await?;

        let security_headers: Vec<String> = security_header_rows
            .iter()
            .map(|r| {
                let name: String = r.get("header_name");
                let value: String = r.get("header_value");
                format!("{}:{}", name, value)
            })
            .collect();
        let security_header_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_security_headers WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&*pool)
                .await?;
        let security_headers_str = security_headers.join(",");

        // GeoIP data
        let geoip_row = sqlx::query(
            "SELECT country_code, country_name, region, city, latitude, longitude, asn, asn_org
             FROM url_geoip WHERE url_status_id = ?",
        )
        .bind(url_status_id)
        .fetch_optional(&*pool)
        .await?;

        let (
            geoip_country_code,
            geoip_country_name,
            geoip_region,
            geoip_city,
            geoip_latitude,
            geoip_longitude,
            geoip_asn,
            geoip_asn_org,
        ) = if let Some(row) = geoip_row {
            (
                row.get::<Option<String>, _>("country_code"),
                row.get::<Option<String>, _>("country_name"),
                row.get::<Option<String>, _>("region"),
                row.get::<Option<String>, _>("city"),
                row.get::<Option<f64>, _>("latitude"),
                row.get::<Option<f64>, _>("longitude"),
                row.get::<Option<i32>, _>("asn"),
                row.get::<Option<String>, _>("asn_org"),
            )
        } else {
            (None, None, None, None, None, None, None, None)
        };

        // WHOIS data
        let whois_row = sqlx::query(
            "SELECT registrar, creation_date, expiration_date, registrant_country
             FROM url_whois WHERE url_status_id = ?",
        )
        .bind(url_status_id)
        .fetch_optional(&*pool)
        .await?;

        let (whois_registrar, whois_creation_date, whois_expiration_date, whois_registrant_country) =
            if let Some(row) = whois_row {
                (
                    row.get::<Option<String>, _>("registrar"),
                    row.get::<Option<i64>, _>("creation_date"),
                    row.get::<Option<i64>, _>("expiration_date"),
                    row.get::<Option<String>, _>("registrant_country"),
                )
            } else {
                (None, None, None, None)
            };

        // Format URL (use final_domain as base)
        let url = format!("https://{}", final_domain);

        // Format SSL cert valid_to date
        let ssl_cert_valid_to_str = ssl_cert_valid_to
            .map(|ts| {
                chrono::DateTime::from_timestamp(ts / 1000, 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| ts.to_string())
            })
            .unwrap_or_default();

        // Format WHOIS dates
        let whois_creation_str = whois_creation_date
            .map(|ts| {
                chrono::DateTime::from_timestamp(ts, 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string())
                    .unwrap_or_default()
            })
            .unwrap_or_default();

        let whois_expiration_str = whois_expiration_date
            .map(|ts| {
                chrono::DateTime::from_timestamp(ts, 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string())
                    .unwrap_or_default()
            })
            .unwrap_or_default();

        // Write CSV row
        writer.write_record(&[
            url,
            initial_domain,
            final_domain,
            ip_address,
            reverse_dns.unwrap_or_default(),
            status.to_string(),
            status_desc,
            format!("{:.2}", response_time),
            title,
            keywords.unwrap_or_default(),
            description.unwrap_or_default(),
            if is_mobile_friendly { "true" } else { "false" }.to_string(),
            redirect_count.to_string(),
            final_redirect_url,
            technologies_str,
            technology_count.to_string(),
            tls_version.unwrap_or_default(),
            ssl_cert_subject.unwrap_or_default(),
            ssl_cert_issuer.unwrap_or_default(),
            ssl_cert_valid_to_str,
            cipher_suite.unwrap_or_default(),
            key_algorithm.unwrap_or_default(),
            certificate_sans_str,
            certificate_san_count.to_string(),
            oids_str,
            oid_count.to_string(),
            nameserver_count.to_string(),
            txt_count.to_string(),
            mx_count.to_string(),
            spf_record.unwrap_or_default(),
            dmarc_record.unwrap_or_default(),
            analytics_ids_str,
            analytics_count.to_string(),
            social_media_links_str,
            social_media_count.to_string(),
            security_warnings_str,
            security_warning_count.to_string(),
            structured_data_types_str,
            structured_data_count.to_string(),
            http_headers_str,
            http_header_count.to_string(),
            security_headers_str,
            security_header_count.to_string(),
            geoip_country_code.unwrap_or_default(),
            geoip_country_name.unwrap_or_default(),
            geoip_region.unwrap_or_default(),
            geoip_city.unwrap_or_default(),
            geoip_latitude.map(|v| v.to_string()).unwrap_or_default(),
            geoip_longitude.map(|v| v.to_string()).unwrap_or_default(),
            geoip_asn.map(|v| v.to_string()).unwrap_or_default(),
            geoip_asn_org.unwrap_or_default(),
            whois_registrar.unwrap_or_default(),
            whois_creation_str,
            whois_expiration_str,
            whois_registrant_country.unwrap_or_default(),
            timestamp.to_string(),
            run_id.unwrap_or_default(),
        ])?;

        record_count += 1;
    }

    writer.flush()?;

    Ok(record_count)
}
