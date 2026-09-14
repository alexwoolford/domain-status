//! Main URL record insertion.
//!
//! This module handles inserting URL status records and related satellite tables.
//! In-transaction satellites live in `URL_STATUS_CORE_SATELLITE_TABLES`; enrichment
//! satellites (`GeoIP`, WHOIS, secrets, etc.) live in
//! `URL_STATUS_ENRICHMENT_SATELLITE_TABLES` and are replaced after that transaction
//! commits, in a second writer transaction.

mod columns;
mod core_satellites;
mod satellite;
mod upsert;

#[cfg(test)]
pub(crate) use columns::{
    url_status_column_names, url_status_insert_sql, url_status_update_sql, URL_STATUS_COLUMN_DEFS,
};
pub(crate) use core_satellites::URL_STATUS_ENRICHMENT_SATELLITE_TABLES;
#[cfg(test)]
pub(crate) use core_satellites::{url_status_satellite_tables, URL_STATUS_CORE_SATELLITE_TABLES};
pub use upsert::{insert_url_record, UrlRecordInsertParams};
pub(crate) use upsert::{insert_url_record_with_outcome, SatelliteWriteFailure, UrlUpsertOutcome};

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use sqlx::{Row, SqlitePool};
    use std::collections::{HashMap, HashSet};

    use crate::storage::migrations::run_migrations;
    use crate::storage::models::UrlRecord;
    use crate::storage::CookieInfo;

    fn insert_sql_column_names(sql: &str) -> Vec<&str> {
        let marker = "INSERT INTO url_status (";
        let start = sql
            .find(marker)
            .unwrap_or_else(|| panic!("missing `{marker}` in insert SQL: {sql}"));
        let rest = &sql[start + marker.len()..];
        let end = rest
            .find(')')
            .unwrap_or_else(|| panic!("unclosed column list in insert SQL: {sql}"));
        rest[..end]
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect()
    }

    fn update_sql_set_column_names(sql: &str) -> Vec<&str> {
        let start = sql
            .find("SET")
            .unwrap_or_else(|| panic!("missing SET in update SQL: {sql}"));
        let rest = &sql[start + 3..];
        let end = rest
            .find("WHERE")
            .unwrap_or_else(|| panic!("missing WHERE in update SQL: {sql}"));
        rest[..end]
            .split(',')
            .map(|assignment| assignment.split('=').next().unwrap_or(assignment).trim())
            .filter(|s| !s.is_empty())
            .collect()
    }

    #[tokio::test]
    async fn url_status_column_defs_match_insert_sql_and_migrated_schema() {
        let names: Vec<_> = url_status_column_names().collect();
        assert_eq!(names.len(), URL_STATUS_COLUMN_DEFS.len());
        let mut seen = HashSet::new();
        for (i, name) in names.iter().enumerate() {
            assert_eq!(*name, URL_STATUS_COLUMN_DEFS[i].name);
            assert!(seen.insert(*name), "duplicate url_status column: {name}");
        }

        assert_eq!(
            insert_sql_column_names(&url_status_insert_sql()),
            names,
            "INSERT column list must follow URL_STATUS_COLUMN_DEFS order"
        );

        let expected_update: Vec<_> = names
            .iter()
            .copied()
            .filter(|col| *col != "initial_domain")
            .collect();
        assert_eq!(
            update_sql_set_column_names(&url_status_update_sql()),
            expected_update,
            "UPDATE SET list must follow URL_STATUS_COLUMN_DEFS minus initial_domain"
        );

        let pool = create_test_pool().await;
        let schema_rows = sqlx::query("PRAGMA table_info(url_status)")
            .fetch_all(&pool)
            .await
            .expect("PRAGMA table_info(url_status)");
        let schema: HashSet<String> = schema_rows
            .iter()
            .map(|row| row.get::<String, _>("name"))
            .collect();
        for name in &names {
            assert!(
                schema.contains(*name),
                "{name} is in URL_STATUS_COLUMN_DEFS but missing from migrated url_status"
            );
        }
    }

    /// Creates an in-memory `SQLite` database pool for testing
    async fn create_test_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");
        pool
    }

    /// Creates a test run record for FK constraint
    async fn create_test_run(pool: &SqlitePool, run_id: &str) {
        sqlx::query(
            "INSERT INTO runs (run_id, start_time_ms) VALUES (?, ?)
             ON CONFLICT(run_id) DO NOTHING",
        )
        .bind(run_id)
        .bind(1704067200000i64)
        .execute(pool)
        .await
        .expect("Failed to insert test run");
    }

    /// Creates a minimal `UrlRecord` for testing
    fn create_test_url_record() -> UrlRecord {
        let mut record = UrlRecord::test_default();
        record.reverse_dns_name = Some("example.com".to_string());
        record.response_time = 0.123;
        record.title = "Example Domain".to_string();
        record.description = Some("Example description".to_string());
        record.tls_version = Some(crate::models::TlsVersion::Tls13);
        record.ssl_cert_subject = Some("CN=example.com".to_string());
        record.ssl_cert_issuer = Some("CN=Let's Encrypt".to_string());
        record.ssl_cert_valid_from = NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0);
        record.ssl_cert_valid_to = NaiveDate::from_ymd_opt(2025, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0);
        record.timestamp = 1_704_067_200_000; // 2024-01-01 00:00:00 UTC in milliseconds
        record.nameservers = Some(r#"["ns1.example.com", "ns2.example.com"]"#.to_string());
        record.txt_records = Some(r#"["v=spf1 include:_spf.example.com ~all"]"#.to_string());
        record.mx_records =
            Some(r#"[{"priority": 10, "hostname": "mail.example.com"}]"#.to_string());
        record.spf_record = Some("v=spf1 include:_spf.example.com ~all".to_string());
        record.dmarc_record = Some("v=DMARC1; p=none".to_string());
        record.cipher_suite = Some("TLS_AES_256_GCM_SHA384".to_string());
        record.key_algorithm = Some(crate::models::KeyAlgorithm::ECDSA);
        record.run_id = Some("test-run-1".to_string());
        record
    }

    #[tokio::test]
    async fn test_insert_url_record_basic() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let record = create_test_url_record();
        let security_headers = HashMap::new();
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = Vec::new();
        let technologies = Vec::new();
        let sans = Vec::new();

        let result = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        })
        .await;

        assert!(result.is_ok());
        let url_status_id = result.unwrap();
        assert!(url_status_id > 0);

        // Verify the record was inserted
        let row = sqlx::query(
            "SELECT initial_domain, final_domain, http_status, title FROM url_status WHERE id = ?",
        )
        .bind(url_status_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch inserted record");

        assert_eq!(row.get::<String, _>("initial_domain"), "example.com");
        assert_eq!(row.get::<String, _>("final_domain"), "example.com");
        assert_eq!(row.get::<i64, _>("http_status"), 200);
        assert_eq!(row.get::<String, _>("title"), "Example Domain");
    }

    #[tokio::test]
    async fn test_insert_high_value_capture_fields() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let mut record = create_test_url_record();
        record.initial_url = Some("http://example.com/start".to_string());
        record.final_url = Some("https://example.com/land?x=1".to_string());
        record.meta_robots = Some("noindex".to_string());

        let script_hosts = vec![crate::storage::ScriptHostInfo {
            host: "cdn.example.com".to_string(),
            registrable_domain: Some("example.com".to_string()),
            is_first_party: true,
        }];

        let id = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &HashMap::new(),
            http_headers: &HashMap::new(),
            oids: &HashSet::new(),
            redirect_chain: &[],
            technologies: &[],
            subject_alternative_names: &[],
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            script_hosts: &script_hosts,
            security_txt: None,
            robots_txt: None,
        })
        .await
        .expect("insert");

        let row =
            sqlx::query("SELECT initial_url, final_url, meta_robots FROM url_status WHERE id = ?")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("fetch");
        assert_eq!(
            row.get::<Option<String>, _>("initial_url").as_deref(),
            Some("http://example.com/start")
        );
        assert_eq!(
            row.get::<Option<String>, _>("final_url").as_deref(),
            Some("https://example.com/land?x=1")
        );
        assert_eq!(
            row.get::<Option<String>, _>("meta_robots").as_deref(),
            Some("noindex")
        );

        let host_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_script_hosts WHERE url_status_id = ?")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(host_count, 1);
    }

    #[tokio::test]
    async fn test_insert_url_record_scan_completeness_columns() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let mut record = create_test_url_record();
        record.body_truncated = true;
        record.external_scripts_eligible = 5;
        record.external_scripts_scanned = 3;

        let id = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &HashMap::new(),
            http_headers: &HashMap::new(),
            oids: &HashSet::new(),
            redirect_chain: &[],
            technologies: &[],
            subject_alternative_names: &[],
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        })
        .await
        .expect("insert");

        let row = sqlx::query(
            "SELECT body_truncated, external_scripts_eligible, external_scripts_scanned
             FROM url_status WHERE id = ?",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("select");

        assert_eq!(row.get::<i64, _>("body_truncated"), 1);
        assert_eq!(row.get::<i64, _>("external_scripts_eligible"), 5);
        assert_eq!(row.get::<i64, _>("external_scripts_scanned"), 3);

        // Upsert flips completeness fields; excluded.* must win.
        record.body_truncated = false;
        record.external_scripts_eligible = 7;
        record.external_scripts_scanned = 2;
        record.title = "Rescan".to_string();
        let id2 = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &HashMap::new(),
            http_headers: &HashMap::new(),
            oids: &HashSet::new(),
            redirect_chain: &[],
            technologies: &[],
            subject_alternative_names: &[],
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        })
        .await
        .expect("upsert");
        assert_eq!(id, id2);

        let row2 = sqlx::query(
            "SELECT body_truncated, external_scripts_eligible, external_scripts_scanned, title
             FROM url_status WHERE id = ?",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("select after upsert");

        assert_eq!(row2.get::<i64, _>("body_truncated"), 0);
        assert_eq!(row2.get::<i64, _>("external_scripts_eligible"), 7);
        assert_eq!(row2.get::<i64, _>("external_scripts_scanned"), 2);
        assert_eq!(row2.get::<String, _>("title"), "Rescan");
    }

    #[tokio::test]
    async fn test_insert_url_record_with_technologies() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let record = create_test_url_record();
        let security_headers = HashMap::new();
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = Vec::new();
        let technologies = vec![
            crate::fingerprint::DetectedTechnology {
                name: "WordPress".to_string(),
                version: None,
                category: None,
                is_implied: false,
            },
            crate::fingerprint::DetectedTechnology {
                name: "PHP".to_string(),
                version: None,
                category: None,
                is_implied: false,
            },
        ];
        let sans = Vec::new();

        let url_status_id = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        })
        .await
        .expect("Failed to insert record");

        // Verify technologies were inserted
        let tech_rows =
            sqlx::query("SELECT technology_name FROM url_technologies WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_all(&pool)
                .await
                .expect("Failed to fetch technologies");

        assert_eq!(tech_rows.len(), 2);
        let tech_names: Vec<String> = tech_rows
            .iter()
            .map(|row| row.get::<String, _>("technology_name"))
            .collect();
        assert!(tech_names.contains(&"WordPress".to_string()));
        assert!(tech_names.contains(&"PHP".to_string()));
    }

    #[tokio::test]
    async fn test_insert_url_record_with_redirect_chain() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let record = create_test_url_record();
        let security_headers = HashMap::new();
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = vec![
            ("http://example.com".to_string(), 301u16),
            ("https://example.com".to_string(), 200u16),
        ];
        let technologies = Vec::new();
        let sans = Vec::new();

        let url_status_id = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        })
        .await
        .expect("Failed to insert record");

        // Verify redirect chain was inserted
        let redirect_rows = sqlx::query(
            "SELECT redirect_url FROM url_redirect_chain WHERE url_status_id = ? ORDER BY sequence_order",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch redirect chain");

        assert_eq!(redirect_rows.len(), 2);
        assert_eq!(
            redirect_rows[0].get::<String, _>("redirect_url"),
            "http://example.com"
        );
        assert_eq!(
            redirect_rows[1].get::<String, _>("redirect_url"),
            "https://example.com"
        );
    }

    #[tokio::test]
    async fn test_insert_url_record_with_security_headers() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let record = create_test_url_record();
        let mut security_headers = HashMap::new();
        security_headers.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=31536000".to_string(),
        );
        security_headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = Vec::new();
        let technologies = Vec::new();
        let sans = Vec::new();

        let url_status_id = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        })
        .await
        .expect("Failed to insert record");

        // Verify security headers were inserted
        let header_rows = sqlx::query(
            "SELECT header_name, header_value FROM url_security_headers WHERE url_status_id = ?",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch security headers");

        assert_eq!(header_rows.len(), 2);
        let mut header_map = HashMap::new();
        for row in header_rows {
            let name: String = row.get("header_name");
            let value: String = row.get("header_value");
            header_map.insert(name, value);
        }
        assert_eq!(
            header_map.get("Strict-Transport-Security"),
            Some(&"max-age=31536000".to_string())
        );
        assert_eq!(
            header_map.get("X-Content-Type-Options"),
            Some(&"nosniff".to_string())
        );
    }

    #[tokio::test]
    async fn test_insert_url_record_upsert() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let mut record = create_test_url_record();
        let security_headers = HashMap::new();
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = Vec::new();
        let technologies = Vec::new();
        let sans = Vec::new();

        // Insert first time
        let first = insert_url_record_with_outcome(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        })
        .await
        .expect("Failed to insert record");
        assert!(first.inserted);
        let id1 = first.id;

        // Update record and insert again (same final_domain and timestamp)
        record.title = "Updated Title".to_string();
        record.status = 301;
        let second = insert_url_record_with_outcome(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        })
        .await
        .expect("Failed to upsert record");
        assert!(!second.inserted);
        let id2 = second.id;

        // Should return same ID (UPSERT)
        assert_eq!(id1, id2);

        // Verify the record was updated
        let row = sqlx::query("SELECT title, http_status FROM url_status WHERE id = ?")
            .bind(id1)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch updated record");

        assert_eq!(row.get::<String, _>("title"), "Updated Title");
        assert_eq!(row.get::<i64, _>("http_status"), 301);
    }

    #[tokio::test]
    async fn test_insert_cookies_same_name_updates_domain_and_path() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let record = create_test_url_record();
        let security_headers = HashMap::new();
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let cookies = [
            CookieInfo {
                name: "sid".to_string(),
                secure: false,
                http_only: false,
                same_site: Some("Lax".to_string()),
                domain: Some("a.example".to_string()),
                path: Some("/a".to_string()),
            },
            CookieInfo {
                name: "sid".to_string(),
                secure: true,
                http_only: true,
                same_site: Some("None".to_string()),
                domain: Some("b.example".to_string()),
                path: Some("/b".to_string()),
            },
        ];

        let id = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &[],
            technologies: &[],
            subject_alternative_names: &[],
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &cookies,
            resource_hints: &[],
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        })
        .await
        .expect("insert cookies");

        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM url_cookies WHERE url_status_id = ?")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("count cookies");
        assert_eq!(n, 1, "name-only UNIQUE collapses duplicate cookie names");

        let row = sqlx::query(
            "SELECT cookie_name, secure, http_only, same_site, domain, path
             FROM url_cookies WHERE url_status_id = ?",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("fetch cookie");

        assert_eq!(row.get::<String, _>("cookie_name"), "sid");
        assert_eq!(row.get::<i64, _>("secure"), 1);
        assert_eq!(row.get::<i64, _>("http_only"), 1);
        assert_eq!(row.get::<String, _>("same_site"), "None");
        assert_eq!(row.get::<String, _>("domain"), "b.example");
        assert_eq!(row.get::<String, _>("path"), "/b");
    }

    #[tokio::test]
    async fn test_insert_url_record_same_final_different_initial_keeps_two_rows() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let security_headers = HashMap::new();
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = Vec::new();
        let technologies = Vec::new();
        let sans = Vec::new();

        let mut a = create_test_url_record();
        a.initial_domain = "parked-a.com".to_string();
        a.final_domain = "parked.example.com".to_string();
        a.initial_url = Some("https://parked-a.com".to_string());
        a.final_url = Some("https://parked.example.com/a".to_string());

        let mut b = create_test_url_record();
        b.initial_domain = "parked-b.com".to_string();
        b.final_domain = "parked.example.com".to_string();
        b.initial_url = Some("https://parked-b.com".to_string());
        b.final_url = Some("https://parked.example.com/b".to_string());

        let id_a = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &a,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        })
        .await
        .expect("insert a");

        let id_b = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &b,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        })
        .await
        .expect("insert b");

        assert_ne!(id_a, id_b);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM url_status")
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(count, 2);
    }

    /// Build insert params with empty optional satellites (tests only).
    fn insert_params_with_tech_redirects<'a>(
        pool: &'a SqlitePool,
        record: &'a UrlRecord,
        empty_headers: &'a HashMap<String, String>,
        empty_oids: &'a HashSet<String>,
        empty_sans: &'a [String],
        redirect_chain: &'a [(String, u16)],
        technologies: &'a [crate::fingerprint::DetectedTechnology],
    ) -> UrlRecordInsertParams<'a> {
        UrlRecordInsertParams {
            pool,
            record,
            security_headers: empty_headers,
            http_headers: empty_headers,
            oids: empty_oids,
            redirect_chain,
            technologies,
            subject_alternative_names: empty_sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        }
    }

    /// Adversarial: UPSERT must DELETE stale satellite rows before re-inserting.
    /// Without core satellite DELETE on UPSERT, rescans leave orphan techs/redirects.
    #[tokio::test]
    async fn test_upsert_clears_stale_satellite_rows() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let record = create_test_url_record();
        let empty_headers = HashMap::new();
        let empty_oids = HashSet::new();
        let empty_sans: Vec<String> = Vec::new();

        let tech_a = vec![crate::fingerprint::DetectedTechnology {
            name: "TechA".to_string(),
            version: None,
            category: None,
            is_implied: false,
        }];
        let redirects_first: Vec<(String, u16)> = vec![
            ("http://old.example.com".to_string(), 301),
            ("https://example.com".to_string(), 200),
        ];

        let id1 = insert_url_record(insert_params_with_tech_redirects(
            &pool,
            &record,
            &empty_headers,
            &empty_oids,
            &empty_sans,
            &redirects_first,
            &tech_a,
        ))
        .await
        .expect("first insert");

        let tech_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_technologies WHERE url_status_id = ?")
                .bind(id1)
                .fetch_one(&pool)
                .await
                .expect("count techs");
        let redirect_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_redirect_chain WHERE url_status_id = ?")
                .bind(id1)
                .fetch_one(&pool)
                .await
                .expect("count redirects");
        assert_eq!(tech_count, 1);
        assert_eq!(redirect_count, 2);

        let tech_b = vec![crate::fingerprint::DetectedTechnology {
            name: "TechB".to_string(),
            version: Some("2.0".to_string()),
            category: None,
            is_implied: false,
        }];
        let redirects_second: Vec<(String, u16)> = Vec::new();

        let id2 = insert_url_record(insert_params_with_tech_redirects(
            &pool,
            &record,
            &empty_headers,
            &empty_oids,
            &empty_sans,
            &redirects_second,
            &tech_b,
        ))
        .await
        .expect("upsert");

        assert_eq!(id1, id2, "UPSERT should keep the same url_status id");

        let tech_names: Vec<String> = sqlx::query_scalar(
            "SELECT technology_name FROM url_technologies WHERE url_status_id = ? ORDER BY 1",
        )
        .bind(id2)
        .fetch_all(&pool)
        .await
        .expect("fetch techs after upsert");
        assert_eq!(
            tech_names,
            vec!["TechB".to_string()],
            "stale TechA must be gone; only TechB remains"
        );

        let redirect_count_after: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_redirect_chain WHERE url_status_id = ?")
                .bind(id2)
                .fetch_one(&pool)
                .await
                .expect("count redirects after upsert");
        assert_eq!(
            redirect_count_after, 0,
            "stale redirect hops must be deleted on UPSERT with empty chain"
        );
    }

    /// DNS/header/cert satellites: `url_technologies`, `url_nameservers`, `url_txt_records`,
    /// `url_mx_records`, `url_security_headers`, `url_http_headers`, `url_certificate_oids`.
    async fn seed_dns_and_header_satellite_tables(pool: &SqlitePool, url_status_id: i64) {
        sqlx::query("INSERT INTO url_technologies (url_status_id, technology_name) VALUES (?, ?)")
            .bind(url_status_id)
            .bind("SeedTech")
            .execute(pool)
            .await
            .expect("seed url_technologies");

        sqlx::query("INSERT INTO url_nameservers (url_status_id, nameserver) VALUES (?, ?)")
            .bind(url_status_id)
            .bind("ns1.seed.example")
            .execute(pool)
            .await
            .expect("seed url_nameservers");

        sqlx::query(
            "INSERT INTO url_txt_records (url_status_id, record_type, record_value) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("SPF")
        .bind("v=spf1 -all")
        .execute(pool)
        .await
        .expect("seed url_txt_records");

        sqlx::query(
            "INSERT INTO url_mx_records (url_status_id, priority, mail_exchange) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind(10i64)
        .bind("mail.seed.example")
        .execute(pool)
        .await
        .expect("seed url_mx_records");

        sqlx::query(
            "INSERT INTO url_security_headers (url_status_id, header_name, header_value) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("X-Seed-Security")
        .bind("seed-value")
        .execute(pool)
        .await
        .expect("seed url_security_headers");

        sqlx::query(
            "INSERT INTO url_http_headers (url_status_id, header_name, header_value) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("X-Seed-Header")
        .bind("seed-value")
        .execute(pool)
        .await
        .expect("seed url_http_headers");

        sqlx::query("INSERT INTO url_certificate_oids (url_status_id, oid) VALUES (?, ?)")
            .bind(url_status_id)
            .bind("1.2.3.4.5")
            .execute(pool)
            .await
            .expect("seed url_certificate_oids");
    }

    /// Cert/redirect/DNS-record satellites: `url_redirect_chain`, `url_certificate_sans`,
    /// `url_cname_records`, `url_ipv6_addresses`, `url_caa_records`, `url_csp_domains`,
    /// `url_cookies`.
    async fn seed_redirect_and_record_satellite_tables(pool: &SqlitePool, url_status_id: i64) {
        sqlx::query(
            "INSERT INTO url_redirect_chain (url_status_id, sequence_order, redirect_url) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind(1i64)
        .bind("https://seed.example/hop")
        .execute(pool)
        .await
        .expect("seed url_redirect_chain");

        sqlx::query("INSERT INTO url_certificate_sans (url_status_id, san_value) VALUES (?, ?)")
            .bind(url_status_id)
            .bind("seed.example")
            .execute(pool)
            .await
            .expect("seed url_certificate_sans");

        sqlx::query("INSERT INTO url_cname_records (url_status_id, cname_target) VALUES (?, ?)")
            .bind(url_status_id)
            .bind("cdn.seed.example")
            .execute(pool)
            .await
            .expect("seed url_cname_records");

        sqlx::query("INSERT INTO url_ipv6_addresses (url_status_id, ipv6_address) VALUES (?, ?)")
            .bind(url_status_id)
            .bind("::1")
            .execute(pool)
            .await
            .expect("seed url_ipv6_addresses");

        sqlx::query(
            "INSERT INTO url_caa_records (url_status_id, flag, tag, value) VALUES (?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind(0i64)
        .bind("issue")
        .bind("seed-ca.example")
        .execute(pool)
        .await
        .expect("seed url_caa_records");

        sqlx::query(
            "INSERT INTO url_csp_domains (url_status_id, directive, fqdn, registrable_domain) VALUES (?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("script-src")
        .bind("cdn.seed.example")
        .bind("seed.example")
        .execute(pool)
        .await
        .expect("seed url_csp_domains");

        sqlx::query(
            "INSERT INTO url_cookies (url_status_id, cookie_name, secure, http_only, same_site, domain, path) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("seed_session")
        .bind(true)
        .bind(true)
        .bind("Strict")
        .bind("seed.example")
        .bind("/")
        .execute(pool)
        .await
        .expect("seed url_cookies");
    }

    /// Body-content satellites: `url_resource_hints`, `url_script_hosts`, `url_analytics_ids`,
    /// `url_structured_data`, `url_social_media_links`, `url_contact_links`.
    async fn seed_body_content_satellite_tables(pool: &SqlitePool, url_status_id: i64) {
        sqlx::query(
            "INSERT INTO url_resource_hints (url_status_id, hint_type, href) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("preconnect")
        .bind("https://cdn.seed.example")
        .execute(pool)
        .await
        .expect("seed url_resource_hints");

        sqlx::query(
            "INSERT INTO url_script_hosts (url_status_id, host, registrable_domain, is_first_party) VALUES (?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("cdn.seed.example")
        .bind("seed.example")
        .bind(true)
        .execute(pool)
        .await
        .expect("seed url_script_hosts");

        sqlx::query(
            "INSERT INTO url_security_txt (
                url_status_id, source_url, http_status, contacts, expires, encryption,
                acknowledgments, preferred_languages, canonical, policy, hiring, raw_body
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("https://seed.example/.well-known/security.txt")
        .bind(200i64)
        .bind("mailto:security@seed.example")
        .bind(Option::<String>::None)
        .bind("")
        .bind("")
        .bind(Option::<String>::None)
        .bind("")
        .bind("")
        .bind("")
        .bind("Contact: mailto:security@seed.example\n")
        .execute(pool)
        .await
        .expect("seed url_security_txt");

        sqlx::query(
            "INSERT INTO url_robots_txt (url_status_id, http_status, raw_body) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind(200i64)
        .bind("User-agent: *\nDisallow: /admin\n")
        .execute(pool)
        .await
        .expect("seed url_robots_txt");

        sqlx::query(
            "INSERT INTO url_robots_directives (url_status_id, directive, value) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("disallow")
        .bind("/admin")
        .execute(pool)
        .await
        .expect("seed url_robots_directives");

        sqlx::query(
            "INSERT INTO url_analytics_ids (url_status_id, provider, tracking_id) VALUES (?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("Seed Analytics")
        .bind("SEED-1")
        .execute(pool)
        .await
        .expect("seed url_analytics_ids");

        sqlx::query(
            "INSERT INTO url_structured_data (url_status_id, data_type, property_name, property_value) VALUES (?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("open_graph")
        .bind("og:title")
        .bind("Seed Title")
        .execute(pool)
        .await
        .expect("seed url_structured_data");

        sqlx::query(
            "INSERT INTO url_social_media_links (url_status_id, platform, profile_url, identifier) VALUES (?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("Seed Platform")
        .bind("https://seed.example/profile")
        .bind("seeduser")
        .execute(pool)
        .await
        .expect("seed url_social_media_links");

        sqlx::query(
            "INSERT INTO url_contact_links (url_status_id, contact_type, contact_value, raw_href) VALUES (?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("email")
        .bind("seed@example.com")
        .bind("mailto:seed@example.com")
        .execute(pool)
        .await
        .expect("seed url_contact_links");
    }

    /// Enrichment satellites populated outside the main insert transaction:
    /// `url_exposed_secrets`, `url_partial_failures`, `url_favicons`, `url_geoip`, `url_whois`.
    async fn seed_enrichment_satellite_tables(pool: &SqlitePool, url_status_id: i64) {
        sqlx::query(
            "INSERT INTO url_exposed_secrets (url_status_id, secret_type, matched_value, severity, location, context) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("seed_secret")
        .bind("seed-matched-value")
        .bind("low")
        .bind("inline_script")
        .bind("...seed context...")
        .execute(pool)
        .await
        .expect("seed url_exposed_secrets");

        sqlx::query(
            "INSERT INTO url_partial_failures (url_status_id, error_type, error_message, observed_at_ms) VALUES (?, ?, ?, ?)",
        )
        .bind(url_status_id)
        .bind("seed_error")
        .bind("seed error message")
        .bind(1_704_067_200_000i64)
        .execute(pool)
        .await
        .expect("seed url_partial_failures");

        sqlx::query("INSERT INTO url_favicons (url_status_id, favicon_url, hash) VALUES (?, ?, ?)")
            .bind(url_status_id)
            .bind("https://seed.example/favicon.ico")
            .bind(12345i64)
            .execute(pool)
            .await
            .expect("seed url_favicons");

        sqlx::query("INSERT INTO url_geoip (url_status_id, country_code) VALUES (?, ?)")
            .bind(url_status_id)
            .bind("US")
            .execute(pool)
            .await
            .expect("seed url_geoip");

        sqlx::query("INSERT INTO url_whois (url_status_id, registrar) VALUES (?, ?)")
            .bind(url_status_id)
            .bind("Seed Registrar")
            .execute(pool)
            .await
            .expect("seed url_whois");
    }

    /// Inserts one minimal, schema-valid row into every core and enrichment satellite.
    async fn seed_one_row_per_satellite_table(pool: &SqlitePool, url_status_id: i64) {
        seed_dns_and_header_satellite_tables(pool, url_status_id).await;
        seed_redirect_and_record_satellite_tables(pool, url_status_id).await;
        seed_body_content_satellite_tables(pool, url_status_id).await;
        seed_enrichment_satellite_tables(pool, url_status_id).await;
    }

    fn rust_fn_body<'a>(src: &'a str, sig: &str) -> &'a str {
        let start = src
            .find(sig)
            .unwrap_or_else(|| panic!("missing function `{sig}`"));
        let after = &src[start..];
        let brace = after.find('{').expect("function body");
        let body_start = brace + 1;
        let mut depth = 1usize;
        for (i, b) in after[body_start..].bytes().enumerate() {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &after[body_start..body_start + i];
                    }
                }
                _ => {}
            }
        }
        panic!("unclosed function `{sig}`");
    }

    fn quoted_nth_after_marker<'a>(body: &'a str, marker: &str, n: usize) -> Vec<&'a str> {
        let mut tables = Vec::new();
        let mut rest = body;
        while let Some(i) = rest.find(marker) {
            rest = &rest[i + marker.len()..];
            let mut found = Vec::new();
            let mut search = rest;
            for _ in 0..=n {
                let Some(q) = search.find('"') else {
                    break;
                };
                search = &search[q + 1..];
                let end = search.find('"').expect("closing quote");
                found.push(&search[..end]);
                search = &search[end + 1..];
            }
            tables.push(*found.get(n).unwrap_or_else(|| {
                panic!("{marker} missing quoted arg {n}");
            }));
            rest = search;
        }
        tables
    }

    #[test]
    fn core_satellite_delete_list_matches_insert_call_sites() {
        let src = include_str!("upsert.rs");
        let impl_body = rust_fn_body(src, "async fn insert_url_record_impl");
        let mut written: HashSet<&str> =
            quoted_nth_after_marker(impl_body, "record_satellite_write(", 0)
                .into_iter()
                .collect();
        let robots_body = rust_fn_body(
            include_str!("satellite/page.rs"),
            "async fn insert_robots_txt",
        );
        assert!(
            robots_body.contains("url_robots_directives"),
            "insert_robots_txt must write url_robots_directives (nested under url_robots_txt)"
        );
        written.insert("url_robots_directives");
        let listed: HashSet<&str> = URL_STATUS_CORE_SATELLITE_TABLES.iter().copied().collect();
        assert_eq!(
            written, listed,
            "CORE satellite DELETE list must match insert_url_record_impl writes"
        );
    }

    #[test]
    fn enrichment_satellite_delete_list_matches_insert_call_sites() {
        let src = include_str!("../record.rs");
        let txn_body = rust_fn_body(src, "async fn insert_enrichment_txn");
        let mut written: HashSet<&str> = quoted_nth_after_marker(txn_body, "try_enrich_tx(", 1)
            .into_iter()
            .collect();
        written.insert("url_exposed_secrets");
        written.insert("url_partial_failures");
        let listed: HashSet<&str> = URL_STATUS_ENRICHMENT_SATELLITE_TABLES
            .iter()
            .copied()
            .collect();
        assert_eq!(
            written, listed,
            "ENRICHMENT satellite DELETE list must match insert_enrichment_txn writes"
        );
        let secrets_body = rust_fn_body(src, "async fn insert_exposed_secrets_in_tx");
        assert!(
            secrets_body.contains("url_jwt_claims"),
            "JWT claims are written with secrets and CASCADE on url_exposed_secrets delete"
        );
        assert!(
            !listed.contains("url_jwt_claims"),
            "url_jwt_claims must stay off the ENRICHMENT DELETE list (CASCADE from secrets)"
        );
    }

    /// Core UPSERT clears in-transaction satellites and leaves enrichment in place
    /// until the enrichment writer transaction replaces it.
    #[tokio::test]
    async fn test_upsert_clears_core_satellite_tables_only() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let mut record = UrlRecord::test_default();
        record.run_id = Some("test-run-1".to_string());

        let empty_security = HashMap::new();
        let empty_http = HashMap::new();
        let empty_oids = HashSet::new();

        let id1 = insert_url_record(UrlRecordInsertParams::with_empty_satellites(
            &pool,
            &record,
            &empty_security,
            &empty_http,
            &empty_oids,
        ))
        .await
        .expect("first insert");

        seed_one_row_per_satellite_table(&pool, id1).await;

        for table in url_status_satellite_tables() {
            let count: i64 = sqlx::query_scalar(&format!(
                "SELECT COUNT(*) FROM {table} WHERE url_status_id = ?"
            ))
            .bind(id1)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("failed to count seeded rows in {table}: {e}"));
            assert_eq!(
                count, 1,
                "seed setup should have inserted exactly 1 row into {table}"
            );
        }

        let id2 = insert_url_record(UrlRecordInsertParams::with_empty_satellites(
            &pool,
            &record,
            &empty_security,
            &empty_http,
            &empty_oids,
        ))
        .await
        .expect("upsert");
        assert_eq!(id1, id2, "UPSERT must reuse the same url_status id");

        for table in URL_STATUS_CORE_SATELLITE_TABLES {
            let count: i64 = sqlx::query_scalar(&format!(
                "SELECT COUNT(*) FROM {table} WHERE url_status_id = ?"
            ))
            .bind(id2)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("failed to count post-upsert rows in {table}: {e}"));
            assert_eq!(
                count, 0,
                "core UPSERT must clear stale rows from {table}, found {count}"
            );
        }
        for table in URL_STATUS_ENRICHMENT_SATELLITE_TABLES {
            let count: i64 = sqlx::query_scalar(&format!(
                "SELECT COUNT(*) FROM {table} WHERE url_status_id = ?"
            ))
            .bind(id2)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("failed to count enrichment rows in {table}: {e}"));
            assert_eq!(
                count, 1,
                "core UPSERT must leave enrichment table {table} in place until enrichment rewrite"
            );
        }
    }

    #[tokio::test]
    async fn test_insert_url_record_nullable_fields() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let mut record = create_test_url_record();
        // Set nullable fields to None
        record.description = None;
        record.reverse_dns_name = None;
        record.tls_version = None;
        record.ssl_cert_subject = None;
        record.ssl_cert_issuer = None;
        record.ssl_cert_valid_from = None;
        record.ssl_cert_valid_to = None;
        record.spf_record = None;
        record.dmarc_record = None;
        record.cipher_suite = None;
        record.key_algorithm = None;
        record.run_id = None;

        let security_headers = HashMap::new();
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = Vec::new();
        let technologies = Vec::new();
        let sans = Vec::new();

        let result = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        })
        .await;

        assert!(result.is_ok());
        // Verify NULL fields are handled correctly
        let row = sqlx::query("SELECT description, tls_version FROM url_status WHERE id = ?")
            .bind(result.unwrap())
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch record");

        assert!(row.get::<Option<String>, _>("description").is_none());
        assert!(row.get::<Option<String>, _>("tls_version").is_none());
    }
}
