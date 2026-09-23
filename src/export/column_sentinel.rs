//! One synthetic row, every stored column read back, then exported.
//!
//! Sentinels stay on `example.com`, `192.0.2.1`, and `2001:db8::1`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

use arrow::array::{Array, ListArray, StructArray};
use chrono::{DateTime, NaiveDateTime};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use sqlx::Row;
use tempfile::NamedTempFile;

use super::csv::export_csv;
use super::field_inventory::{SATELLITE_DB_ONLY, URL_STATUS_DB_ONLY};
use super::fields::EXPORT_FIELDS;
use super::jsonl::export_jsonl;
use super::parquet::export_parquet;
use super::types::{ExportFormat, ExportOptions};
use crate::error_handling::ErrorType;
use crate::fetch::favicon::FaviconData;
use crate::fetch::well_known::{RobotsTxtData, SecurityTxtData};
use crate::fingerprint::DetectedTechnology;
use crate::geoip::GeoIpResult;
use crate::models::{KeyAlgorithm, TlsVersion};
use crate::parse::jwt::DecodedJwt;
use crate::parse::{
    AnalyticsId, AnalyticsProvider, ContactLink, ContactType, ExposedSecret, SecretSeverity,
    SocialMediaLink, SocialPlatform, StructuredData,
};
use crate::storage::insert::insert_persisted_url_record;
use crate::storage::insert::url::{
    URL_STATUS_CORE_SATELLITE_TABLES, URL_STATUS_ENRICHMENT_SATELLITE_TABLES,
};
use crate::storage::models::{UrlPartialFailureRecord, UrlRecord};
use crate::storage::{run_migrations, CookieInfo, PersistedUrlRecord, ScriptHostInfo};
use crate::whois::WhoisResult;

const RUN_ID: &str = "sentinel-run";
const OBSERVED_MS: i64 = 1_704_067_200_000;
const CERT_MS: &str = "1704067200000";
const BODY_SHA: &str = "abababababababababababababababababababababababababababababababab";
const CERT_SHA: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

fn cert_time() -> NaiveDateTime {
    DateTime::from_timestamp(1_704_067_200, 0)
        .expect("cert timestamp")
        .naive_utc()
}

fn whois_time() -> DateTime<chrono::Utc> {
    DateTime::from_timestamp(1_704_067_200, 0).expect("whois timestamp")
}

fn url_record() -> UrlRecord {
    UrlRecord {
        initial_domain: "example.com".to_string(),
        final_domain: "www.example.com".to_string(),
        initial_url: Some("https://example.com/start".to_string()),
        final_url: Some("https://www.example.com/end".to_string()),
        ip_address: "192.0.2.1".to_string(),
        reverse_dns_name: Some("rdns.example.com".to_string()),
        status: 200,
        status_desc: "OK".to_string(),
        response_time: 1.25,
        title: "Example Title".to_string(),
        description: Some("Example description".to_string()),
        meta_robots: Some("noindex".to_string()),
        tls_version: Some(TlsVersion::Tls13),
        ssl_cert_subject: Some("CN=example.com".to_string()),
        ssl_cert_issuer: Some("CN=Example CA".to_string()),
        ssl_cert_valid_from: Some(cert_time()),
        ssl_cert_valid_to: Some(cert_time()),
        timestamp: OBSERVED_MS,
        nameservers: Some(r#"["ns1.example.com"]"#.to_string()),
        txt_records: Some(r#"["example-txt-sentinel"]"#.to_string()),
        mx_records: Some(r#"[{"priority":10,"hostname":"mail.example.com"}]"#.to_string()),
        spf_record: Some("v=spf1 -all".to_string()),
        dmarc_record: Some("v=DMARC1; p=reject".to_string()),
        cipher_suite: Some("TLS_AES_128_GCM_SHA256".to_string()),
        key_algorithm: Some(KeyAlgorithm::RSA),
        run_id: Some(RUN_ID.to_string()),
        body_sha256: Some(BODY_SHA.to_string()),
        body_truncated: true,
        external_scripts_eligible: 7,
        external_scripts_scanned: 4,
        content_length: Some(4096),
        http_version: Some("HTTP/2".to_string()),
        content_type: Some("text/html".to_string()),
        canonical_url: Some("https://example.com/canonical".to_string()),
        cert_fingerprint_sha256: Some(CERT_SHA.to_string()),
        cert_serial_number: Some("01".to_string()),
        cert_is_self_signed: Some(true),
        cert_is_wildcard: Some(false),
        cert_is_mismatched: Some(true),
        meta_refresh_url: Some("https://example.com/refresh".to_string()),
        hsts_max_age: Some(12_345),
        hsts_include_subdomains: Some(true),
        hsts_preload: Some(false),
        mta_sts_record: Some("v=STSv1; id=example".to_string()),
        tls_rpt_record: Some("v=TLSRPTv1; rua=mailto:user@example.com".to_string()),
        bimi_record: Some("v=BIMI1; l=https://example.com/bimi.svg".to_string()),
        cdn_provider: Some("example-cdn".to_string()),
    }
}

fn security_txt() -> SecurityTxtData {
    SecurityTxtData {
        source_url: "https://example.com/.well-known/security.txt".to_string(),
        http_status: 200,
        contacts: vec!["mailto:user@example.com".to_string()],
        expires: Some("2025-01-01T00:00:00.000Z".to_string()),
        encryption: vec!["https://example.com/key.asc".to_string()],
        acknowledgments: vec!["https://example.com/thanks".to_string()],
        preferred_languages: Some("en".to_string()),
        canonical: vec!["https://example.com/.well-known/security.txt".to_string()],
        policy: vec!["https://example.com/policy".to_string()],
        hiring: vec!["https://example.com/jobs".to_string()],
        raw_body: "Contact: mailto:user@example.com".to_string(),
    }
}

fn robots_txt() -> RobotsTxtData {
    RobotsTxtData {
        http_status: 200,
        raw_body: "User-agent: *\nDisallow: /sentinel".to_string(),
        directives: vec![("Disallow".to_string(), "/sentinel".to_string())],
    }
}

fn exposed_secret() -> ExposedSecret {
    ExposedSecret {
        secret_type: "jwt".to_string(),
        matched_value: "example.secret.value".to_string(),
        context: "example-context".to_string(),
        severity: SecretSeverity::High,
        location: std::borrow::Cow::Borrowed("inline_script"),
        decoded_jwt: Some(decoded_jwt()),
    }
}

fn decoded_jwt() -> DecodedJwt {
    DecodedJwt {
        header_json: r#"{"alg":"none"}"#.to_string(),
        payload_json: r#"{"sub":"example"}"#.to_string(),
        algorithm: Some("none".to_string()),
        token_type: Some("JWT".to_string()),
        issuer: Some("example-iss".to_string()),
        subject: Some("example-sub".to_string()),
        audience: Some("example-aud".to_string()),
        expiration_ms: Some(1_704_067_201_000),
        issued_at_ms: Some(1_704_067_202_000),
        not_before_ms: Some(1_704_067_203_000),
        jwt_id: Some("example-jti".to_string()),
    }
}

fn whois() -> WhoisResult {
    WhoisResult {
        creation_date: Some(whois_time()),
        expiration_date: Some(whois_time()),
        updated_date: Some(whois_time()),
        registrar: Some("Example Registrar".to_string()),
        registrant_country: Some("EX".to_string()),
        registrant_org: Some("Example Org".to_string()),
        status: vec!["active".to_string()],
        nameservers: vec!["ns1.example.com".to_string()],
        raw_text: Some("example-whois".to_string()),
    }
}

fn geoip() -> GeoIpResult {
    GeoIpResult {
        country_code: Some("EX".to_string()),
        country_name: Some("Exampleland".to_string()),
        region: Some("Example Region".to_string()),
        city: Some("Example City".to_string()),
        latitude: Some(12.5),
        longitude: Some(-7.25),
        postal_code: Some("00000".to_string()),
        timezone: Some("Etc/UTC".to_string()),
        asn: Some(64_496),
        asn_org: Some("Example Org".to_string()),
    }
}

fn persisted_record() -> PersistedUrlRecord {
    PersistedUrlRecord {
        url_record: url_record(),
        security_headers: HashMap::from([(
            "Strict-Transport-Security".to_string(),
            "max-age=12345".to_string(),
        )]),
        http_headers: HashMap::from([("Server".to_string(), "Example".to_string())]),
        oids: HashSet::from(["1.2.3.4".to_string()]),
        redirect_chain: vec![("https://example.com/next".to_string(), 301)],
        technologies: vec![DetectedTechnology {
            name: "AlphaMarker".to_string(),
            version: Some("1.2".to_string()),
            category: Some("CMS".to_string()),
            is_implied: false,
            detection_source: Some("html".to_string()),
        }],
        subject_alternative_names: vec!["example.com".to_string()],
        analytics_ids: vec![AnalyticsId {
            provider: AnalyticsProvider::GoogleAnalytics,
            id: "UA-1-1".to_string(),
        }],
        geoip: Some(("192.0.2.1".to_string(), geoip())),
        structured_data: Some(StructuredData {
            json_ld: vec![serde_json::json!({"@type": "WebPage"})],
            ..StructuredData::default()
        }),
        social_media_links: vec![SocialMediaLink {
            platform: SocialPlatform::LinkedIn,
            url: "https://example.com/in/example".to_string(),
            identifier: Some("example".to_string()),
        }],
        contact_links: vec![ContactLink {
            contact_type: ContactType::Email,
            value: "user@example.com".to_string(),
            raw_href: "mailto:user@example.com".to_string(),
        }],
        exposed_secrets: vec![exposed_secret()],
        whois: Some(whois()),
        partial_failures: vec![UrlPartialFailureRecord {
            url_status_id: 0,
            error_type: ErrorType::DnsMxLookupError,
            error_message: "mx lookup timed out".to_string(),
            timestamp: OBSERVED_MS,
            run_id: Some(RUN_ID.to_string()),
        }],
        favicon: Some(FaviconData {
            favicon_url: "https://example.com/favicon.ico".to_string(),
            hash: 12_345,
        }),
        cname_records: Some(r#"["cdn.example"]"#.to_string()),
        aaaa_records: Some(r#"["2001:db8::1"]"#.to_string()),
        caa_records: Some(r#"[{"flag":1,"tag":"issue","value":"ca.example.com"}]"#.to_string()),
        csp_domains: vec![(
            "script-src".to_string(),
            "cdn.example".to_string(),
            Some("example.com".to_string()),
        )],
        cookies: vec![CookieInfo {
            name: "session".to_string(),
            secure: true,
            http_only: true,
            same_site: Some("Lax".to_string()),
            domain: Some("example.com".to_string()),
            path: Some("/".to_string()),
        }],
        resource_hints: vec![("preconnect".to_string(), "https://cdn.example/".to_string())],
        script_hosts: vec![ScriptHostInfo {
            host: "cdn.example".to_string(),
            registrable_domain: Some("example.com".to_string()),
            is_first_party: true,
        }],
        security_txt: Some(security_txt()),
        robots_txt: Some(robots_txt()),
    }
}

type Cell = (&'static str, &'static str, &'static str);

fn expected_cells() -> Vec<Cell> {
    let mut cells = Vec::new();
    cells.extend(url_status_identity());
    cells.extend(url_status_tls());
    cells.extend(url_status_page());
    cells.extend(dns_cells());
    cells.extend(page_cells());
    cells.extend(enrichment_cells());
    cells
}

fn url_status_identity() -> Vec<Cell> {
    vec![
        ("url_status", "initial_domain", "example.com"),
        ("url_status", "final_domain", "www.example.com"),
        ("url_status", "initial_url", "https://example.com/start"),
        ("url_status", "final_url", "https://www.example.com/end"),
        ("url_status", "ip_address", "192.0.2.1"),
        ("url_status", "reverse_dns_name", "rdns.example.com"),
        ("url_status", "http_status", "200"),
        ("url_status", "http_status_text", "OK"),
        ("url_status", "response_time_seconds", "1.25"),
        ("url_status", "title", "Example Title"),
        ("url_status", "description", "Example description"),
        ("url_status", "meta_robots", "noindex"),
        ("url_status", "run_id", RUN_ID),
        ("url_status", "observed_at_ms", CERT_MS),
    ]
}

fn url_status_tls() -> Vec<Cell> {
    vec![
        ("url_status", "tls_version", "TLSv1.3"),
        ("url_status", "ssl_cert_subject", "CN=example.com"),
        ("url_status", "ssl_cert_issuer", "CN=Example CA"),
        ("url_status", "ssl_cert_valid_from_ms", CERT_MS),
        ("url_status", "ssl_cert_valid_to_ms", CERT_MS),
        ("url_status", "cipher_suite", "TLS_AES_128_GCM_SHA256"),
        ("url_status", "key_algorithm", "RSA"),
        ("url_status", "cert_fingerprint_sha256", CERT_SHA),
        ("url_status", "cert_serial_number", "01"),
        ("url_status", "cert_is_self_signed", "1"),
        ("url_status", "cert_is_wildcard", "0"),
        ("url_status", "cert_is_mismatched", "1"),
    ]
}

fn url_status_page() -> Vec<Cell> {
    vec![
        ("url_status", "spf_record", "v=spf1 -all"),
        ("url_status", "dmarc_record", "v=DMARC1; p=reject"),
        ("url_status", "body_sha256", BODY_SHA),
        ("url_status", "body_truncated", "1"),
        ("url_status", "external_scripts_eligible", "7"),
        ("url_status", "external_scripts_scanned", "4"),
        ("url_status", "content_length", "4096"),
        ("url_status", "http_version", "HTTP/2"),
        ("url_status", "content_type", "text/html"),
        (
            "url_status",
            "canonical_url",
            "https://example.com/canonical",
        ),
        (
            "url_status",
            "meta_refresh_url",
            "https://example.com/refresh",
        ),
        ("url_status", "hsts_max_age", "12345"),
        ("url_status", "hsts_include_subdomains", "1"),
        ("url_status", "hsts_preload", "0"),
        ("url_status", "mta_sts_record", "v=STSv1; id=example"),
        (
            "url_status",
            "tls_rpt_record",
            "v=TLSRPTv1; rua=mailto:user@example.com",
        ),
        (
            "url_status",
            "bimi_record",
            "v=BIMI1; l=https://example.com/bimi.svg",
        ),
        ("url_status", "cdn_provider", "example-cdn"),
    ]
}

fn dns_cells() -> Vec<Cell> {
    vec![
        ("url_nameservers", "nameserver", "ns1.example.com"),
        ("url_txt_records", "record_value", "example-txt-sentinel"),
        ("url_txt_records", "record_type", "OTHER"),
        ("url_mx_records", "priority", "10"),
        ("url_mx_records", "mail_exchange", "mail.example.com"),
        ("url_cname_records", "cname_target", "cdn.example"),
        ("url_ipv6_addresses", "ipv6_address", "2001:db8::1"),
        ("url_caa_records", "flag", "1"),
        ("url_caa_records", "tag", "issue"),
        ("url_caa_records", "value", "ca.example.com"),
        ("url_technologies", "technology_name", "AlphaMarker"),
        ("url_technologies", "technology_version", "1.2"),
        ("url_technologies", "technology_category", "CMS"),
        ("url_technologies", "is_implied", "0"),
        ("url_technologies", "detection_source", "html"),
        ("url_certificate_oids", "oid", "1.2.3.4"),
        ("url_certificate_sans", "san_value", "example.com"),
        ("url_redirect_chain", "sequence_order", "1"),
        (
            "url_redirect_chain",
            "redirect_url",
            "https://example.com/next",
        ),
        ("url_redirect_chain", "http_status", "301"),
        (
            "url_security_headers",
            "header_name",
            "Strict-Transport-Security",
        ),
        ("url_security_headers", "header_value", "max-age=12345"),
        ("url_http_headers", "header_name", "Server"),
        ("url_http_headers", "header_value", "Example"),
    ]
}

fn page_cells() -> Vec<Cell> {
    vec![
        ("url_csp_domains", "directive", "script-src"),
        ("url_csp_domains", "fqdn", "cdn.example"),
        ("url_csp_domains", "registrable_domain", "example.com"),
        ("url_cookies", "cookie_name", "session"),
        ("url_cookies", "secure", "1"),
        ("url_cookies", "http_only", "1"),
        ("url_cookies", "same_site", "Lax"),
        ("url_cookies", "domain", "example.com"),
        ("url_cookies", "path", "/"),
        ("url_resource_hints", "hint_type", "preconnect"),
        ("url_resource_hints", "href", "https://cdn.example/"),
        ("url_script_hosts", "host", "cdn.example"),
        ("url_script_hosts", "registrable_domain", "example.com"),
        ("url_script_hosts", "is_first_party", "1"),
        (
            "url_security_txt",
            "source_url",
            "https://example.com/.well-known/security.txt",
        ),
        ("url_security_txt", "http_status", "200"),
        ("url_security_txt", "contacts", "mailto:user@example.com"),
        ("url_security_txt", "expires", "2025-01-01T00:00:00.000Z"),
        (
            "url_security_txt",
            "encryption",
            "https://example.com/key.asc",
        ),
        (
            "url_security_txt",
            "acknowledgments",
            "https://example.com/thanks",
        ),
        ("url_security_txt", "preferred_languages", "en"),
        (
            "url_security_txt",
            "canonical",
            "https://example.com/.well-known/security.txt",
        ),
        ("url_security_txt", "policy", "https://example.com/policy"),
        ("url_security_txt", "hiring", "https://example.com/jobs"),
        (
            "url_security_txt",
            "raw_body",
            "Contact: mailto:user@example.com",
        ),
        ("url_robots_txt", "http_status", "200"),
        (
            "url_robots_txt",
            "raw_body",
            "User-agent: *\nDisallow: /sentinel",
        ),
        ("url_robots_directives", "directive", "Disallow"),
        ("url_robots_directives", "value", "/sentinel"),
    ]
}

fn enrichment_cells() -> Vec<Cell> {
    vec![
        ("url_analytics_ids", "provider", "Google Analytics"),
        ("url_analytics_ids", "tracking_id", "UA-1-1"),
        ("url_structured_data", "data_type", "json_ld"),
        ("url_structured_data", "property_name", "@document"),
        (
            "url_structured_data",
            "property_value",
            r#"{"@type":"WebPage"}"#,
        ),
        ("url_social_media_links", "platform", "LinkedIn"),
        (
            "url_social_media_links",
            "profile_url",
            "https://example.com/in/example",
        ),
        ("url_social_media_links", "identifier", "example"),
        ("url_contact_links", "contact_type", "email"),
        ("url_contact_links", "contact_value", "user@example.com"),
        ("url_contact_links", "raw_href", "mailto:user@example.com"),
        ("url_exposed_secrets", "secret_type", "jwt"),
        (
            "url_exposed_secrets",
            "matched_value",
            "example.secret.value",
        ),
        ("url_exposed_secrets", "severity", "high"),
        ("url_exposed_secrets", "location", "inline_script"),
        ("url_exposed_secrets", "context", "example-context"),
        ("url_partial_failures", "error_type", "DNS MX lookup error"),
        (
            "url_partial_failures",
            "error_message",
            "mx lookup timed out",
        ),
        ("url_partial_failures", "observed_at_ms", CERT_MS),
        ("url_partial_failures", "run_id", RUN_ID),
        (
            "url_favicons",
            "favicon_url",
            "https://example.com/favicon.ico",
        ),
        ("url_favicons", "hash", "12345"),
        ("url_geoip", "country_code", "EX"),
        ("url_geoip", "country_name", "Exampleland"),
        ("url_geoip", "region", "Example Region"),
        ("url_geoip", "city", "Example City"),
        ("url_geoip", "latitude", "12.5"),
        ("url_geoip", "longitude", "-7.25"),
        ("url_geoip", "postal_code", "00000"),
        ("url_geoip", "timezone", "Etc/UTC"),
        ("url_geoip", "asn", "64496"),
        ("url_geoip", "asn_org", "Example Org"),
        ("url_whois", "creation_date_ms", CERT_MS),
        ("url_whois", "expiration_date_ms", CERT_MS),
        ("url_whois", "updated_date_ms", CERT_MS),
        ("url_whois", "registrar", "Example Registrar"),
        ("url_whois", "registrant_country", "EX"),
        ("url_whois", "registrant_org", "Example Org"),
        ("url_whois", "whois_statuses", r#"["active"]"#),
        ("url_whois", "nameservers_json", r#"["ns1.example.com"]"#),
        ("url_whois", "raw_response", "example-whois"),
        ("url_jwt_claims", "header_json", r#"{"alg":"none"}"#),
        ("url_jwt_claims", "payload_json", r#"{"sub":"example"}"#),
        ("url_jwt_claims", "algorithm", "none"),
        ("url_jwt_claims", "token_type", "JWT"),
        ("url_jwt_claims", "issuer", "example-iss"),
        ("url_jwt_claims", "subject", "example-sub"),
        ("url_jwt_claims", "audience", "example-aud"),
        ("url_jwt_claims", "expiration_ms", "1704067201000"),
        ("url_jwt_claims", "issued_at_ms", "1704067202000"),
        ("url_jwt_claims", "not_before_ms", "1704067203000"),
        ("url_jwt_claims", "jwt_id", "example-jti"),
    ]
}

fn sentinel_tables() -> Vec<&'static str> {
    let mut tables = vec!["url_status"];
    tables.extend(URL_STATUS_CORE_SATELLITE_TABLES);
    tables.extend(URL_STATUS_ENRICHMENT_SATELLITE_TABLES);
    tables.push("url_jwt_claims");
    tables
}

fn is_key(name: &str, pk: i64) -> bool {
    pk > 0 || name == "url_status_id" || name == "exposed_secret_id"
}

async fn column_values(pool: &sqlx::SqlitePool, table: &str) -> BTreeMap<String, Option<String>> {
    assert!(
        table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "unexpected table name"
    );
    let info = crate::sql::query(format!("PRAGMA table_info({table})"))
        .fetch_all(pool)
        .await
        .expect("pragma");
    let mut names = Vec::new();
    for column in &info {
        let name: String = column.get("name");
        let pk: i64 = column.get("pk");
        if !is_key(&name, pk) {
            names.push(name);
        }
    }
    let count: i64 = crate::sql::query_scalar(format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(pool)
        .await
        .expect("count");
    assert_eq!(count, 1, "{table} row count");
    let projection = names
        .iter()
        .map(|name| format!("CAST(\"{name}\" AS TEXT) AS \"{name}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let row = crate::sql::query(format!("SELECT {projection} FROM {table}"))
        .fetch_one(pool)
        .await
        .expect("row");
    names
        .into_iter()
        .map(|name| {
            let value = row
                .try_get::<Option<String>, _>(name.as_str())
                .expect("text");
            (name, value)
        })
        .collect()
}

fn mismatches(actual: &BTreeMap<&str, BTreeMap<String, Option<String>>>) -> Vec<String> {
    let expected = expected_cells();
    let mut wanted: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut problems = Vec::new();
    for (table, column, value) in &expected {
        wanted.entry(table).or_default().insert(column);
        let got = actual
            .get(table)
            .and_then(|row| row.get(*column))
            .map(Option::as_deref);
        if got != Some(Some(*value)) {
            problems.push(format!("{table}.{column}: expected {value:?} got {got:?}"));
        }
    }
    for (table, row) in actual {
        for column in row.keys() {
            if !wanted
                .get(table)
                .is_some_and(|cols| cols.contains(column.as_str()))
            {
                problems.push(format!(
                    "unread {table}.{column} = {:?}",
                    row.get(column).and_then(|v| v.as_deref())
                ));
            }
        }
    }
    problems
}

async fn insert_sentinel_db() -> NamedTempFile {
    let db = NamedTempFile::new().expect("temp db");
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", db.path().display()))
        .await
        .expect("pool");
    run_migrations(&pool).await.expect("migrations");
    sqlx::query("INSERT INTO runs (run_id, start_time_ms) VALUES (?, ?)")
        .bind(RUN_ID)
        .bind(OBSERVED_MS)
        .execute(&pool)
        .await
        .expect("insert run");
    insert_persisted_url_record(&pool, persisted_record())
        .await
        .expect("insert sentinel row");

    let mut actual = BTreeMap::new();
    for table in sentinel_tables() {
        actual.insert(table, column_values(&pool, table).await);
    }
    let problems = mismatches(&actual);
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    drop(pool);
    db
}

fn export_options(db: &Path, output: &Path, format: ExportFormat) -> ExportOptions {
    ExportOptions {
        db_path: db.to_path_buf(),
        output: Some(output.to_path_buf()),
        format,
        run_id: None,
        domain: None,
        status: None,
        since: None,
        include_implied_tech: false,
    }
}

const EXPORT_NEEDLES: &[&str] = &[
    "example.com",
    "192.0.2.1",
    "2001:db8::1",
    "AlphaMarker",
    "Example Title",
    "Example Registrar",
    "Exampleland",
    "64496",
    "user@example.com",
    "example-txt-sentinel",
    "mail.example.com",
    "example-iss",
];

fn assert_needles(label: &str, text: &str) {
    let missing: Vec<_> = EXPORT_NEEDLES
        .iter()
        .filter(|needle| !text.contains(**needle))
        .copied()
        .collect();
    assert!(missing.is_empty(), "{label} missing {missing:?}");
}

fn assert_csv(path: &Path) {
    let text = std::fs::read_to_string(path).expect("csv");
    assert_needles("csv", &text);
    let mut reader = csv::Reader::from_path(path).expect("csv reader");
    let headers = reader.headers().expect("headers").clone();
    let row = reader.records().next().expect("row").expect("record");
    let mut empty = Vec::new();
    for field in EXPORT_FIELDS {
        let Some(spec) = &field.csv else {
            continue;
        };
        let idx = headers
            .iter()
            .position(|header| header == spec.name)
            .unwrap_or_else(|| panic!("csv missing {}", spec.name));
        let cell = row.get(idx).unwrap_or("");
        if cell.is_empty() {
            empty.push(spec.name);
        }
    }
    assert!(empty.is_empty(), "empty csv cells: {empty:?}");
    for name in URL_STATUS_DB_ONLY {
        assert!(
            !headers.iter().any(|header| header == *name),
            "{name} is db-only"
        );
    }
    for name in SATELLITE_DB_ONLY {
        assert!(
            !headers.iter().any(|header| header == *name),
            "{name} is db-only"
        );
    }
}

fn assert_jsonl(path: &Path) {
    let text = std::fs::read_to_string(path).expect("jsonl");
    assert_needles("jsonl", &text);
    let row: serde_json::Value = serde_json::from_str(text.trim()).expect("json");
    let mut missing = Vec::new();
    for field in EXPORT_FIELDS {
        if field.jsonl_flat.is_none() {
            continue;
        }
        match row.get(field.id) {
            Some(serde_json::Value::Null) | None => missing.push(field.id),
            Some(_) => {}
        }
    }
    assert!(missing.is_empty(), "jsonl flat fields missing: {missing:?}");
}

fn assert_list(list: &ListArray, index: usize, path: &str) {
    let start = usize::try_from(list.value_offsets()[index]).expect("offset");
    let end = usize::try_from(list.value_offsets()[index + 1]).expect("offset");
    assert!(end > start, "{path} is empty");
    for offset in start..end {
        assert_populated(list.values().as_ref(), offset, path);
    }
}

fn assert_struct(structure: &StructArray, index: usize, path: &str) {
    for (field, column) in structure.fields().iter().zip(structure.columns()) {
        assert_populated(column.as_ref(), index, &format!("{path}.{}", field.name()));
    }
}

fn assert_populated(array: &dyn Array, index: usize, path: &str) {
    assert!(!array.is_null(index), "{path} is null");
    if let Some(list) = array.as_any().downcast_ref::<ListArray>() {
        assert_list(list, index, path);
        return;
    }
    if let Some(structure) = array.as_any().downcast_ref::<StructArray>() {
        assert_struct(structure, index, path);
    }
}

fn assert_parquet(path: &Path) {
    let file = std::fs::File::open(path).expect("open");
    let builder = ParquetRecordBatchReaderBuilder::try_new(file).expect("parse");
    let mut reader = builder.build().expect("reader");
    let batch = reader.next().expect("batch").expect("batch ok");
    assert!(reader.next().is_none(), "one parquet batch");
    for field in EXPORT_FIELDS {
        let Some(spec) = &field.parquet else {
            continue;
        };
        let column = batch
            .column_by_name(spec.name)
            .unwrap_or_else(|| panic!("parquet missing {}", spec.name));
        assert_populated(column.as_ref(), 0, spec.name);
    }
}

async fn assert_exports(db: &Path) {
    let csv_out = NamedTempFile::new().expect("csv");
    let jsonl_out = NamedTempFile::new().expect("jsonl");
    let parquet_out = NamedTempFile::new().expect("parquet");
    let csv_count = export_csv(&export_options(db, csv_out.path(), ExportFormat::Csv))
        .await
        .expect("csv export");
    let jsonl_count = export_jsonl(&export_options(db, jsonl_out.path(), ExportFormat::Jsonl))
        .await
        .expect("jsonl export");
    let parquet_count = export_parquet(&export_options(
        db,
        parquet_out.path(),
        ExportFormat::Parquet,
    ))
    .await
    .expect("parquet export");
    assert_eq!((csv_count, jsonl_count, parquet_count), (1, 1, 1));
    assert_csv(csv_out.path());
    assert_jsonl(jsonl_out.path());
    assert_parquet(parquet_out.path());
}

#[tokio::test]
async fn sentinel_row_reads_back_every_column_and_export() {
    let db = insert_sentinel_db().await;
    assert_exports(db.path()).await;
}
