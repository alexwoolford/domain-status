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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::migrations::run_migrations;
    use sqlx::{Row, SqlitePool};
    use std::collections::{HashMap, HashSet};

    async fn create_test_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");
        pool
    }

    async fn create_test_url_status(pool: &SqlitePool) -> i64 {
        sqlx::query(
            "INSERT INTO url_status (domain, final_domain, ip_address, status, status_description, response_time, title, timestamp, is_mobile_friendly) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind("example.com")
        .bind("example.com")
        .bind("93.184.216.34")
        .bind(200i64)
        .bind("OK")
        .bind(0.123f64)
        .bind("Test Page")
        .bind(1704067200000i64)
        .bind(true)
        .fetch_one(pool)
        .await
        .expect("Failed to insert test URL status")
        .get::<i64, _>(0)
    }

    #[tokio::test]
    async fn test_insert_technologies_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let technologies = vec!["WordPress".to_string(), "PHP".to_string()];

        insert_technologies(&mut tx, url_status_id, &technologies).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify insertion
        let rows = sqlx::query(
            "SELECT technology_name, technology_category FROM url_technologies WHERE url_status_id = ? ORDER BY technology_name",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch technologies");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<String, _>("technology_name"), "PHP");
        assert_eq!(rows[1].get::<String, _>("technology_name"), "WordPress");
    }

    #[tokio::test]
    async fn test_insert_technologies_duplicates() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let technologies = vec!["WordPress".to_string(), "WordPress".to_string()];

        insert_technologies(&mut tx, url_status_id, &technologies).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify only one entry (ON CONFLICT DO NOTHING)
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_technologies WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count technologies");

        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_insert_technologies_empty() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let technologies = vec![];

        insert_technologies(&mut tx, url_status_id, &technologies).await;
        tx.commit().await.expect("Failed to commit transaction");

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_technologies WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count technologies");

        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_insert_nameservers_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let nameservers_json = Some(r#"["ns1.example.com", "ns2.example.com"]"#.to_string());

        insert_nameservers(&mut tx, url_status_id, &nameservers_json).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify insertion
        let rows = sqlx::query(
            "SELECT nameserver FROM url_nameservers WHERE url_status_id = ? ORDER BY nameserver",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch nameservers");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<String, _>("nameserver"), "ns1.example.com");
        assert_eq!(rows[1].get::<String, _>("nameserver"), "ns2.example.com");
    }

    #[tokio::test]
    async fn test_insert_nameservers_empty() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let nameservers_json = None;

        insert_nameservers(&mut tx, url_status_id, &nameservers_json).await;
        tx.commit().await.expect("Failed to commit transaction");

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_nameservers WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count nameservers");

        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_insert_txt_records_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let txt_records_json =
            Some(r#"["v=spf1 include:_spf.example.com ~all", "v=dmarc1; p=none"]"#.to_string());

        insert_txt_records(&mut tx, url_status_id, &txt_records_json).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify insertion
        let rows = sqlx::query(
            "SELECT txt_record, record_type FROM url_txt_records WHERE url_status_id = ? ORDER BY record_type",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch TXT records");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<String, _>("record_type"), "DMARC");
        assert_eq!(rows[1].get::<String, _>("record_type"), "SPF");
    }

    #[tokio::test]
    async fn test_insert_txt_records_types() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let txt_records_json =
            Some(r#"["google-site-verification=abc123", "some other record"]"#.to_string());

        insert_txt_records(&mut tx, url_status_id, &txt_records_json).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify record types
        let rows = sqlx::query(
            "SELECT record_type FROM url_txt_records WHERE url_status_id = ? ORDER BY record_type",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch TXT records");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<String, _>("record_type"), "OTHER");
        assert_eq!(rows[1].get::<String, _>("record_type"), "VERIFICATION");
    }

    #[tokio::test]
    async fn test_insert_mx_records_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let mx_records_json = Some(r#"[{"priority": 10, "hostname": "mail1.example.com"}, {"priority": 20, "hostname": "mail2.example.com"}]"#.to_string());

        insert_mx_records(&mut tx, url_status_id, &mx_records_json).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify insertion
        let rows = sqlx::query(
            "SELECT priority, mail_exchange FROM url_mx_records WHERE url_status_id = ? ORDER BY priority",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch MX records");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<i32, _>("priority"), 10);
        assert_eq!(
            rows[0].get::<String, _>("mail_exchange"),
            "mail1.example.com"
        );
        assert_eq!(rows[1].get::<i32, _>("priority"), 20);
        assert_eq!(
            rows[1].get::<String, _>("mail_exchange"),
            "mail2.example.com"
        );
    }

    #[tokio::test]
    async fn test_insert_security_headers_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let mut security_headers = HashMap::new();
        security_headers.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=31536000".to_string(),
        );
        security_headers.insert(
            "Content-Security-Policy".to_string(),
            "default-src 'self'".to_string(),
        );

        insert_security_headers(&mut tx, url_status_id, &security_headers).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify insertion
        let rows = sqlx::query(
            "SELECT header_name, header_value FROM url_security_headers WHERE url_status_id = ? ORDER BY header_name",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch security headers");

        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].get::<String, _>("header_name"),
            "Content-Security-Policy"
        );
        assert_eq!(
            rows[1].get::<String, _>("header_name"),
            "Strict-Transport-Security"
        );
    }

    #[tokio::test]
    async fn test_insert_security_headers_upsert() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx1 = pool.begin().await.expect("Failed to start transaction");
        let mut security_headers1 = HashMap::new();
        security_headers1.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=31536000".to_string(),
        );
        insert_security_headers(&mut tx1, url_status_id, &security_headers1).await;
        tx1.commit().await.expect("Failed to commit transaction");

        // Insert again with updated value
        let mut tx2 = pool.begin().await.expect("Failed to start transaction");
        let mut security_headers2 = HashMap::new();
        security_headers2.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=63072000".to_string(),
        );
        insert_security_headers(&mut tx2, url_status_id, &security_headers2).await;
        tx2.commit().await.expect("Failed to commit transaction");

        // Verify updated value
        let row = sqlx::query(
            "SELECT header_value FROM url_security_headers WHERE url_status_id = ? AND header_name = 'Strict-Transport-Security'",
        )
        .bind(url_status_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch security header");

        assert_eq!(row.get::<String, _>("header_value"), "max-age=63072000");
    }

    #[tokio::test]
    async fn test_insert_http_headers_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let mut http_headers = HashMap::new();
        http_headers.insert("Server".to_string(), "nginx/1.18.0".to_string());
        http_headers.insert("X-Powered-By".to_string(), "PHP/7.4".to_string());

        insert_http_headers(&mut tx, url_status_id, &http_headers).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify insertion
        let rows = sqlx::query(
            "SELECT header_name, header_value FROM url_http_headers WHERE url_status_id = ? ORDER BY header_name",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch HTTP headers");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<String, _>("header_name"), "Server");
        assert_eq!(rows[1].get::<String, _>("header_name"), "X-Powered-By");
    }

    #[tokio::test]
    async fn test_insert_oids_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let mut oids = HashSet::new();
        oids.insert("1.3.6.1.4.1.311".to_string());
        oids.insert("1.2.840.113549".to_string());

        insert_oids(&mut tx, url_status_id, &oids).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify insertion
        let rows = sqlx::query("SELECT oid FROM url_oids WHERE url_status_id = ? ORDER BY oid")
            .bind(url_status_id)
            .fetch_all(&pool)
            .await
            .expect("Failed to fetch OIDs");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<String, _>("oid"), "1.2.840.113549");
        assert_eq!(rows[1].get::<String, _>("oid"), "1.3.6.1.4.1.311");
    }

    #[tokio::test]
    async fn test_insert_oids_duplicates() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let mut oids = HashSet::new();
        oids.insert("1.3.6.1.4.1.311".to_string());
        oids.insert("1.3.6.1.4.1.311".to_string()); // Duplicate (HashSet will dedupe)

        insert_oids(&mut tx, url_status_id, &oids).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify only one entry
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_oids WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count OIDs");

        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_insert_redirect_chain_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let redirect_chain = vec![
            "http://example.com".to_string(),
            "https://example.com".to_string(),
            "https://www.example.com".to_string(),
        ];

        insert_redirect_chain(&mut tx, url_status_id, &redirect_chain).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify insertion with correct sequence order
        let rows = sqlx::query(
            "SELECT sequence_order, url FROM url_redirect_chain WHERE url_status_id = ? ORDER BY sequence_order",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch redirect chain");

        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].get::<i32, _>("sequence_order"), 1);
        assert_eq!(rows[0].get::<String, _>("url"), "http://example.com");
        assert_eq!(rows[1].get::<i32, _>("sequence_order"), 2);
        assert_eq!(rows[1].get::<String, _>("url"), "https://example.com");
        assert_eq!(rows[2].get::<i32, _>("sequence_order"), 3);
        assert_eq!(rows[2].get::<String, _>("url"), "https://www.example.com");
    }

    #[tokio::test]
    async fn test_insert_certificate_sans_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let sans = vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
            "*.example.com".to_string(),
        ];

        insert_certificate_sans(&mut tx, url_status_id, &sans).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify insertion
        let rows = sqlx::query(
            "SELECT domain_name FROM url_certificate_sans WHERE url_status_id = ? ORDER BY domain_name",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch certificate SANs");

        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].get::<String, _>("domain_name"), "*.example.com");
        assert_eq!(rows[1].get::<String, _>("domain_name"), "example.com");
        assert_eq!(rows[2].get::<String, _>("domain_name"), "www.example.com");
    }

    #[tokio::test]
    async fn test_insert_certificate_sans_duplicates() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let sans = vec![
            "example.com".to_string(),
            "example.com".to_string(), // Duplicate
        ];

        insert_certificate_sans(&mut tx, url_status_id, &sans).await;
        tx.commit().await.expect("Failed to commit transaction");

        // Verify only one entry (ON CONFLICT DO NOTHING)
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_certificate_sans WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count certificate SANs");

        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_insert_empty_collections() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");

        // Test all empty cases
        insert_technologies(&mut tx, url_status_id, &[]).await;
        insert_nameservers(&mut tx, url_status_id, &None).await;
        insert_txt_records(&mut tx, url_status_id, &None).await;
        insert_mx_records(&mut tx, url_status_id, &None).await;
        insert_security_headers(&mut tx, url_status_id, &HashMap::new()).await;
        insert_http_headers(&mut tx, url_status_id, &HashMap::new()).await;
        insert_oids(&mut tx, url_status_id, &HashSet::new()).await;
        insert_redirect_chain(&mut tx, url_status_id, &[]).await;
        insert_certificate_sans(&mut tx, url_status_id, &[]).await;

        tx.commit().await.expect("Failed to commit transaction");

        // Verify no rows inserted
        let counts = vec![
            (
                "url_technologies",
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM url_technologies WHERE url_status_id = ?",
                )
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            ),
            (
                "url_nameservers",
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM url_nameservers WHERE url_status_id = ?",
                )
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            ),
            (
                "url_txt_records",
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM url_txt_records WHERE url_status_id = ?",
                )
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            ),
            (
                "url_mx_records",
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM url_mx_records WHERE url_status_id = ?",
                )
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            ),
            (
                "url_security_headers",
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM url_security_headers WHERE url_status_id = ?",
                )
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            ),
            (
                "url_http_headers",
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM url_http_headers WHERE url_status_id = ?",
                )
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            ),
            (
                "url_oids",
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM url_oids WHERE url_status_id = ?",
                )
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            ),
            (
                "url_redirect_chain",
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM url_redirect_chain WHERE url_status_id = ?",
                )
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            ),
            (
                "url_certificate_sans",
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM url_certificate_sans WHERE url_status_id = ?",
                )
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            ),
        ];

        for (table, count) in counts {
            assert_eq!(count, 0, "Table {} should have no rows", table);
        }
    }
}
