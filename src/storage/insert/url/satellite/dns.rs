//! DNS record insertion (nameservers, TXT, MX) for satellite tables.

use sqlx::Sqlite;
use sqlx::Transaction;

use super::super::super::utils::{
    build_batch_insert_query, detect_txt_type, parse_json_array, parse_mx_json_array,
};

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
        let query = build_batch_insert_query(
            "url_nameservers",
            &["url_status_id", "nameserver"],
            ns.len(),
            Some("ON CONFLICT(url_status_id, nameserver) DO NOTHING"),
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
        let query = build_batch_insert_query(
            "url_txt_records",
            &["url_status_id", "txt_record", "record_type"],
            txt_with_types.len(),
            None,
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
        let query = build_batch_insert_query(
            "url_mx_records",
            &["url_status_id", "priority", "mail_exchange"],
            mx_records.len(),
            Some("ON CONFLICT(url_status_id, priority, mail_exchange) DO NOTHING"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::migrations::run_migrations;
    use sqlx::{Row, SqlitePool};

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
}
