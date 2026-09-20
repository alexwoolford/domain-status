//! DNS record insertion (nameservers, TXT, MX) for satellite tables.

use sqlx::Sqlite;
use sqlx::Transaction;

use super::super::super::utils::{
    detect_txt_type, insert_key_value_batch, insert_single_column_batch, parse_json_array,
    parse_mx_json_array,
};

/// Inserts nameservers into `url_nameservers` table using batch insert.
pub(crate) async fn insert_nameservers(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    nameservers_json: Option<&String>,
) -> Result<(), sqlx::Error> {
    let Some(ns) = parse_json_array(nameservers_json) else {
        return Ok(());
    };
    if ns.is_empty() {
        return Ok(());
    }
    insert_single_column_batch(
        tx,
        "url_nameservers",
        "url_status_id",
        "nameserver",
        url_status_id,
        &ns,
        Some("ON CONFLICT(url_status_id, nameserver) DO NOTHING"),
    )
    .await
}

/// Inserts TXT records into `url_txt_records` table using batch insert.
pub(crate) async fn insert_txt_records(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    txt_records_json: Option<&String>,
) -> Result<(), sqlx::Error> {
    let Some(txts) = parse_json_array(txt_records_json) else {
        return Ok(());
    };
    if txts.is_empty() {
        return Ok(());
    }

    let txt_with_types: Vec<(&String, String)> = txts
        .iter()
        .filter(|txt| crate::dns::is_storable_txt(txt))
        .map(|txt| (txt, detect_txt_type(txt).to_string()))
        .collect();

    if txt_with_types.is_empty() {
        return Ok(());
    }

    insert_key_value_batch(
        tx,
        "url_txt_records",
        "url_status_id",
        "record_value",
        "record_type",
        url_status_id,
        &txt_with_types,
        Some("ON CONFLICT(url_status_id, record_type, record_value) DO NOTHING"),
    )
    .await
}

/// Inserts MX records into `url_mx_records` table using batch insert.
pub(crate) async fn insert_mx_records(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    mx_records_json: Option<&String>,
) -> Result<(), sqlx::Error> {
    let Some(mx_records) = parse_mx_json_array(mx_records_json) else {
        return Ok(());
    };
    if mx_records.is_empty() {
        return Ok(());
    }

    insert_key_value_batch(
        tx,
        "url_mx_records",
        "url_status_id",
        "priority",
        "mail_exchange",
        url_status_id,
        &mx_records,
        Some("ON CONFLICT(url_status_id, priority, mail_exchange) DO NOTHING"),
    )
    .await
}

/// Inserts CNAME records into `url_cname_records` table using batch insert.
pub(crate) async fn insert_cname_records(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    cname_records_json: Option<&String>,
) -> Result<(), sqlx::Error> {
    let Some(cnames) = parse_json_array(cname_records_json) else {
        return Ok(());
    };
    if cnames.is_empty() {
        return Ok(());
    }

    insert_single_column_batch(
        tx,
        "url_cname_records",
        "url_status_id",
        "cname_target",
        url_status_id,
        &cnames,
        Some("ON CONFLICT(url_status_id, cname_target) DO NOTHING"),
    )
    .await
}

/// Inserts IPv6 addresses into `url_ipv6_addresses` table using batch insert.
pub(crate) async fn insert_ipv6_addresses(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    aaaa_records_json: Option<&String>,
) -> Result<(), sqlx::Error> {
    let Some(addrs) = parse_json_array(aaaa_records_json) else {
        return Ok(());
    };
    if addrs.is_empty() {
        return Ok(());
    }

    insert_single_column_batch(
        tx,
        "url_ipv6_addresses",
        "url_status_id",
        "ipv6_address",
        url_status_id,
        &addrs,
        Some("ON CONFLICT(url_status_id, ipv6_address) DO NOTHING"),
    )
    .await
}

/// Inserts CAA records into `url_caa_records` table using batch insert.
pub(crate) async fn insert_caa_records(
    tx: &mut Transaction<'_, Sqlite>,
    url_status_id: i64,
    caa_records_json: Option<&String>,
) -> Result<(), sqlx::Error> {
    let Some(json_str) = caa_records_json else {
        return Ok(());
    };
    let parsed: Vec<serde_json::Value> = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    if parsed.is_empty() {
        return Ok(());
    }

    let query = super::super::super::utils::build_batch_insert_query(
        "url_caa_records",
        &["url_status_id", "flag", "tag", "value"],
        parsed.len(),
        Some("ON CONFLICT(url_status_id, tag, value) DO UPDATE SET flag=excluded.flag"),
    );

    let mut query_builder = crate::sql::query(query);
    for record in &parsed {
        let flag = record["flag"].as_u64().unwrap_or(0);
        let tag = record["tag"].as_str().unwrap_or("");
        let value = record["value"].as_str().unwrap_or("");
        #[allow(clippy::cast_possible_truncation)]
        let flag_i32 = flag as i32;
        query_builder = query_builder
            .bind(url_status_id)
            .bind(flag_i32)
            .bind(tag)
            .bind(value);
    }

    query_builder.execute(&mut **tx).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;

    use crate::storage::test_helpers::{create_test_pool, create_test_url_status_default};

    #[tokio::test]
    async fn test_insert_nameservers_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let nameservers_json = Some(r#"["ns1.example.com", "ns2.example.com"]"#.to_string());

        insert_nameservers(&mut tx, url_status_id, nameservers_json.as_ref())
            .await
            .expect("insert");
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
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let nameservers_json = None;

        insert_nameservers(&mut tx, url_status_id, nameservers_json.as_ref())
            .await
            .expect("insert");
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
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let txt_records_json =
            Some(r#"["v=spf1 include:_spf.example.com ~all", "v=dmarc1; p=none"]"#.to_string());

        insert_txt_records(&mut tx, url_status_id, txt_records_json.as_ref())
            .await
            .expect("insert");
        tx.commit().await.expect("Failed to commit transaction");

        // Verify insertion
        let rows = sqlx::query(
            "SELECT record_value, record_type FROM url_txt_records WHERE url_status_id = ? ORDER BY record_type",
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
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let txt_records_json =
            Some(r#"["google-site-verification=abc123", "some other record"]"#.to_string());

        insert_txt_records(&mut tx, url_status_id, txt_records_json.as_ref())
            .await
            .expect("insert");
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
    async fn test_insert_txt_records_rescan_no_duplicates() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let txt_records_json =
            Some(r#"["v=spf1 include:_spf.example.com ~all", "v=dmarc1; p=none"]"#.to_string());

        // First insert
        let mut tx1 = pool.begin().await.expect("Failed to start transaction");
        insert_txt_records(&mut tx1, url_status_id, txt_records_json.as_ref())
            .await
            .expect("insert");
        tx1.commit().await.expect("Failed to commit transaction");

        // Rescan: insert same records again (ON CONFLICT DO NOTHING)
        let mut tx2 = pool.begin().await.expect("Failed to start transaction");
        insert_txt_records(&mut tx2, url_status_id, txt_records_json.as_ref())
            .await
            .expect("insert");
        tx2.commit().await.expect("Failed to commit transaction");

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_txt_records WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count TXT records");

        assert_eq!(count, 2, "Rescan should not create duplicate TXT records");
    }

    #[tokio::test]
    async fn test_insert_txt_records_skips_empty() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let txt_records_json = Some(r#"["", "   ", "v=spf1 ~all"]"#.to_string());

        insert_txt_records(&mut tx, url_status_id, txt_records_json.as_ref())
            .await
            .expect("insert");
        tx.commit().await.expect("Failed to commit transaction");

        let rows = sqlx::query(
            "SELECT record_value, record_type FROM url_txt_records WHERE url_status_id = ?",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch TXT records");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get::<String, _>("record_type"), "SPF");
        assert_eq!(rows[0].get::<String, _>("record_value"), "v=spf1 ~all");
    }

    #[tokio::test]
    async fn test_insert_mx_records_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut tx = pool.begin().await.expect("Failed to start transaction");
        let mx_records_json = Some(r#"[{"priority": 10, "hostname": "mail1.example.com"}, {"priority": 20, "hostname": "mail2.example.com"}]"#.to_string());

        insert_mx_records(&mut tx, url_status_id, mx_records_json.as_ref())
            .await
            .expect("insert");
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

    async fn caa_rows(pool: &sqlx::SqlitePool, url_status_id: i64) -> Vec<(i32, String, String)> {
        sqlx::query_as(
            "SELECT flag, tag, value FROM url_caa_records WHERE url_status_id = ? \
             ORDER BY tag, value",
        )
        .bind(url_status_id)
        .fetch_all(pool)
        .await
        .expect("fetch CAA")
    }

    /// Kills: `insert_caa_records` treating `None` / invalid JSON / `[]` as a
    /// SQL write instead of `Ok` with zero rows.
    #[tokio::test]
    async fn test_insert_caa_records_none_invalid_and_empty_are_noop() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut tx = pool.begin().await.expect("tx");
        insert_caa_records(&mut tx, url_status_id, None)
            .await
            .expect("None");
        insert_caa_records(&mut tx, url_status_id, Some(&"not-json".to_string()))
            .await
            .expect("invalid JSON must be Ok");
        insert_caa_records(&mut tx, url_status_id, Some(&"[]".to_string()))
            .await
            .expect("empty array");
        tx.commit().await.expect("commit");

        assert!(
            caa_rows(&pool, url_status_id).await.is_empty(),
            "None / invalid JSON / [] must write zero CAA rows"
        );
    }

    /// Kills: dropping `flag`/`tag`/`value` columns or writing a different
    /// `issue` / `ca.example.com` pair.
    #[tokio::test]
    async fn test_insert_caa_records_writes_flag_tag_value() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;
        let json = r#"[{"flag":0,"tag":"issue","value":"ca.example.com"}]"#.to_string();

        let mut tx = pool.begin().await.expect("tx");
        insert_caa_records(&mut tx, url_status_id, Some(&json))
            .await
            .expect("insert");
        tx.commit().await.expect("commit");

        assert_eq!(
            caa_rows(&pool, url_status_id).await,
            vec![(0, "issue".to_string(), "ca.example.com".to_string())]
        );
    }

    /// Kills: `ON CONFLICT` inserting a second row instead of updating `flag`.
    #[tokio::test]
    async fn test_insert_caa_records_conflict_updates_flag() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;
        let first = r#"[{"flag":0,"tag":"issue","value":"ca.example.com"}]"#.to_string();
        let second = r#"[{"flag":128,"tag":"issue","value":"ca.example.com"}]"#.to_string();

        let mut tx = pool.begin().await.expect("tx1");
        insert_caa_records(&mut tx, url_status_id, Some(&first))
            .await
            .expect("first");
        tx.commit().await.expect("commit1");

        let mut tx = pool.begin().await.expect("tx2");
        insert_caa_records(&mut tx, url_status_id, Some(&second))
            .await
            .expect("second");
        tx.commit().await.expect("commit2");

        assert_eq!(
            caa_rows(&pool, url_status_id).await,
            vec![(128, "issue".to_string(), "ca.example.com".to_string())],
            "same tag+value must update flag, not duplicate"
        );
    }

    async fn cname_targets(pool: &sqlx::SqlitePool, url_status_id: i64) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT cname_target FROM url_cname_records WHERE url_status_id = ? \
             ORDER BY cname_target",
        )
        .bind(url_status_id)
        .fetch_all(pool)
        .await
        .expect("fetch CNAME")
    }

    async fn ipv6_addrs(pool: &sqlx::SqlitePool, url_status_id: i64) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT ipv6_address FROM url_ipv6_addresses WHERE url_status_id = ? \
             ORDER BY ipv6_address",
        )
        .bind(url_status_id)
        .fetch_all(pool)
        .await
        .expect("fetch IPv6")
    }

    /// Kills: `insert_cname_records` treating `None` / invalid JSON / `[]` as a
    /// SQL write instead of `Ok` with zero rows.
    #[tokio::test]
    async fn test_insert_cname_records_none_invalid_and_empty_are_noop() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut tx = pool.begin().await.expect("tx");
        insert_cname_records(&mut tx, url_status_id, None)
            .await
            .expect("None");
        insert_cname_records(&mut tx, url_status_id, Some(&"not-json".to_string()))
            .await
            .expect("invalid JSON must be Ok");
        insert_cname_records(&mut tx, url_status_id, Some(&"[]".to_string()))
            .await
            .expect("empty array");
        tx.commit().await.expect("commit");

        assert!(
            cname_targets(&pool, url_status_id).await.is_empty(),
            "None / invalid JSON / [] must write zero CNAME rows"
        );
    }

    /// Kills: `insert_cname_records` returning `Ok(())` without writing
    /// `cdn.example.com`.
    #[tokio::test]
    async fn test_insert_cname_records_writes_target() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;
        let json = r#"["cdn.example.com"]"#.to_string();

        let mut tx = pool.begin().await.expect("tx");
        insert_cname_records(&mut tx, url_status_id, Some(&json))
            .await
            .expect("insert");
        tx.commit().await.expect("commit");

        assert_eq!(
            cname_targets(&pool, url_status_id).await,
            vec!["cdn.example.com".to_string()]
        );
    }

    /// Kills: `ON CONFLICT` inserting a second `cdn.example.com` row.
    #[tokio::test]
    async fn test_insert_cname_records_conflict_is_noop() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;
        let json = r#"["cdn.example.com"]"#.to_string();

        let mut tx = pool.begin().await.expect("tx1");
        insert_cname_records(&mut tx, url_status_id, Some(&json))
            .await
            .expect("first");
        tx.commit().await.expect("commit1");

        let mut tx = pool.begin().await.expect("tx2");
        insert_cname_records(&mut tx, url_status_id, Some(&json))
            .await
            .expect("second");
        tx.commit().await.expect("commit2");

        assert_eq!(
            cname_targets(&pool, url_status_id).await,
            vec!["cdn.example.com".to_string()],
            "same cname_target must not duplicate"
        );
    }

    /// Kills: `insert_ipv6_addresses` treating `None` / invalid JSON / `[]` as a
    /// SQL write instead of `Ok` with zero rows.
    #[tokio::test]
    async fn test_insert_ipv6_addresses_none_invalid_and_empty_are_noop() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        let mut tx = pool.begin().await.expect("tx");
        insert_ipv6_addresses(&mut tx, url_status_id, None)
            .await
            .expect("None");
        insert_ipv6_addresses(&mut tx, url_status_id, Some(&"not-json".to_string()))
            .await
            .expect("invalid JSON must be Ok");
        insert_ipv6_addresses(&mut tx, url_status_id, Some(&"[]".to_string()))
            .await
            .expect("empty array");
        tx.commit().await.expect("commit");

        assert!(
            ipv6_addrs(&pool, url_status_id).await.is_empty(),
            "None / invalid JSON / [] must write zero IPv6 rows"
        );
    }

    /// Kills: `insert_ipv6_addresses` returning `Ok(())` without writing
    /// `2001:db8::1`.
    #[tokio::test]
    async fn test_insert_ipv6_addresses_writes_address() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;
        let json = r#"["2001:db8::1"]"#.to_string();

        let mut tx = pool.begin().await.expect("tx");
        insert_ipv6_addresses(&mut tx, url_status_id, Some(&json))
            .await
            .expect("insert");
        tx.commit().await.expect("commit");

        assert_eq!(
            ipv6_addrs(&pool, url_status_id).await,
            vec!["2001:db8::1".to_string()]
        );
    }

    /// Kills: `ON CONFLICT` inserting a second `2001:db8::1` row.
    #[tokio::test]
    async fn test_insert_ipv6_addresses_conflict_is_noop() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;
        let json = r#"["2001:db8::1"]"#.to_string();

        let mut tx = pool.begin().await.expect("tx1");
        insert_ipv6_addresses(&mut tx, url_status_id, Some(&json))
            .await
            .expect("first");
        tx.commit().await.expect("commit1");

        let mut tx = pool.begin().await.expect("tx2");
        insert_ipv6_addresses(&mut tx, url_status_id, Some(&json))
            .await
            .expect("second");
        tx.commit().await.expect("commit2");

        assert_eq!(
            ipv6_addrs(&pool, url_status_id).await,
            vec!["2001:db8::1".to_string()],
            "same ipv6_address must not duplicate"
        );
    }
}
