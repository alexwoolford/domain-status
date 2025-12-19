//! GeoIP data insertion.

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;

/// Inserts GeoIP data for a URL status record.
///
/// This should be called after `insert_url_record` to populate geographic
/// and network information for the IP address.
/// Note: ip_address is not stored here - it's in the url_status table.
pub async fn insert_geoip_data(
    pool: &SqlitePool,
    url_status_id: i64,
    _ip_address: &str, // Kept for API compatibility, but not stored (use url_status.ip_address)
    geoip: &crate::geoip::GeoIpResult,
) -> Result<(), DatabaseError> {
    sqlx::query(
        "INSERT INTO url_geoip (
            url_status_id, country_code, country_name, region, city,
            latitude, longitude, postal_code, timezone, asn, asn_org
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(url_status_id) DO UPDATE SET
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geoip::GeoIpResult;
    use sqlx::Row;

    use crate::storage::test_helpers::{create_test_pool, create_test_url_status_default};

    fn create_test_geoip_result() -> GeoIpResult {
        GeoIpResult {
            country_code: Some("US".to_string()),
            country_name: Some("United States".to_string()),
            region: Some("California".to_string()),
            city: Some("San Francisco".to_string()),
            latitude: Some(37.7749),
            longitude: Some(-122.4194),
            postal_code: Some("94102".to_string()),
            timezone: Some("America/Los_Angeles".to_string()),
            asn: Some(15169),
            asn_org: Some("Google LLC".to_string()),
        }
    }

    #[tokio::test]
    async fn test_insert_geoip_data_basic() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;
        let geoip = create_test_geoip_result();

        let result = insert_geoip_data(&pool, url_status_id, "93.184.216.34", &geoip).await;
        assert!(result.is_ok());

        // Verify insertion
        let row = sqlx::query(
            "SELECT country_code, country_name, region, city, latitude, longitude, asn, asn_org FROM url_geoip WHERE url_status_id = ?",
        )
        .bind(url_status_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch geoip data");

        // Note: ip_address is no longer stored in url_geoip - it's in url_status table
        assert_eq!(
            row.get::<Option<String>, _>("country_code"),
            Some("US".to_string())
        );
        assert_eq!(
            row.get::<Option<String>, _>("country_name"),
            Some("United States".to_string())
        );
        assert_eq!(
            row.get::<Option<String>, _>("region"),
            Some("California".to_string())
        );
        assert_eq!(
            row.get::<Option<String>, _>("city"),
            Some("San Francisco".to_string())
        );
        assert_eq!(row.get::<Option<f64>, _>("latitude"), Some(37.7749));
        assert_eq!(row.get::<Option<f64>, _>("longitude"), Some(-122.4194));
        assert_eq!(row.get::<Option<i64>, _>("asn"), Some(15169));
        assert_eq!(
            row.get::<Option<String>, _>("asn_org"),
            Some("Google LLC".to_string())
        );
    }

    #[tokio::test]
    async fn test_insert_geoip_data_upsert() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;
        let mut geoip = create_test_geoip_result();

        // Insert first time
        let result1 = insert_geoip_data(&pool, url_status_id, "93.184.216.34", &geoip).await;
        assert!(result1.is_ok());

        // Update and insert again (should upsert)
        geoip.city = Some("Los Angeles".to_string());
        geoip.region = Some("California".to_string());
        let result2 = insert_geoip_data(&pool, url_status_id, "93.184.216.34", &geoip).await;
        assert!(result2.is_ok());

        // Verify only one row exists and it was updated
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_geoip WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to count geoip records");

        assert_eq!(count, 1);

        let row = sqlx::query("SELECT city FROM url_geoip WHERE url_status_id = ?")
            .bind(url_status_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch updated geoip data");

        assert_eq!(
            row.get::<Option<String>, _>("city"),
            Some("Los Angeles".to_string())
        );
    }

    #[tokio::test]
    async fn test_insert_geoip_data_partial() {
        let pool = create_test_pool().await;
        let url_status_id = create_test_url_status_default(&pool).await;

        // GeoIP result with only some fields
        let geoip = GeoIpResult {
            country_code: Some("US".to_string()),
            country_name: Some("United States".to_string()),
            region: None,
            city: None,
            latitude: None,
            longitude: None,
            postal_code: None,
            timezone: None,
            asn: None,
            asn_org: None,
        };

        let result = insert_geoip_data(&pool, url_status_id, "93.184.216.34", &geoip).await;
        assert!(result.is_ok());

        // Verify partial data was inserted
        let row =
            sqlx::query("SELECT country_code, city, asn FROM url_geoip WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_one(&pool)
                .await
                .expect("Failed to fetch geoip data");

        assert_eq!(
            row.get::<Option<String>, _>("country_code"),
            Some("US".to_string())
        );
        assert_eq!(row.get::<Option<String>, _>("city"), None);
        assert_eq!(row.get::<Option<i64>, _>("asn"), None);
    }
}
