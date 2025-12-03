//! GeoIP data insertion.

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;

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
