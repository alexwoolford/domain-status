-- Create url_geoip table for GeoIP lookup results
-- This table stores geographic and network information for IP addresses
-- One-to-one relationship with url_status (one GeoIP record per URL)

CREATE TABLE IF NOT EXISTS url_geoip (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL, -- Duplicated from url_status for convenience (denormalized)
    country_code TEXT, -- ISO 3166-1 alpha-2 country code (e.g., "US", "GB")
    country_name TEXT, -- Full country name (e.g., "United States", "United Kingdom")
    region TEXT, -- State/province/region name (e.g., "California", "England")
    city TEXT, -- City name (e.g., "San Francisco", "London")
    latitude REAL, -- Latitude coordinate
    longitude REAL, -- Longitude coordinate
    postal_code TEXT, -- Postal/ZIP code
    timezone TEXT, -- Timezone (e.g., "America/Los_Angeles", "Europe/London")
    asn INTEGER, -- Autonomous System Number (if available from ASN database)
    asn_org TEXT, -- ASN organization name (e.g., "AS15169 Google LLC")
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE (url_status_id) -- One-to-one relationship
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_url_geoip_country_code ON url_geoip(country_code);
CREATE INDEX IF NOT EXISTS idx_url_geoip_city ON url_geoip(city);
CREATE INDEX IF NOT EXISTS idx_url_geoip_asn ON url_geoip(asn);
CREATE INDEX IF NOT EXISTS idx_url_geoip_url_status_id ON url_geoip(url_status_id);

