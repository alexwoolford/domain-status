-- ============================================================================
-- domain_status - Initial Schema (Consolidated)
-- ============================================================================
-- This is a clean, consolidated schema that replaces the 33 iterative migrations.
--
-- Design Principles:
-- 1. Star schema: url_status is the fact table, runs is the dimension table
-- 2. Normalized satellites for multi-valued attributes (technologies, headers, etc.)
-- 3. Proper FK constraints with ON DELETE CASCADE for referential integrity
-- 4. Clean naming: http_status (not status), observed_at_ms (not timestamp)
-- 5. Only necessary indexes (no redundant ones)
-- 6. Consistent timestamp naming: *_at_ms for epoch millis, *_seconds for durations
-- ============================================================================

-- ============================================================================
-- DIMENSION TABLE: runs
-- Stores metadata about each scan execution (batch run)
-- ============================================================================
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    version TEXT,                    -- Application version that ran the scan
    fingerprints_source TEXT,        -- Source URL/path of fingerprint ruleset
    fingerprints_version TEXT,       -- Commit SHA of fingerprint ruleset
    geoip_version TEXT,              -- GeoIP database version used
    start_time_ms INTEGER NOT NULL,  -- Scan start time (milliseconds since epoch)
    end_time_ms INTEGER,             -- Scan end time (NULL if still running)
    elapsed_seconds REAL,            -- Total execution time in seconds
    total_urls INTEGER DEFAULT 0,
    successful_urls INTEGER DEFAULT 0,
    failed_urls INTEGER DEFAULT 0
);

CREATE INDEX idx_runs_start_time ON runs(start_time_ms);

-- ============================================================================
-- FACT TABLE: url_status (successful observations)
-- Stores the result of successfully scanning a URL
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Domain identification
    initial_domain TEXT NOT NULL,    -- Original domain from input URL
    final_domain TEXT NOT NULL,      -- Domain after following redirects

    -- Network
    ip_address TEXT NOT NULL,        -- Resolved IP address
    reverse_dns_name TEXT,           -- PTR record for IP

    -- HTTP response
    http_status INTEGER NOT NULL,    -- HTTP status code (200, 301, 404, etc.)
    http_status_text TEXT NOT NULL,  -- Human-readable status ("OK", "Not Found")
    response_time_seconds REAL NOT NULL,  -- Time to get response

    -- HTML metadata
    title TEXT NOT NULL,             -- Page title (empty string if missing)
    keywords TEXT,                   -- Meta keywords
    description TEXT,                -- Meta description
    is_mobile_friendly BOOLEAN NOT NULL DEFAULT 0,  -- Has viewport meta tag

    -- TLS/SSL (NULL for HTTP sites)
    tls_version TEXT,                -- e.g., "TLSv1.3"
    cipher_suite TEXT,               -- e.g., "TLS_AES_256_GCM_SHA384"
    key_algorithm TEXT,              -- e.g., "ECDSA"
    ssl_cert_subject TEXT,           -- Certificate subject
    ssl_cert_issuer TEXT,            -- Certificate issuer
    ssl_cert_valid_from_ms INTEGER,  -- Certificate start validity (epoch ms)
    ssl_cert_valid_to_ms INTEGER,    -- Certificate end validity (epoch ms)

    -- DNS records (extracted for convenience)
    spf_record TEXT,                 -- SPF record if found
    dmarc_record TEXT,               -- DMARC record if found

    -- Tracking
    observed_at_ms INTEGER NOT NULL, -- When this observation was made (epoch ms)
    run_id TEXT,                     -- FK to runs table

    -- Constraints
    UNIQUE(final_domain, observed_at_ms),
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE SET NULL
);

-- Indexes for common query patterns
CREATE INDEX idx_url_status_initial_domain ON url_status(initial_domain);
CREATE INDEX idx_url_status_final_domain ON url_status(final_domain);
CREATE INDEX idx_url_status_http_status ON url_status(http_status);
CREATE INDEX idx_url_status_observed_at ON url_status(observed_at_ms);
CREATE INDEX idx_url_status_run_id ON url_status(run_id, observed_at_ms);

-- ============================================================================
-- FACT TABLE: url_failures (failed URL processing attempts)
-- Stores information about URLs that failed to process
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- URL identification
    attempted_url TEXT NOT NULL,     -- Original URL we tried to fetch
    final_url TEXT,                  -- URL after redirects (if any before failure)
    initial_domain TEXT NOT NULL,    -- Domain from original URL
    final_domain TEXT,               -- Domain after redirects (if any)

    -- Error details
    error_type TEXT NOT NULL,        -- Categorized error type
    error_message TEXT NOT NULL,     -- Full error message for debugging
    http_status INTEGER,             -- HTTP status if available (403, 500, etc.)
    retry_count INTEGER NOT NULL DEFAULT 0,
    elapsed_time_seconds REAL,       -- Time spent before failure

    -- Tracking
    observed_at_ms INTEGER NOT NULL, -- When failure occurred (epoch ms)
    run_id TEXT,

    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE SET NULL
);

CREATE INDEX idx_url_failures_initial_domain ON url_failures(initial_domain);
CREATE INDEX idx_url_failures_error_type ON url_failures(error_type);
CREATE INDEX idx_url_failures_http_status ON url_failures(http_status);
CREATE INDEX idx_url_failures_run_id ON url_failures(run_id, observed_at_ms);

-- ============================================================================
-- SATELLITE: url_partial_failures
-- Records partial failures (DNS/TLS errors that didn't block URL processing)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_partial_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    error_type TEXT NOT NULL,        -- e.g., "DNS NS lookup error", "TLS certificate error"
    error_message TEXT NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    run_id TEXT,

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE SET NULL
);

CREATE INDEX idx_url_partial_failures_error_type ON url_partial_failures(error_type);
CREATE INDEX idx_url_partial_failures_run_id ON url_partial_failures(run_id);

-- ============================================================================
-- SATELLITE: url_technologies (detected web technologies)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_technologies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    technology_name TEXT NOT NULL,
    technology_version TEXT,         -- Version if detected (NULL otherwise)
    technology_category TEXT,        -- e.g., "CMS", "JavaScript framework"

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE
);

-- Partial unique indexes to handle NULL version correctly
CREATE UNIQUE INDEX idx_url_technologies_unique_with_version
    ON url_technologies(url_status_id, technology_name, technology_version)
    WHERE technology_version IS NOT NULL;

CREATE UNIQUE INDEX idx_url_technologies_unique_no_version
    ON url_technologies(url_status_id, technology_name)
    WHERE technology_version IS NULL;

CREATE INDEX idx_url_technologies_name ON url_technologies(technology_name);

-- ============================================================================
-- SATELLITE: url_redirect_chain (redirect hops)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_redirect_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    sequence_order INTEGER NOT NULL, -- 1-based order in chain
    redirect_url TEXT NOT NULL,      -- Renamed from 'url' to avoid collision

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, sequence_order)
);

-- ============================================================================
-- SATELLITE: url_nameservers (DNS NS records)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_nameservers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    nameserver TEXT NOT NULL,

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, nameserver)
);

CREATE INDEX idx_url_nameservers_nameserver ON url_nameservers(nameserver);

-- ============================================================================
-- SATELLITE: url_txt_records (DNS TXT records)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_txt_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    record_type TEXT NOT NULL,       -- 'SPF', 'DMARC', 'VERIFICATION', 'OTHER'
    record_value TEXT NOT NULL,

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE
);

CREATE INDEX idx_url_txt_records_type ON url_txt_records(record_type);

-- ============================================================================
-- SATELLITE: url_mx_records (DNS MX records)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_mx_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    mail_exchange TEXT NOT NULL,

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, priority, mail_exchange)
);

CREATE INDEX idx_url_mx_records_exchange ON url_mx_records(mail_exchange);

-- ============================================================================
-- SATELLITE: url_security_headers (security-related HTTP headers)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_security_headers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    header_name TEXT NOT NULL,       -- e.g., "Strict-Transport-Security"
    header_value TEXT NOT NULL,

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, header_name)
);

CREATE INDEX idx_url_security_headers_name ON url_security_headers(header_name);

-- ============================================================================
-- SATELLITE: url_http_headers (non-security HTTP headers)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_http_headers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    header_name TEXT NOT NULL,       -- e.g., "Server", "CF-Ray"
    header_value TEXT NOT NULL,

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, header_name)
);

CREATE INDEX idx_url_http_headers_name ON url_http_headers(header_name);

-- ============================================================================
-- SATELLITE: url_certificate_oids (TLS certificate OIDs)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_certificate_oids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    oid TEXT NOT NULL,

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, oid)
);

CREATE INDEX idx_url_certificate_oids_oid ON url_certificate_oids(oid);

-- ============================================================================
-- SATELLITE: url_certificate_sans (TLS certificate Subject Alternative Names)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_certificate_sans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    san_value TEXT NOT NULL,         -- Renamed from domain_name for clarity

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, san_value)
);

CREATE INDEX idx_url_certificate_sans_value ON url_certificate_sans(san_value);

-- ============================================================================
-- SATELLITE: url_geoip (GeoIP enrichment - 1:1 with url_status)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_geoip (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    -- Note: ip_address is NOT duplicated here - join to url_status if needed
    country_code TEXT,               -- ISO 3166-1 alpha-2
    country_name TEXT,
    region TEXT,
    city TEXT,
    latitude REAL,
    longitude REAL,
    postal_code TEXT,
    timezone TEXT,
    asn INTEGER,
    asn_org TEXT,

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id)            -- 1:1 relationship
);

CREATE INDEX idx_url_geoip_country_code ON url_geoip(country_code);
CREATE INDEX idx_url_geoip_asn ON url_geoip(asn);

-- ============================================================================
-- SATELLITE: url_whois (WHOIS enrichment - 1:1 with url_status)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_whois (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    creation_date_ms INTEGER,        -- Domain creation date (epoch ms)
    expiration_date_ms INTEGER,      -- Domain expiration date (epoch ms)
    updated_date_ms INTEGER,         -- Domain last updated (epoch ms)
    registrar TEXT,
    registrant_country TEXT,         -- ISO 3166-1 alpha-2
    registrant_org TEXT,
    whois_statuses TEXT,             -- Renamed from 'status' to avoid collision (JSON array)
    nameservers_json TEXT,           -- JSON array of nameservers
    raw_response TEXT,               -- Raw WHOIS text for debugging

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id)            -- 1:1 relationship
);

CREATE INDEX idx_url_whois_registrar ON url_whois(registrar);
CREATE INDEX idx_url_whois_registrant_country ON url_whois(registrant_country);

-- ============================================================================
-- SATELLITE: url_structured_data (JSON-LD, Open Graph, Twitter Cards)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_structured_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    data_type TEXT NOT NULL,         -- 'json_ld', 'open_graph', 'twitter_card', 'schema_type'
    property_name TEXT NOT NULL,
    property_value TEXT NOT NULL,

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE
);

CREATE INDEX idx_url_structured_data_type ON url_structured_data(data_type);
CREATE INDEX idx_url_structured_data_type_property ON url_structured_data(data_type, property_name);

-- ============================================================================
-- SATELLITE: url_social_media_links (extracted social media profiles)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_social_media_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    platform TEXT NOT NULL,          -- e.g., 'LinkedIn', 'Twitter', 'Facebook'
    profile_url TEXT NOT NULL,       -- Renamed from 'url' to avoid collision
    identifier TEXT,                 -- Username/handle extracted from URL

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, platform, profile_url)
);

CREATE INDEX idx_url_social_media_links_platform ON url_social_media_links(platform);
CREATE INDEX idx_url_social_media_links_identifier ON url_social_media_links(identifier);

-- ============================================================================
-- SATELLITE: url_analytics_ids (tracking IDs for graph analysis)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_analytics_ids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    provider TEXT NOT NULL,          -- e.g., 'Google Analytics', 'Facebook Pixel'
    tracking_id TEXT NOT NULL,       -- e.g., 'UA-123456-1', 'G-XXXXXXXXXX'

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, provider, tracking_id)
);

CREATE INDEX idx_url_analytics_ids_provider ON url_analytics_ids(provider);
CREATE INDEX idx_url_analytics_ids_tracking_id ON url_analytics_ids(tracking_id);

-- ============================================================================
-- SATELLITE: url_security_warnings (security analysis findings)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_security_warnings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    warning_code TEXT NOT NULL,
    warning_description TEXT NOT NULL,

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, warning_code)
);

CREATE INDEX idx_url_security_warnings_code ON url_security_warnings(warning_code);

-- ============================================================================
-- FAILURE SATELLITES: url_failure_* tables
-- ============================================================================

-- Redirect chain for failures (hops before failure)
CREATE TABLE IF NOT EXISTS url_failure_redirect_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_failure_id INTEGER NOT NULL,
    sequence_order INTEGER NOT NULL,
    redirect_url TEXT NOT NULL,

    FOREIGN KEY (url_failure_id) REFERENCES url_failures(id) ON DELETE CASCADE,
    UNIQUE(url_failure_id, sequence_order)
);

-- Response headers received before failure
CREATE TABLE IF NOT EXISTS url_failure_response_headers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_failure_id INTEGER NOT NULL,
    header_name TEXT NOT NULL,
    header_value TEXT NOT NULL,

    FOREIGN KEY (url_failure_id) REFERENCES url_failures(id) ON DELETE CASCADE,
    UNIQUE(url_failure_id, header_name)
);

-- Request headers sent (for debugging bot detection)
CREATE TABLE IF NOT EXISTS url_failure_request_headers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_failure_id INTEGER NOT NULL,
    header_name TEXT NOT NULL,
    header_value TEXT NOT NULL,

    FOREIGN KEY (url_failure_id) REFERENCES url_failures(id) ON DELETE CASCADE,
    UNIQUE(url_failure_id, header_name)
);

-- ============================================================================
-- SATELLITE: url_favicons (Shodan-compatible favicon hashes)
-- Stores MurmurHash3 hash and base64-encoded favicon data for each URL.
-- The hash matches Shodan's http.favicon.hash for direct interoperability
-- with global threat intelligence feeds.
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_favicons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    favicon_url TEXT NOT NULL,       -- URL the favicon was fetched from
    hash INTEGER NOT NULL,           -- MurmurHash3 (Shodan-compatible)
    base64_data TEXT,                -- Base64-encoded favicon bytes

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id)            -- 1:1 relationship
);

CREATE INDEX idx_url_favicons_hash ON url_favicons(hash);
