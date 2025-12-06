-- Add a redirect_chain TEXT column (nullable) storing JSON array of URLs
-- SQLite requires table recreation for adding columns with constraints across older versions

CREATE TABLE IF NOT EXISTS url_status_new (
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL,
    final_domain TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    reverse_dns_name TEXT,
    status INTEGER NOT NULL,
    status_description TEXT NOT NULL,
    response_time NUMERIC(10, 2),
    title TEXT NOT NULL,
    keywords TEXT,
    description TEXT,
    linkedin_slug TEXT,
    security_headers TEXT NOT NULL,
    tls_version TEXT,
    ssl_cert_subject TEXT,
    ssl_cert_issuer TEXT,
    ssl_cert_valid_from INTEGER,
    ssl_cert_valid_to INTEGER,
    oids STRING,
    is_mobile_friendly BOOLEAN,
    timestamp INTEGER NOT NULL,
    redirect_chain TEXT,
    UNIQUE (final_domain, timestamp)
);

INSERT INTO url_status_new (
    id, domain, final_domain, ip_address, reverse_dns_name, status, status_description,
    response_time, title, keywords, description, linkedin_slug, security_headers, tls_version,
    ssl_cert_subject, ssl_cert_issuer, ssl_cert_valid_from, ssl_cert_valid_to, oids, is_mobile_friendly, timestamp, redirect_chain
)
SELECT
    id, domain, final_domain, ip_address, reverse_dns_name, status, status_description,
    response_time, title, keywords, description, linkedin_slug, security_headers, tls_version,
    ssl_cert_subject, ssl_cert_issuer, ssl_cert_valid_from, ssl_cert_valid_to, oids, is_mobile_friendly, timestamp, NULL
FROM url_status;

DROP TABLE url_status;
ALTER TABLE url_status_new RENAME TO url_status;

-- Recreate indexes
CREATE INDEX IF NOT EXISTS idx_url_status_domain ON url_status(domain);
CREATE INDEX IF NOT EXISTS idx_url_status_final_domain ON url_status(final_domain);
CREATE INDEX IF NOT EXISTS idx_url_status_timestamp ON url_status(timestamp);
