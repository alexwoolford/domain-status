-- Add certificate Subject Alternative Names (SANs) table
-- This table stores DNS names from the Subject Alternative Name extension of SSL/TLS certificates
-- SANs enable graph analysis by linking domains that share the same certificate

CREATE TABLE IF NOT EXISTS url_certificate_sans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    domain_name TEXT NOT NULL,  -- DNS name from certificate SAN extension
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE (url_status_id, domain_name)  -- Prevent duplicate SAN entries per URL
);

-- Index for querying by domain name (enables finding all URLs sharing a certificate)
CREATE INDEX IF NOT EXISTS idx_url_certificate_sans_domain_name ON url_certificate_sans(domain_name);

-- Index for querying by url_status_id
CREATE INDEX IF NOT EXISTS idx_url_certificate_sans_url_status_id ON url_certificate_sans(url_status_id);
