-- Add WHOIS data table
-- Stores domain registration information from WHOIS/RDAP lookups

CREATE TABLE IF NOT EXISTS url_whois (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    creation_date INTEGER, -- Milliseconds since Unix epoch
    expiration_date INTEGER, -- Milliseconds since Unix epoch
    updated_date INTEGER, -- Milliseconds since Unix epoch
    registrar TEXT,
    registrant_country TEXT, -- ISO 3166-1 alpha-2 country code
    registrant_org TEXT,
    status TEXT, -- JSON array of status strings
    nameservers TEXT, -- JSON array of nameserver strings
    raw_text TEXT, -- Raw WHOIS text (for debugging)
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id)
);

-- Index for querying by registrar
CREATE INDEX IF NOT EXISTS idx_url_whois_registrar ON url_whois(registrar);

-- Index for querying by registrant country
CREATE INDEX IF NOT EXISTS idx_url_whois_country ON url_whois(registrant_country);

-- Index for querying by url_status_id
CREATE INDEX IF NOT EXISTS idx_url_whois_status_id ON url_whois(url_status_id);

