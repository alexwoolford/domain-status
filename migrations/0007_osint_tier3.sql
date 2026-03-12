-- ============================================================================
-- OSINT Tier 3: cert intelligence, CSP domains, cookies, resource hints,
-- meta refresh, body domain extraction
-- ============================================================================

-- Certificate intelligence (scalars derived from existing TLS parse)
ALTER TABLE url_status ADD COLUMN cert_serial_number TEXT;
ALTER TABLE url_status ADD COLUMN cert_is_self_signed BOOLEAN;
ALTER TABLE url_status ADD COLUMN cert_is_wildcard BOOLEAN;
ALTER TABLE url_status ADD COLUMN cert_is_mismatched BOOLEAN;

-- Meta refresh redirect target (scalar -- one per page)
ALTER TABLE url_status ADD COLUMN meta_refresh_url TEXT;

-- ============================================================================
-- SATELLITE: url_csp_domains (domains extracted from Content-Security-Policy)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_csp_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    directive TEXT NOT NULL,          -- e.g. 'default-src', 'script-src', 'img-src'
    fqdn TEXT NOT NULL,               -- e.g. 'cdn.example.com'
    registrable_domain TEXT,          -- e.g. 'example.com' (via PSL)

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, directive, fqdn)
);

CREATE INDEX idx_url_csp_domains_fqdn ON url_csp_domains(fqdn);
CREATE INDEX idx_url_csp_domains_registrable ON url_csp_domains(registrable_domain);

-- ============================================================================
-- SATELLITE: url_cookies (Set-Cookie security analysis)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_cookies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    cookie_name TEXT NOT NULL,
    secure BOOLEAN NOT NULL DEFAULT 0,
    http_only BOOLEAN NOT NULL DEFAULT 0,
    same_site TEXT,                   -- 'Strict', 'Lax', 'None', or NULL
    domain TEXT,
    path TEXT,

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, cookie_name)
);

CREATE INDEX idx_url_cookies_name ON url_cookies(cookie_name);

-- ============================================================================
-- SATELLITE: url_resource_hints (preconnect, dns-prefetch)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_resource_hints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    hint_type TEXT NOT NULL,          -- 'preconnect' or 'dns-prefetch'
    href TEXT NOT NULL,

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, hint_type, href)
);

CREATE INDEX idx_url_resource_hints_type ON url_resource_hints(hint_type);

-- ============================================================================
-- SATELLITE: url_body_domains (FQDNs extracted from HTML body)
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_body_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    fqdn TEXT NOT NULL,
    registrable_domain TEXT,          -- via PSL

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, fqdn)
);

CREATE INDEX idx_url_body_domains_fqdn ON url_body_domains(fqdn);
CREATE INDEX idx_url_body_domains_registrable ON url_body_domains(registrable_domain);
