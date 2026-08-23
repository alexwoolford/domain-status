-- Observation enrichments: parsed HSTS, email-auth TXT convenience columns,
-- CDN taxonomy, security.txt / robots.txt satellites.
-- Header allowlist expansion is code-only (same url_security_headers / url_http_headers).

ALTER TABLE url_status ADD COLUMN hsts_max_age INTEGER;
ALTER TABLE url_status ADD COLUMN hsts_include_subdomains INTEGER;
ALTER TABLE url_status ADD COLUMN hsts_preload INTEGER;
ALTER TABLE url_status ADD COLUMN mta_sts_record TEXT;
ALTER TABLE url_status ADD COLUMN tls_rpt_record TEXT;
ALTER TABLE url_status ADD COLUMN bimi_record TEXT;
ALTER TABLE url_status ADD COLUMN cdn_provider TEXT;

CREATE TABLE IF NOT EXISTS url_security_txt (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    source_url TEXT,
    http_status INTEGER,
    contacts TEXT,
    expires TEXT,
    encryption TEXT,
    acknowledgments TEXT,
    preferred_languages TEXT,
    canonical TEXT,
    policy TEXT,
    hiring TEXT,
    raw_body TEXT,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id)
);

CREATE TABLE IF NOT EXISTS url_robots_txt (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    http_status INTEGER,
    raw_body TEXT,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id)
);

CREATE TABLE IF NOT EXISTS url_robots_directives (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    directive TEXT NOT NULL,
    value TEXT NOT NULL,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, directive, value)
);

CREATE INDEX IF NOT EXISTS idx_url_robots_directives_directive
    ON url_robots_directives(directive);
CREATE INDEX IF NOT EXISTS idx_url_status_cdn_provider ON url_status(cdn_provider);
