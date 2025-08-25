-- Create base table
CREATE TABLE IF NOT EXISTS url_status (
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
    ssl_cert_subject TEXT NOT NULL,
    ssl_cert_issuer TEXT NOT NULL,
    ssl_cert_valid_from INTEGER,
    ssl_cert_valid_to INTEGER,
    oids STRING,
    is_mobile_friendly BOOLEAN,
    timestamp INTEGER NOT NULL
);

