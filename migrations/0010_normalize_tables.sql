-- Create child tables for normalized relationships
-- This enables efficient querying and joining without JSON parsing

-- Technologies table: one row per technology detected per URL
CREATE TABLE IF NOT EXISTS url_technologies (
    id INTEGER PRIMARY KEY,
    url_status_id INTEGER NOT NULL,
    technology_name TEXT NOT NULL,
    technology_category TEXT,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, technology_name)
);

CREATE INDEX IF NOT EXISTS idx_url_technologies_name
    ON url_technologies(technology_name);

CREATE INDEX IF NOT EXISTS idx_url_technologies_status_id
    ON url_technologies(url_status_id);

-- Nameservers table: one row per nameserver per URL
CREATE TABLE IF NOT EXISTS url_nameservers (
    id INTEGER PRIMARY KEY,
    url_status_id INTEGER NOT NULL,
    nameserver TEXT NOT NULL,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, nameserver)
);

CREATE INDEX IF NOT EXISTS idx_url_nameservers_nameserver
    ON url_nameservers(nameserver);

CREATE INDEX IF NOT EXISTS idx_url_nameservers_status_id
    ON url_nameservers(url_status_id);

-- TXT records table: one row per TXT record per URL
-- Includes record_type for filtering (SPF, DMARC, VERIFICATION, OTHER)
CREATE TABLE IF NOT EXISTS url_txt_records (
    id INTEGER PRIMARY KEY,
    url_status_id INTEGER NOT NULL,
    txt_record TEXT NOT NULL,
    record_type TEXT, -- 'SPF', 'DMARC', 'VERIFICATION', 'OTHER'
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_url_txt_records_type
    ON url_txt_records(record_type);

CREATE INDEX IF NOT EXISTS idx_url_txt_records_status_id
    ON url_txt_records(url_status_id);

-- MX records table: one row per MX record per URL
-- Stores priority and mail exchange hostname
CREATE TABLE IF NOT EXISTS url_mx_records (
    id INTEGER PRIMARY KEY,
    url_status_id INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    mail_exchange TEXT NOT NULL,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, priority, mail_exchange)
);

CREATE INDEX IF NOT EXISTS idx_url_mx_records_exchange
    ON url_mx_records(mail_exchange);

CREATE INDEX IF NOT EXISTS idx_url_mx_records_status_id
    ON url_mx_records(url_status_id);
