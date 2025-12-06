-- Add security warnings table
-- Stores security analysis warnings for each URL status record

CREATE TABLE IF NOT EXISTS url_security_warnings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    warning_code TEXT NOT NULL,
    warning_description TEXT NOT NULL,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, warning_code)
);

-- Index for querying by warning type
CREATE INDEX IF NOT EXISTS idx_url_security_warnings_code ON url_security_warnings(warning_code);

-- Index for querying by url_status_id
CREATE INDEX IF NOT EXISTS idx_url_security_warnings_status_id ON url_security_warnings(url_status_id);
