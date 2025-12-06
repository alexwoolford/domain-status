-- Helpful indexes for common queries
CREATE INDEX IF NOT EXISTS idx_url_status_domain ON url_status(domain);
CREATE INDEX IF NOT EXISTS idx_url_status_final_domain ON url_status(final_domain);
CREATE INDEX IF NOT EXISTS idx_url_status_timestamp ON url_status(timestamp);
