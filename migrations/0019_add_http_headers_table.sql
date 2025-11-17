-- Create child table for HTTP headers (non-security)
-- These headers are stored separately from security headers for different use cases:
-- - Infrastructure: Server, X-Powered-By, X-Generator (technology detection)
-- - CDN/Proxy: CF-Ray, X-Served-By, Via (infrastructure analysis)
-- - Performance: Server-Timing, X-Cache (performance monitoring)
-- - Caching: Cache-Control, ETag, Last-Modified (cache analysis)

-- Step 1: Create child table for HTTP headers
CREATE TABLE IF NOT EXISTS url_http_headers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    header_name TEXT NOT NULL,
    header_value TEXT NOT NULL,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE (url_status_id, header_name)
);

CREATE INDEX IF NOT EXISTS idx_url_http_headers_name 
    ON url_http_headers(header_name);

CREATE INDEX IF NOT EXISTS idx_url_http_headers_status_id 
    ON url_http_headers(url_status_id);

