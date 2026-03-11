-- ============================================================================
-- Tier 1 OSINT additions: body fingerprint, content metrics, HTTP version, etc.
-- ============================================================================

-- Response body SHA-256 hash for fingerprinting identical pages across domains
ALTER TABLE url_status ADD COLUMN body_sha256 TEXT;

-- Response body length in bytes
ALTER TABLE url_status ADD COLUMN content_length INTEGER;

-- HTTP protocol version (HTTP/1.0, HTTP/1.1, HTTP/2)
ALTER TABLE url_status ADD COLUMN http_version TEXT;

-- Word and line count for content analysis and fingerprinting
ALTER TABLE url_status ADD COLUMN body_word_count INTEGER;
ALTER TABLE url_status ADD COLUMN body_line_count INTEGER;

-- Content-Type header as standalone queryable field
ALTER TABLE url_status ADD COLUMN content_type TEXT;

-- Canonical URL from <link rel="canonical">
ALTER TABLE url_status ADD COLUMN canonical_url TEXT;

-- SHA-256 fingerprint of the leaf TLS certificate DER
ALTER TABLE url_status ADD COLUMN cert_fingerprint_sha256 TEXT;

-- HTTP status code per redirect hop (301 vs 302 matters for SEO/caching)
ALTER TABLE url_redirect_chain ADD COLUMN http_status INTEGER;
