-- Drop deprecated / redundant satellite tables.
--
-- url_security_warnings: findings are derivable from url_status (scheme, tls_version,
--   cert flags) and url_security_headers; no longer persisted.
-- url_body_domains: deprecated since OSINT tier work; never populated on new scans
--   (prefer CSP / analytics / social / url_script_hosts).
-- url_failure_request_headers: deprecated; failure satellite insert path skipped writes.

DROP TABLE IF EXISTS url_security_warnings;
DROP TABLE IF EXISTS url_body_domains;
DROP TABLE IF EXISTS url_failure_request_headers;
