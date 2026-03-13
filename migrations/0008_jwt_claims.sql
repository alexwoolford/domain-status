-- ============================================================================
-- SATELLITE: url_jwt_claims (decoded JWT header + payload)
-- 1:1 with url_exposed_secrets. Only populated for secret_type 'jwt'/'jwt-base64'.
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_jwt_claims (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exposed_secret_id INTEGER NOT NULL,
    header_json TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    algorithm TEXT,
    token_type TEXT,
    issuer TEXT,
    subject TEXT,
    audience TEXT,
    expiration_ms INTEGER,
    issued_at_ms INTEGER,
    not_before_ms INTEGER,
    jwt_id TEXT,
    FOREIGN KEY (exposed_secret_id) REFERENCES url_exposed_secrets(id) ON DELETE CASCADE,
    UNIQUE(exposed_secret_id)
);

CREATE INDEX IF NOT EXISTS idx_url_jwt_claims_algorithm ON url_jwt_claims(algorithm);
CREATE INDEX IF NOT EXISTS idx_url_jwt_claims_issuer ON url_jwt_claims(issuer);
