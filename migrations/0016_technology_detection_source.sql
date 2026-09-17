-- Record which static signal produced a fingerprint match so audits do not
-- need a live refetch. Certificate authorities are omitted in code (use
-- url_status.ssl_cert_issuer); this column is for remaining serving-stack rows.
ALTER TABLE url_technologies ADD COLUMN detection_source TEXT;
