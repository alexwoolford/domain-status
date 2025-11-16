-- Add enhanced TLS analysis columns: cipher suite and key algorithm
ALTER TABLE url_status ADD COLUMN cipher_suite TEXT;
ALTER TABLE url_status ADD COLUMN key_algorithm TEXT;

