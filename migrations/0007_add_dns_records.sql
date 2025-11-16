-- Add DNS record columns for expanded DNS queries
ALTER TABLE url_status ADD COLUMN nameservers TEXT; -- JSON array of NS records
ALTER TABLE url_status ADD COLUMN txt_records TEXT; -- JSON array of TXT records
ALTER TABLE url_status ADD COLUMN mx_records TEXT; -- JSON array of MX records (priority, hostname)
ALTER TABLE url_status ADD COLUMN spf_record TEXT; -- Extracted SPF record
ALTER TABLE url_status ADD COLUMN dmarc_record TEXT; -- Extracted DMARC record

