-- Satellite table UNIQUE constraints so rescans do not create duplicate rows.
-- url_txt_records: matches conflict handling for url_nameservers and url_mx_records.
-- url_structured_data: same (url_status_id, data_type, property_name, property_value) deduplicated;
--   two og:image with different values remain; JSON-LD uses property_value = full blob (index can be large).

-- url_txt_records
DELETE FROM url_txt_records
WHERE id NOT IN (
    SELECT MIN(id) FROM url_txt_records
    GROUP BY url_status_id, record_type, record_value
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_url_txt_records_unique
ON url_txt_records(url_status_id, record_type, record_value);

-- url_structured_data
DELETE FROM url_structured_data
WHERE id NOT IN (
    SELECT MIN(id) FROM url_structured_data
    GROUP BY url_status_id, data_type, property_name, property_value
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_url_structured_data_unique
ON url_structured_data(url_status_id, data_type, property_name, property_value);
