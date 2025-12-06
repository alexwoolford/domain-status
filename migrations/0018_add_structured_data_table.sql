-- Create table for structured data (JSON-LD, Open Graph, Twitter Cards, Schema.org)
CREATE TABLE IF NOT EXISTS url_structured_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    data_type TEXT NOT NULL, -- 'json_ld', 'open_graph', 'twitter_card', 'schema_type'
    property_name TEXT NOT NULL, -- For Open Graph/Twitter: property name (e.g., 'og:title', 'twitter:card')
                                 -- For JSON-LD: empty string (full JSON stored in value)
                                 -- For Schema types: the @type value (e.g., 'Organization', 'Product')
    property_value TEXT NOT NULL, -- For Open Graph/Twitter: content value
                                  -- For JSON-LD: full JSON object as string
                                  -- For Schema types: empty string (type is in property_name)
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_url_structured_data_type ON url_structured_data(data_type);
CREATE INDEX IF NOT EXISTS idx_url_structured_data_property ON url_structured_data(property_name);
CREATE INDEX IF NOT EXISTS idx_url_structured_data_status_id ON url_structured_data(url_status_id);

-- Composite index for common queries (e.g., find all og:title values)
CREATE INDEX IF NOT EXISTS idx_url_structured_data_type_property ON url_structured_data(data_type, property_name);
