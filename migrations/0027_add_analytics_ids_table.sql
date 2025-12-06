-- Add analytics/tracking IDs table
-- This table stores analytics and tracking IDs extracted from HTML/JavaScript
-- (Google Analytics, Facebook Pixel, Google Tag Manager, Google AdSense)
-- These IDs enable graph analysis by linking domains that share the same tracking IDs

CREATE TABLE IF NOT EXISTS url_analytics_ids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    provider TEXT NOT NULL,  -- Analytics provider (e.g., "Google Analytics", "Facebook Pixel", "Google Tag Manager", "Google AdSense")
    tracking_id TEXT NOT NULL,  -- The tracking ID (e.g., "UA-123456-1", "G-XXXXXXXXXX", "1234567890", "GTM-XXXXX", "pub-XXXXXXXXXX")
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE (url_status_id, provider, tracking_id)  -- Prevent duplicate entries per URL
);

-- Index for querying by provider (e.g., find all URLs using Google Analytics)
CREATE INDEX IF NOT EXISTS idx_url_analytics_ids_provider ON url_analytics_ids(provider);

-- Index for querying by tracking_id (enables finding all URLs sharing a tracking ID - key for graph analysis)
CREATE INDEX IF NOT EXISTS idx_url_analytics_ids_tracking_id ON url_analytics_ids(tracking_id);

-- Index for querying by url_status_id
CREATE INDEX IF NOT EXISTS idx_url_analytics_ids_url_status_id ON url_analytics_ids(url_status_id);
