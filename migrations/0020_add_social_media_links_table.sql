-- Create child table for social media links
-- Stores social media platform links extracted from HTML (LinkedIn, Twitter, Facebook, etc.)

-- Step 1: Create child table for social media links
CREATE TABLE IF NOT EXISTS url_social_media_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    platform TEXT NOT NULL, -- e.g., 'LinkedIn', 'Twitter', 'Facebook', 'Instagram', 'YouTube', 'GitHub', 'TikTok', 'Pinterest', 'Snapchat', 'Reddit'
    url TEXT NOT NULL, -- Full URL to the social media profile/page
    identifier TEXT, -- Username, handle, or ID extracted from URL (e.g., company slug, username)
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE (url_status_id, platform, url) -- Prevent duplicate links per URL
);

CREATE INDEX IF NOT EXISTS idx_url_social_media_links_platform
    ON url_social_media_links(platform);

CREATE INDEX IF NOT EXISTS idx_url_social_media_links_status_id
    ON url_social_media_links(url_status_id);

CREATE INDEX IF NOT EXISTS idx_url_social_media_links_identifier
    ON url_social_media_links(identifier);
