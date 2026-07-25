//! HTTP header name constants.
//!
//! This module defines constants for security headers and other HTTP headers
//! that are captured and stored in the database.

// Security header names
// These headers are stored in the url_security_headers table
/// Content Security Policy header
pub(crate) const HEADER_CONTENT_SECURITY_POLICY: &str = "Content-Security-Policy";
/// HTTP Strict Transport Security header
pub(crate) const HEADER_STRICT_TRANSPORT_SECURITY: &str = "Strict-Transport-Security";
/// X-Content-Type-Options header
pub(crate) const HEADER_X_CONTENT_TYPE_OPTIONS: &str = "X-Content-Type-Options";
/// X-Frame-Options header
pub(crate) const HEADER_X_FRAME_OPTIONS: &str = "X-Frame-Options";
/// X-XSS-Protection header
pub(crate) const HEADER_X_XSS_PROTECTION: &str = "X-XSS-Protection";
/// Referrer-Policy header
pub(crate) const HEADER_REFERRER_POLICY: &str = "Referrer-Policy";
/// Permissions-Policy header
pub(crate) const HEADER_PERMISSIONS_POLICY: &str = "Permissions-Policy";

/// List of security headers to capture.
/// These are stored in the `url_security_headers` table.
/// To add/remove headers, modify this array.
pub(crate) const SECURITY_HEADERS: &[&str] = &[
    HEADER_CONTENT_SECURITY_POLICY,
    HEADER_STRICT_TRANSPORT_SECURITY,
    HEADER_X_CONTENT_TYPE_OPTIONS,
    HEADER_X_FRAME_OPTIONS,
    HEADER_X_XSS_PROTECTION,
    HEADER_REFERRER_POLICY,
    HEADER_PERMISSIONS_POLICY,
];

// Other HTTP header names
// These headers are stored in the url_http_headers table
// Infrastructure/Server identification
/// Server header (identifies server software)
pub(crate) const HEADER_SERVER: &str = "Server";
/// X-Powered-By header (identifies server framework)
pub(crate) const HEADER_X_POWERED_BY: &str = "X-Powered-By";
/// X-Generator header (identifies CMS/generator)
pub(crate) const HEADER_X_GENERATOR: &str = "X-Generator";

// CDN/Proxy identification
/// CF-Ray header (Cloudflare request ID)
pub(crate) const HEADER_CF_RAY: &str = "CF-Ray";
/// X-Served-By header (Fastly server identification)
pub(crate) const HEADER_X_SERVED_BY: &str = "X-Served-By";
/// Via header (proxy chain information)
pub(crate) const HEADER_VIA: &str = "Via";

// Performance/Monitoring
/// Server-Timing header (performance metrics)
pub(crate) const HEADER_SERVER_TIMING: &str = "Server-Timing";
/// X-Cache header (cache status)
pub(crate) const HEADER_X_CACHE: &str = "X-Cache";

// Caching
/// Cache-Control header
pub(crate) const HEADER_CACHE_CONTROL: &str = "Cache-Control";
/// `ETag` header
pub(crate) const HEADER_ETAG: &str = "ETag";
/// Last-Modified header
pub(crate) const HEADER_LAST_MODIFIED: &str = "Last-Modified";

/// List of other HTTP headers to capture (non-security).
/// These are stored in the `url_http_headers` table.
/// Headers are categorized by use case:
/// - Infrastructure: Server, X-Powered-By, X-Generator (technology detection)
/// - CDN/Proxy: CF-Ray, X-Served-By, Via (infrastructure analysis)
/// - Performance: Server-Timing, X-Cache (performance monitoring)
/// - Caching: Cache-Control, `ETag`, Last-Modified (cache analysis)
///
/// To add/remove headers, modify this array.
pub(crate) const HTTP_HEADERS: &[&str] = &[
    // Infrastructure/Server identification
    HEADER_SERVER,
    HEADER_X_POWERED_BY,
    HEADER_X_GENERATOR,
    // CDN/Proxy identification
    HEADER_CF_RAY,
    HEADER_X_SERVED_BY,
    HEADER_VIA,
    // Performance/Monitoring
    HEADER_SERVER_TIMING,
    HEADER_X_CACHE,
    // Caching
    HEADER_CACHE_CONTROL,
    HEADER_ETAG,
    HEADER_LAST_MODIFIED,
];
