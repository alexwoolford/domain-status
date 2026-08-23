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
/// Content-Security-Policy-Report-Only header
pub(crate) const HEADER_CONTENT_SECURITY_POLICY_REPORT_ONLY: &str =
    "Content-Security-Policy-Report-Only";
/// Cross-Origin-Opener-Policy header
pub(crate) const HEADER_CROSS_ORIGIN_OPENER_POLICY: &str = "Cross-Origin-Opener-Policy";
/// Cross-Origin-Embedder-Policy header
pub(crate) const HEADER_CROSS_ORIGIN_EMBEDDER_POLICY: &str = "Cross-Origin-Embedder-Policy";
/// Cross-Origin-Resource-Policy header
pub(crate) const HEADER_CROSS_ORIGIN_RESOURCE_POLICY: &str = "Cross-Origin-Resource-Policy";
/// Access-Control-Allow-Origin header
pub(crate) const HEADER_ACCESS_CONTROL_ALLOW_ORIGIN: &str = "Access-Control-Allow-Origin";
/// Access-Control-Allow-Methods header
pub(crate) const HEADER_ACCESS_CONTROL_ALLOW_METHODS: &str = "Access-Control-Allow-Methods";
/// Access-Control-Allow-Headers header
pub(crate) const HEADER_ACCESS_CONTROL_ALLOW_HEADERS: &str = "Access-Control-Allow-Headers";
/// Access-Control-Allow-Credentials header
pub(crate) const HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS: &str =
    "Access-Control-Allow-Credentials";
/// Access-Control-Expose-Headers header
pub(crate) const HEADER_ACCESS_CONTROL_EXPOSE_HEADERS: &str = "Access-Control-Expose-Headers";
/// Access-Control-Max-Age header
pub(crate) const HEADER_ACCESS_CONTROL_MAX_AGE: &str = "Access-Control-Max-Age";

/// List of security headers to capture.
/// These are stored in the `url_security_headers` table.
/// To add/remove headers, modify this array.
pub(crate) const SECURITY_HEADERS: &[&str] = &[
    HEADER_CONTENT_SECURITY_POLICY,
    HEADER_CONTENT_SECURITY_POLICY_REPORT_ONLY,
    HEADER_STRICT_TRANSPORT_SECURITY,
    HEADER_X_CONTENT_TYPE_OPTIONS,
    HEADER_X_FRAME_OPTIONS,
    HEADER_X_XSS_PROTECTION,
    HEADER_REFERRER_POLICY,
    HEADER_PERMISSIONS_POLICY,
    HEADER_CROSS_ORIGIN_OPENER_POLICY,
    HEADER_CROSS_ORIGIN_EMBEDDER_POLICY,
    HEADER_CROSS_ORIGIN_RESOURCE_POLICY,
    HEADER_ACCESS_CONTROL_ALLOW_ORIGIN,
    HEADER_ACCESS_CONTROL_ALLOW_METHODS,
    HEADER_ACCESS_CONTROL_ALLOW_HEADERS,
    HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS,
    HEADER_ACCESS_CONTROL_EXPOSE_HEADERS,
    HEADER_ACCESS_CONTROL_MAX_AGE,
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
/// CF-Cache-Status header (Cloudflare cache status)
pub(crate) const HEADER_CF_CACHE_STATUS: &str = "CF-Cache-Status";
/// X-Served-By header (Fastly server identification)
pub(crate) const HEADER_X_SERVED_BY: &str = "X-Served-By";
/// Via header (proxy chain information)
pub(crate) const HEADER_VIA: &str = "Via";
/// CloudFront request ID
pub(crate) const HEADER_X_AMZ_CF_ID: &str = "X-Amz-Cf-Id";
/// CloudFront PoP
pub(crate) const HEADER_X_AMZ_CF_POP: &str = "X-Amz-Cf-Pop";
/// Azure Front Door / CDN ref
pub(crate) const HEADER_X_AZURE_REF: &str = "X-Azure-Ref";
/// Azure / MS Edge ref
pub(crate) const HEADER_X_MSEDGE_REF: &str = "X-MSEdge-Ref";
/// Akamai request ID
pub(crate) const HEADER_X_AKAMAI_REQUEST_ID: &str = "X-Akamai-Request-ID";
/// Vercel request ID
pub(crate) const HEADER_X_VERCEL_ID: &str = "X-Vercel-Id";
/// Vercel cache status
pub(crate) const HEADER_X_VERCEL_CACHE: &str = "X-Vercel-Cache";
/// Netlify request ID
pub(crate) const HEADER_X_NF_REQUEST_ID: &str = "X-Nf-Request-Id";
/// Fastly IO info
pub(crate) const HEADER_FASTLY_IO_INFO: &str = "Fastly-IO-Info";

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

// Resource discovery / protocol negotiation
/// Link header (rel=preload/prefetch/alternate/etc. resource hints and pagination)
pub(crate) const HEADER_LINK: &str = "Link";
/// Alt-Svc header (alternative service/protocol advertisement, e.g. HTTP/3 support)
pub(crate) const HEADER_ALT_SVC: &str = "Alt-Svc";
/// Accept-CH header (client hints the server requests from the client)
pub(crate) const HEADER_ACCEPT_CH: &str = "Accept-CH";
/// Critical-CH header (client hints required before the client should retry)
pub(crate) const HEADER_CRITICAL_CH: &str = "Critical-CH";
/// Clear-Site-Data header (instructs browser to clear cookies/storage/cache)
pub(crate) const HEADER_CLEAR_SITE_DATA: &str = "Clear-Site-Data";
/// Report-To header (reporting API endpoint configuration)
pub(crate) const HEADER_REPORT_TO: &str = "Report-To";
/// NEL header (Network Error Logging configuration)
pub(crate) const HEADER_NEL: &str = "NEL";
/// X-Robots-Tag (indexability directives from the origin)
pub(crate) const HEADER_X_ROBOTS_TAG: &str = "X-Robots-Tag";

/// List of other HTTP headers to capture (non-security).
/// These are stored in the `url_http_headers` table.
/// Headers are categorized by use case:
/// - Infrastructure: Server, X-Powered-By, X-Generator (technology detection)
/// - CDN/Proxy: CF-Ray, X-Served-By, Via (infrastructure analysis)
/// - Performance: Server-Timing, X-Cache (performance monitoring)
/// - Caching: Cache-Control, `ETag`, Last-Modified (cache analysis)
/// - Resource discovery/negotiation: Link, Alt-Svc, Accept-CH, Critical-CH,
///   Clear-Site-Data, Report-To, NEL (resource hints, protocol upgrades, client
///   hints, and reporting configuration)
/// - SEO / crawl: X-Robots-Tag
///
/// To add/remove headers, modify this array.
pub(crate) const HTTP_HEADERS: &[&str] = &[
    // Infrastructure/Server identification
    HEADER_SERVER,
    HEADER_X_POWERED_BY,
    HEADER_X_GENERATOR,
    // CDN/Proxy identification
    HEADER_CF_RAY,
    HEADER_CF_CACHE_STATUS,
    HEADER_X_SERVED_BY,
    HEADER_VIA,
    HEADER_X_AMZ_CF_ID,
    HEADER_X_AMZ_CF_POP,
    HEADER_X_AZURE_REF,
    HEADER_X_MSEDGE_REF,
    HEADER_X_AKAMAI_REQUEST_ID,
    HEADER_X_VERCEL_ID,
    HEADER_X_VERCEL_CACHE,
    HEADER_X_NF_REQUEST_ID,
    HEADER_FASTLY_IO_INFO,
    // Performance/Monitoring
    HEADER_SERVER_TIMING,
    HEADER_X_CACHE,
    // Caching
    HEADER_CACHE_CONTROL,
    HEADER_ETAG,
    HEADER_LAST_MODIFIED,
    // Resource discovery/protocol negotiation
    HEADER_LINK,
    HEADER_ALT_SVC,
    HEADER_ACCEPT_CH,
    HEADER_CRITICAL_CH,
    HEADER_CLEAR_SITE_DATA,
    HEADER_REPORT_TO,
    HEADER_NEL,
    // SEO / crawl
    HEADER_X_ROBOTS_TAG,
];
