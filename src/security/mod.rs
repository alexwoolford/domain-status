//! URL safety and SSRF-prevention helpers.
//!
//! This module holds the security-adjacent helpers that are still active:
//! - HSTS directive parsing
//! - SSRF-safe DNS resolution and redirect policy
//! - URL validation before dispatching a request
//!
//! `analyze_security`/`SecurityWarning` (previously used to populate the
//! now-dropped `url_security_warnings` table) were removed; the same signal
//! is derivable on demand from `url_status` (scheme, `tls_version`, cert
//! flags) and `url_security_headers`.

mod hsts;
pub(crate) mod safe_resolver;
mod url_validation;

#[allow(unused_imports)]
// Public API re-export; HstsDirectives is the parse_hsts_directive return type
pub use hsts::{parse_hsts_directive, HstsDirectives};
pub use url_validation::{ssrf_safe_redirect_policy, validate_url_safe};
