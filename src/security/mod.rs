//! URL safety and SSRF-prevention helpers.
//!
//! - HSTS directive parsing
//! - SSRF-safe DNS resolution and redirect policy
//! - URL validation before dispatching a request

mod hsts;
pub(crate) mod safe_resolver;
mod url_validation;

#[allow(unused_imports)]
// Public API re-export; HstsDirectives is the parse_hsts_directive return type
pub use hsts::{parse_hsts_directive, HstsDirectives};
pub use url_validation::{ssrf_safe_redirect_policy, validate_url_safe};
