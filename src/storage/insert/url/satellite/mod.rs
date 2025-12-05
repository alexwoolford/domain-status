//! Satellite table insertion helpers.
//!
//! This module provides functions to insert data into satellite tables that are
//! related to the main `url_status` table. Each submodule handles a specific
//! category of satellite data:
//!
//! - `technologies`: Technology detection results
//! - `dns`: DNS records (nameservers, TXT, MX)
//! - `headers`: HTTP and security headers
//! - `certificates`: Certificate OIDs and Subject Alternative Names
//! - `redirects`: Redirect chain URLs

mod certificates;
mod dns;
mod headers;
mod redirects;
mod technologies;

#[cfg(test)]
mod tests;

// Re-export all public functions
pub(crate) use certificates::{insert_certificate_sans, insert_oids};
pub(crate) use dns::{insert_mx_records, insert_nameservers, insert_txt_records};
pub(crate) use headers::{insert_http_headers, insert_security_headers};
pub(crate) use redirects::insert_redirect_chain;
pub(crate) use technologies::insert_technologies;
