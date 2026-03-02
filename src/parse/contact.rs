//! Contact link extraction (mailto/tel).
//!
//! This module extracts contact information from HTML documents by finding
//! `<a href="mailto:...">` and `<a href="tel:...">` links.

use scraper::{Html, Selector};
use std::collections::HashSet;
use std::fmt;
use std::sync::LazyLock;

const ANCHOR_SELECTOR_STR: &str = "a[href]";

static ANCHOR_SELECTOR: LazyLock<Selector> = LazyLock::new(|| {
    Selector::parse(ANCHOR_SELECTOR_STR)
        .expect("ANCHOR_SELECTOR_STR is a hardcoded valid CSS selector; this is a compile-time bug")
});

/// Type of contact link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContactType {
    Email,
    Phone,
}

impl ContactType {
    /// Returns the contact type as a lowercase string slice for DB storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            ContactType::Email => "email",
            ContactType::Phone => "phone",
        }
    }
}

impl fmt::Display for ContactType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A contact link extracted from an HTML document.
#[derive(Debug, Clone)]
pub struct ContactLink {
    pub contact_type: ContactType,
    /// The extracted value (email address or phone number).
    pub value: String,
    /// The original href attribute value.
    pub raw_href: String,
}

/// Extracts mailto and tel links from an HTML document.
///
/// Searches for anchor tags (`<a>`) with `href` attributes starting with
/// `mailto:` or `tel:` and extracts the contact information.
///
/// Deduplicates by (contact_type, value) — the same email/phone appearing
/// in multiple `<a>` tags is only returned once.
pub fn extract_contact_links(document: &Html) -> Vec<ContactLink> {
    let mut links = Vec::new();
    let mut seen: HashSet<(ContactType, String)> = HashSet::new();

    for element in document.select(&ANCHOR_SELECTOR) {
        if let Some(href) = element.value().attr("href") {
            let href_lower = href.to_lowercase();

            if let Some(rest) = href_lower.strip_prefix("mailto:") {
                // Strip query parameters (?subject=..., ?body=..., etc.)
                let value = rest.split('?').next().unwrap_or(rest).trim().to_string();
                if value.is_empty() {
                    continue;
                }
                let key = (ContactType::Email, value.clone());
                if seen.insert(key) {
                    links.push(ContactLink {
                        contact_type: ContactType::Email,
                        value,
                        raw_href: href.to_string(),
                    });
                }
            } else if let Some(rest) = href_lower.strip_prefix("tel:") {
                let value = rest.trim().to_string();
                if value.is_empty() {
                    continue;
                }
                let key = (ContactType::Phone, value.clone());
                if seen.insert(key) {
                    links.push(ContactLink {
                        contact_type: ContactType::Phone,
                        value,
                        raw_href: href.to_string(),
                    });
                }
            }
        }
    }

    links
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_mailto() {
        let html = Html::parse_document(
            r#"<html><body><a href="mailto:info@example.com">Contact us</a></body></html>"#,
        );
        let links = extract_contact_links(&html);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].contact_type, ContactType::Email);
        assert_eq!(links[0].value, "info@example.com");
        assert_eq!(links[0].raw_href, "mailto:info@example.com");
    }

    #[test]
    fn test_extract_tel() {
        let html = Html::parse_document(
            r#"<html><body><a href="tel:+1-800-555-1234">Call us</a></body></html>"#,
        );
        let links = extract_contact_links(&html);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].contact_type, ContactType::Phone);
        assert_eq!(links[0].value, "+1-800-555-1234");
    }

    #[test]
    fn test_extract_mailto_with_query_params() {
        let html = Html::parse_document(
            r#"<html><body><a href="mailto:info@example.com?subject=Hello&body=Hi">Email</a></body></html>"#,
        );
        let links = extract_contact_links(&html);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].value, "info@example.com");
    }

    #[test]
    fn test_extract_multiple_contacts() {
        let html = Html::parse_document(
            r#"<html><body>
                <a href="mailto:sales@example.com">Sales</a>
                <a href="mailto:support@example.com">Support</a>
                <a href="tel:+1-800-555-0001">Phone</a>
            </body></html>"#,
        );
        let links = extract_contact_links(&html);
        assert_eq!(links.len(), 3);
    }

    #[test]
    fn test_extract_deduplicates() {
        let html = Html::parse_document(
            r#"<html><body>
                <a href="mailto:info@example.com">Contact 1</a>
                <a href="mailto:info@example.com">Contact 2</a>
            </body></html>"#,
        );
        let links = extract_contact_links(&html);
        assert_eq!(links.len(), 1);
    }

    #[test]
    fn test_extract_empty_mailto() {
        let html = Html::parse_document(r#"<html><body><a href="mailto:">Empty</a></body></html>"#);
        let links = extract_contact_links(&html);
        assert_eq!(links.len(), 0);
    }

    #[test]
    fn test_extract_empty_tel() {
        let html = Html::parse_document(r#"<html><body><a href="tel:">Empty</a></body></html>"#);
        let links = extract_contact_links(&html);
        assert_eq!(links.len(), 0);
    }

    #[test]
    fn test_extract_no_contacts() {
        let html = Html::parse_document(
            r#"<html><body><a href="https://example.com">Regular link</a></body></html>"#,
        );
        let links = extract_contact_links(&html);
        assert_eq!(links.len(), 0);
    }

    #[test]
    fn test_extract_case_insensitive() {
        let html = Html::parse_document(
            r#"<html><body><a href="MAILTO:INFO@EXAMPLE.COM">Email</a></body></html>"#,
        );
        let links = extract_contact_links(&html);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].contact_type, ContactType::Email);
        // Value is lowercased because we lowercase the href
        assert_eq!(links[0].value, "info@example.com");
    }

    #[test]
    fn test_contact_type_as_str() {
        assert_eq!(ContactType::Email.as_str(), "email");
        assert_eq!(ContactType::Phone.as_str(), "phone");
    }

    #[test]
    fn test_contact_type_display() {
        assert_eq!(format!("{}", ContactType::Email), "email");
        assert_eq!(format!("{}", ContactType::Phone), "phone");
    }
}
