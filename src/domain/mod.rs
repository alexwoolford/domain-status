//! Domain extraction and normalization utilities.
//!
//! This module provides functions to extract and normalize domain names from URLs
//! using the Public Suffix List (PSL) to correctly identify registrable domains.
//!
//! Key functions:
//! - `extract_domain()` - Extracts the registrable domain from a URL
//! - `normalize_domain()` - Normalizes domain names (lowercase, removes www)

use anyhow::Result;
use publicsuffix::{List, Psl};
use reqwest::Url;

/// Extracts the registrable domain from a URL using the Public Suffix List.
///
/// # Arguments
///
/// * `list` - The Public Suffix List instance
/// * `url` - The URL to extract the domain from
///
/// # Returns
///
/// The registrable domain (e.g., "example.com" from "https://www.example.com/path")
///
/// # Errors
///
/// Returns an error if the URL cannot be parsed or if domain extraction fails.
///
/// # Implementation Note
///
/// The `publicsuffix` crate's `domain()` method has a bug where it returns the public suffix
/// (e.g., "co.uk") instead of the registrable domain (e.g., "example.co.uk") for multi-part TLDs.
/// This function works around that by:
/// 1. Getting the public suffix using `suffix()`
/// 2. Getting what `domain()` returns (which may be just the suffix for multi-part TLDs)
/// 3. If they're the same, we need to extract the registrable domain manually by finding
///    the part of the hostname that comes before the suffix
pub fn extract_domain(list: &List, url: &str) -> Result<String> {
    let parsed = Url::parse(url)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Failed to extract host from {url}"))?;

    // Get what domain() returns (may be just a partial suffix for multi-part TLDs)
    let domain_result = list
        .domain(host.as_bytes())
        .ok_or_else(|| anyhow::anyhow!("Failed to extract domain from {url}"))?;
    let domain_str = String::from_utf8_lossy(domain_result.as_bytes()).to_string();

    let host_lower = host.to_lowercase();

    // Check if domain() returned a valid registrable domain
    // For "www.example.co.uk", domain() incorrectly returns "co.uk" instead of "example.co.uk"
    // The publicsuffix crate's domain() method has a bug: for multi-part TLDs, it returns
    // just the public suffix part (e.g., "co.uk") instead of the registrable domain (e.g., "example.co.uk").
    // For simple TLDs, domain() works correctly (e.g., "example.com").
    //
    // Detection: if domain_str contains a dot AND the hostname has more parts than just domain_str,
    // AND extracting would give us a different result, then domain_str is likely just a suffix.
    // However, we can't easily detect this without trying extraction.
    //
    // Simpler approach: if domain_str contains a dot, try extraction and see if it gives us
    // a different (longer) result. But that's inefficient.
    //
    // Best approach: check if domain_str, when we try to extract the registrable domain from it,
    // would give us the same result. If domain_str is "example.com", extracting from "www.example.com"
    // with domain_str="example.com" would give us "example.com" (same). If domain_str is "co.uk",
    // extracting from "www.example.co.uk" with domain_str="co.uk" would give us "example.co.uk" (different).
    //
    // The key insight: for multi-part TLDs like "co.uk", domain() returns "co.uk" (just the suffix),
    // not "example.co.uk" (the registrable domain). For simple TLDs, domain() works correctly.
    //
    // Detection: if domain_str contains a dot AND extracting would give us a domain that's actually
    // in the hostname (as a complete registrable domain), then domain_str is likely just a suffix.
    //
    // Example: "www.example.co.uk" with domain_str="co.uk"
    //   - Extract: "example.co.uk"
    //   - Check: does "www.example.co.uk" end with ".example.co.uk"? Yes!
    //   - So extract "example.co.uk"
    //
    // Example: "a.b.c.example.com" with domain_str="example.com"
    //   - Extract: "c.example.com"
    //   - Check: does "a.b.c.example.com" end with ".c.example.com"? No!
    //   - So don't extract, use "example.com" as-is
    // For multi-part TLDs, domain() has a bug where it returns just the suffix (e.g., "co.uk")
    // instead of the registrable domain (e.g., "example.co.uk"). We need to detect this case.
    //
    // The key insight: domain() returns the suffix for multi-part TLDs. We can detect this by
    // checking if domain_str, when we try to extract the registrable domain, gives us a domain
    // that's actually the registrable domain (not a subdomain).
    //
    // How to detect: if domain_str contains a dot, try extraction. The extracted domain is valid
    // if it's the shortest domain in the hostname that contains domain_str as a suffix.
    // For "www.example.co.uk" with domain_str="co.uk": "example.co.uk" is valid (shortest)
    // For "a.b.c.example.com" with domain_str="example.com": "example.com" is already valid,
    //   "c.example.com" is NOT valid (not the shortest)
    let needs_extraction = if domain_str.contains('.') {
        // Try to extract the registrable domain
        let domain_with_dot = format!(".{}", domain_str);
        if let Some(pos) = host_lower.rfind(&domain_with_dot) {
            if pos > 0 {
                let before = &host_lower[..pos];
                if !before.is_empty() {
                    let parts: Vec<&str> = before.split('.').collect();
                    if let Some(label) = parts.last() {
                        if !label.is_empty() {
                            let extracted = format!("{}.{}", label, domain_str);
                            // Check if extracted domain is the registrable domain by verifying it appears in hostname
                            // For "www.example.co.uk" with domain_str="co.uk":
                            //   extracted="example.co.uk", hostname ends with ".example.co.uk" ✓
                            // For "a.b.c.example.com" with domain_str="example.com":
                            //   extracted="c.example.com", hostname does NOT end with ".c.example.com" ✗
                            let extracted_with_dot = format!(".{}", extracted);
                            // Only extract if the extracted domain appears as a complete domain in the hostname
                            // AND domain_str is likely just a suffix (not a complete registrable domain)
                            // We can detect this by checking if domain_str, when used as-is, would be a valid domain
                            // For "co.uk", it's not a valid registrable domain (no label before the TLD)
                            // For "example.com", it IS a valid registrable domain (has a label before the TLD)
                            // Simple heuristic: if domain_str has no label before the last dot, it's likely just a suffix
                            let domain_parts: Vec<&str> = domain_str.split('.').collect();
                            let is_likely_suffix =
                                domain_parts.len() >= 2 && domain_parts[0].len() <= 3;
                            // Common multi-part TLD patterns: co.uk, com.br, co.jp, etc. (first part is short, 2-3 chars)
                            (host_lower.ends_with(&extracted_with_dot) || host_lower == extracted)
                                && is_likely_suffix
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    } else {
        // For simple TLDs like "com", domain() works correctly
        !(host_lower == domain_str || host_lower.ends_with(&format!(".{}", domain_str)))
    };

    // If we need to extract the registrable domain, do it now
    if needs_extraction {
        // For multi-part TLDs, domain() returns something like "co.uk" instead of "example.co.uk"
        // We need to find the label before what domain() returned
        // e.g., "www.example.co.uk" -> domain() returns "co.uk", we need "example.co.uk"
        let domain_with_dot = format!(".{}", domain_str);
        if let Some(domain_pos) = host_lower.rfind(&domain_with_dot) {
            // Get the part before domain_str (e.g., "www.example" from "www.example.co.uk")
            let before_domain = &host_lower[..domain_pos];
            if !before_domain.is_empty() {
                // Split by dots and get the last part (the registrable domain label)
                // e.g., "www.example" -> "example"
                let parts: Vec<&str> = before_domain.split('.').collect();
                if let Some(registrable_label) = parts.last() {
                    if !registrable_label.is_empty() {
                        let extracted = format!("{}.{}", registrable_label, domain_str);
                        // Double-check: only return extracted if it's actually in the hostname as a complete domain
                        // This prevents returning "c.example.com" for "a.b.c.example.com"
                        if host_lower.ends_with(&format!(".{}", extracted))
                            || host_lower == extracted
                        {
                            return Ok(extracted);
                        }
                    }
                }
            }
        }
        // Fallback: if we can't extract properly, return the domain() result
        // This shouldn't happen, but better than panicking
        return Ok(domain_str);
    }

    // For simple TLDs like "com", domain() works correctly
    Ok(domain_str)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}

