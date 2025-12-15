//! Security analysis functions.

use std::collections::HashMap;

use super::SecurityWarning;

/// Checks if a TLS version is considered weak (< TLS 1.2)
///
/// # Arguments
///
/// * `version` - TLS version string (e.g., "TLSv1.2", "TLSv1.3", "SSLv3")
///
/// # Returns
///
/// `true` if the TLS version is weak, `false` otherwise
pub(crate) fn is_weak_tls(version: &str) -> bool {
    // Normalize to lowercase and normalize separators (replace spaces/underscores with dots)
    let version_normalized = version
        .to_lowercase()
        .replace(' ', "")
        .replace('_', ".")
        .replace("tlsv", "tls");

    // TLS 1.3 and TLS 1.2 are considered secure
    // Check for various formats: "tlsv1.3", "tls1.3", "tls 1.3", "tlsv1_3", etc.
    // After normalization, these become: "tls1.3" or "tls1.2"
    if version_normalized.contains("tls1.3") || version_normalized == "tls1.3" {
        return false;
    }
    if version_normalized.contains("tls1.2") || version_normalized == "tls1.2" {
        return false;
    }

    // Everything else (TLS 1.1, TLS 1.0, SSLv3, SSLv2) is considered weak
    true
}

/// Analyzes collected data and returns a list of security warnings
///
/// # Arguments
///
/// * `final_url` - The final URL after redirects (to check if HTTPS)
/// * `tls_version` - TLS version used (if HTTPS)
/// * `security_headers` - Map of security headers found
/// * `cert_subject` - Certificate subject (if HTTPS)
/// * `cert_issuer` - Certificate issuer (if HTTPS)
/// * `cert_valid_to` - Certificate expiration date (if HTTPS)
/// * `cert_sans` - Certificate Subject Alternative Names (if HTTPS)
///
/// # Returns
///
/// A vector of security warnings found
pub fn analyze_security(
    final_url: &str,
    tls_version: &Option<String>,
    security_headers: &HashMap<String, String>,
    cert_subject: &Option<String>,
    cert_issuer: &Option<String>,
    cert_valid_to: &Option<chrono::NaiveDateTime>,
    _cert_sans: &Option<Vec<String>>,
) -> Vec<SecurityWarning> {
    let mut warnings = Vec::new();

    // Check if site uses HTTP (no HTTPS)
    if !final_url.starts_with("https://") {
        warnings.push(SecurityWarning::NoHttps);
        // If no HTTPS, we can't check TLS version, so return early
        return warnings;
    }

    // Check TLS version (only if HTTPS)
    if let Some(version) = tls_version {
        if is_weak_tls(version) {
            warnings.push(SecurityWarning::WeakTls);
        }
    }

    // Check for missing security headers (case-insensitive)
    // Headers are stored with their original case, so we need to check case-insensitively
    let has_hsts = security_headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case("strict-transport-security"));
    if !has_hsts {
        warnings.push(SecurityWarning::MissingHsts);
    }

    let has_csp = security_headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case("content-security-policy"));
    if !has_csp {
        warnings.push(SecurityWarning::MissingCsp);
    }

    let has_content_type_options = security_headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case("x-content-type-options"));
    if !has_content_type_options {
        warnings.push(SecurityWarning::MissingContentTypeOptions);
    }

    let has_frame_options = security_headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case("x-frame-options"));
    if !has_frame_options {
        warnings.push(SecurityWarning::MissingFrameOptions);
    }

    // Check certificate validity
    // Since we always allow invalid certificates to maximize data capture,
    // we need to validate the certificate ourselves and record issues
    if let (Some(subject), Some(issuer), Some(valid_to)) =
        (cert_subject, cert_issuer, cert_valid_to)
    {
        let now = chrono::Utc::now().naive_utc();

        // Check if certificate is expired
        let is_expired = *valid_to < now;

        // Check if certificate is self-signed (subject == issuer)
        // X.509 DNs from x509-parser are normalized, so direct string comparison should work
        // However, we normalize by trimming whitespace and comparing case-insensitively
        // to handle any edge cases
        let is_self_signed = subject.trim().eq_ignore_ascii_case(issuer.trim());

        if is_expired || is_self_signed {
            warnings.push(SecurityWarning::InvalidCertificate);
        }
        // Note: Hostname mismatch detection is complex and would require
        // parsing the certificate subject and SANs, which is handled by
        // the TLS library. Since we're accepting all certs, we can't easily
        // detect hostname mismatches without re-implementing the validation logic.
        // For now, we detect expired and self-signed certificates.
    } else if final_url.starts_with("https://") {
        // If we have HTTPS but no certificate info, it indicates
        // a certificate extraction failure. This could mean:
        // - The certificate was so broken we couldn't parse it
        // - TLS handshake failed completely
        // - Network/connection issues
        // This is a security concern (can't verify the certificate) and should be recorded
        warnings.push(SecurityWarning::InvalidCertificate);
    }

    warnings
}
