//! Certificate extraction utilities.

use anyhow::Result;
use x509_parser::extensions::{GeneralName, ParsedExtension};

/// Extracts all relevant OIDs from an X.509 certificate.
///
/// This function extracts OIDs from multiple certificate extensions:
/// - Certificate Policies (validation levels: DV, OV, EV)
/// - Extended Key Usage (key purposes: server auth, client auth, etc.)
/// - Extension OIDs themselves (identifiers for each extension)
///
/// # Arguments
///
/// * `cert` - The parsed X.509 certificate
///
/// # Returns
///
/// A vector of OID strings, or an error if parsing fails.
pub(crate) fn extract_certificate_oids(
    cert: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<Vec<String>> {
    let mut oids: Vec<String> = Vec::new();

    for ext in cert.extensions() {
        // Extract the extension OID itself (e.g., 2.5.29.32 for Certificate Policies)
        let ext_oid = ext.oid.to_string();
        oids.push(ext_oid.clone());

        // Extract OIDs from specific extension types
        match ext.parsed_extension() {
            // Certificate Policies Extension (OID: 2.5.29.32)
            // Contains policy OIDs like 2.23.140.1.1 (EV), 2.23.140.1.2.1 (DV), etc.
            ParsedExtension::CertificatePolicies(ref policies) => {
                oids.extend(policies.iter().map(|policy| policy.policy_id.to_string()));
            }

            // Extended Key Usage Extension (OID: 2.5.29.37)
            // Contains purpose OIDs like 1.3.6.1.5.5.7.3.1 (serverAuth), etc.
            ParsedExtension::ExtendedKeyUsage(ref eku) => {
                // ExtendedKeyUsage has boolean fields for each purpose
                // Map each enabled purpose to its corresponding OID
                if eku.server_auth {
                    oids.push("1.3.6.1.5.5.7.3.1".to_string()); // Server Authentication
                }
                if eku.client_auth {
                    oids.push("1.3.6.1.5.5.7.3.2".to_string()); // Client Authentication
                }
                if eku.code_signing {
                    oids.push("1.3.6.1.5.5.7.3.3".to_string()); // Code Signing
                }
                if eku.email_protection {
                    oids.push("1.3.6.1.5.5.7.3.4".to_string()); // Email Protection
                }
                if eku.time_stamping {
                    oids.push("1.3.6.1.5.5.7.3.8".to_string()); // Time Stamping
                }
                if eku.ocsp_signing {
                    oids.push("1.3.6.1.5.5.7.3.9".to_string()); // OCSP Signing
                }
                // Note: The 'any' field is a boolean flag, not a vector of OIDs.
                // Custom OIDs in Extended Key Usage would be in the extension itself,
                // which we've already captured via the extension OID (2.5.29.37).
            }

            // Key Usage Extension (OID: 2.5.29.15)
            // This is a bitmask, not OIDs, but we've already captured the extension OID above
            // No additional OIDs to extract here

            // Subject Alternative Name (OID: 2.5.29.17)
            // Contains names, not OIDs, but we've already captured the extension OID above
            // Note: SANs are extracted separately in extract_certificate_sans()

            // Authority Key Identifier (OID: 2.5.29.35)
            // Contains key identifiers, not OIDs, but we've already captured the extension OID above

            // Subject Key Identifier (OID: 2.5.29.14)
            // Contains key identifiers, not OIDs, but we've already captured the extension OID above

            // Other extensions - we've already captured the extension OID above
            _ => {
                // Extension OID already added above
            }
        }
    }

    Ok(oids)
}

/// Extracts Subject Alternative Names (SANs) from an X.509 certificate.
///
/// This function extracts DNS names from the Subject Alternative Name extension.
/// Only DNS names are extracted (not IP addresses, email addresses, etc.) as they
/// are the most useful for linking domains in graph analysis.
///
/// # Arguments
///
/// * `cert` - The parsed X.509 certificate
///
/// # Returns
///
/// A vector of DNS domain names found in the SAN extension.
pub(crate) fn extract_certificate_sans(
    cert: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<Vec<String>> {
    let mut sans = Vec::new();

    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(ref san) = ext.parsed_extension() {
            for general_name in &san.general_names {
                // We only extract DNS names for graph analysis
                // Other types (IPAddress, RFC822Name, etc.) are ignored
                if let GeneralName::DNSName(dns_name) = general_name {
                    // DNSName is already a &str in x509-parser
                    sans.push(dns_name.to_string());
                }
            }
        }
    }

    Ok(sans)
}

