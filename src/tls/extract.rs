//! Certificate extraction utilities.

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
/// A vector of OID strings.
pub(crate) fn extract_certificate_oids(
    cert: &x509_parser::certificate::X509Certificate<'_>,
) -> Vec<String> {
    let mut oids: Vec<String> = Vec::new();

    for ext in cert.extensions() {
        oids.push(ext.oid.to_string());

        match ext.parsed_extension() {
            ParsedExtension::CertificatePolicies(policies) => {
                oids.extend(policies.iter().map(|policy| policy.policy_id.to_string()));
            }
            ParsedExtension::ExtendedKeyUsage(eku) => {
                push_eku_oids(&mut oids, eku);
            }
            _ => {}
        }
    }

    oids
}

fn push_eku_oids(oids: &mut Vec<String>, eku: &x509_parser::extensions::ExtendedKeyUsage<'_>) {
    if eku.server_auth {
        oids.push("1.3.6.1.5.5.7.3.1".to_string());
    }
    if eku.client_auth {
        oids.push("1.3.6.1.5.5.7.3.2".to_string());
    }
    if eku.code_signing {
        oids.push("1.3.6.1.5.5.7.3.3".to_string());
    }
    if eku.email_protection {
        oids.push("1.3.6.1.5.5.7.3.4".to_string());
    }
    if eku.time_stamping {
        oids.push("1.3.6.1.5.5.7.3.8".to_string());
    }
    if eku.ocsp_signing {
        oids.push("1.3.6.1.5.5.7.3.9".to_string());
    }
    oids.extend(eku.other.iter().map(ToString::to_string));
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
) -> Vec<String> {
    let mut sans = Vec::new();

    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for general_name in &san.general_names {
                if let GeneralName::DNSName(dns_name) = general_name {
                    sans.push((*dns_name).to_string());
                }
            }
        }
    }

    sans
}

#[cfg(test)]
mod tests {
    use super::super::test_certs::{self, TestCertOptions};
    use super::*;
    use pretty_assertions::assert_eq;

    struct ParsedFixture {
        der: Vec<u8>,
    }

    impl ParsedFixture {
        fn new(options: TestCertOptions) -> Self {
            Self {
                der: test_certs::generate(options).der,
            }
        }

        fn cert(&self) -> x509_parser::certificate::X509Certificate<'_> {
            x509_parser::parse_x509_certificate(&self.der)
                .expect("parse generated certificate")
                .1
        }
    }

    #[test]
    fn test_extract_certificate_sans_ignores_ip_addresses() {
        let fixture = ParsedFixture::new(TestCertOptions::default());
        assert_eq!(
            extract_certificate_sans(&fixture.cert()),
            vec![
                "example.com".to_string(),
                "www.example.com".to_string(),
                "*.example.com".to_string(),
            ]
        );
    }

    #[test]
    fn test_extract_certificate_oids_includes_eku_policy_and_custom() {
        let fixture = ParsedFixture::new(TestCertOptions::default());
        let oids = extract_certificate_oids(&fixture.cert());
        assert!(oids.contains(&"2.5.29.17".to_string()));
        assert!(oids.contains(&"2.5.29.37".to_string()));
        assert!(oids.contains(&"2.5.29.32".to_string()));
        assert!(oids.contains(&"1.3.6.1.5.5.7.3.1".to_string()));
        assert!(oids.contains(&"1.3.6.1.5.5.7.3.2".to_string()));
        assert!(oids.contains(&test_certs::CUSTOM_EKU_OID.to_string()));
        assert!(oids.contains(&test_certs::DV_POLICY_OID.to_string()));
    }
}
