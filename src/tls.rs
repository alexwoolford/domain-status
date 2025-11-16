use anyhow::Result;
use chrono::NaiveDateTime;
use log::{error, info};
use rustls::pki_types::ServerName;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use x509_parser::extensions::ParsedExtension;

use crate::models::CertificateInfo;

/// Serializes a value to JSON string.
///
/// Note: JSON object key order is not guaranteed by the JSON spec, but serde_json
/// typically preserves insertion order for HashMap. If deterministic key ordering
/// is required, use BTreeMap in the source data structure instead.
fn serialize_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())
}

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
fn extract_certificate_oids(
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

/// Retrieves SSL/TLS certificate information for a domain.
///
/// This function establishes a TLS connection to the domain and extracts
/// certificate details including version, subject, issuer, validity period, and OIDs.
/// OIDs are extracted from Certificate Policies, Extended Key Usage, and other extensions.
///
/// # Arguments
///
/// * `domain` - The domain name to connect to (e.g., "example.com")
///
/// # Returns
///
/// Certificate information including TLS version, subject, issuer, validity dates, and OIDs.
///
/// # Errors
///
/// Returns an error if:
/// - The domain name is invalid
/// - TCP connection fails
/// - TLS handshake fails
/// - Certificate parsing fails
pub async fn get_ssl_certificate_info(domain: String) -> Result<CertificateInfo> {
    log::debug!("Attempting to get SSL info for domain: {domain}");

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    log::info!("Attempting to resolve server name for domain: {domain}");
    let server_name = match ServerName::try_from(domain.clone()) {
        Ok(name) => name,
        Err(e) => {
            error!("Invalid domain name: {e}");
            return Err(anyhow::anyhow!("Invalid domain name: {}", e));
        }
    };

    log::info!("Attempting to connect to domain: {domain}");
    let sock = match tokio::time::timeout(
        std::time::Duration::from_secs(crate::config::TCP_CONNECT_TIMEOUT_SECS),
        TcpStream::connect((domain.clone(), 443)),
    )
    .await
    {
        Ok(Ok(sock)) => sock,
        Ok(Err(e)) => {
            error!("Failed to connect to {domain}:443 - {e}");
            return Err(anyhow::anyhow!("Failed to connect to {}:443", domain));
        }
        Err(_) => {
            error!("TCP connection timeout for {domain}:443");
            return Err(anyhow::anyhow!(
                "TCP connection timeout for {}:443 ({}s)",
                domain,
                crate::config::TCP_CONNECT_TIMEOUT_SECS
            ));
        }
    };

    let connector = TlsConnector::from(Arc::new(config));
    let mut tls_stream = match tokio::time::timeout(
        std::time::Duration::from_secs(crate::config::TLS_HANDSHAKE_TIMEOUT_SECS),
        connector.connect(server_name, sock),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            error!("TLS connection failed for {domain}: {e}");
            return Err(anyhow::anyhow!("TLS connection failed for {}", domain));
        }
        Err(_) => {
            error!("TLS handshake timeout for {domain}");
            return Err(anyhow::anyhow!(
                "TLS handshake timeout for {} ({}s)",
                domain,
                crate::config::TLS_HANDSHAKE_TIMEOUT_SECS
            ));
        }
    };

    log::info!("Extracting TLS version for domain: {domain}");
    let tls_version = tls_stream
        .get_ref()
        .1
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "Unknown".to_string());

    // Extract negotiated cipher suite
    let cipher_suite = tls_stream
        .get_ref()
        .1
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()));

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {domain}\r\n\
         Connection: close\r\n\
         Accept-Encoding: identity\r\n\
         \r\n",
    );

    if let Err(e) = tls_stream.write_all(request.as_bytes()).await {
        error!("Failed to write request to {domain}: {e}");
        return Err(anyhow::anyhow!("Failed to write request to {}", domain));
    }

    if let Some(certs) = tls_stream.get_ref().1.peer_certificates() {
        if let Some(cert) = certs.first() {
            let (_, cert) = x509_parser::parse_x509_certificate(cert.as_ref())?;
            let tbs_cert = &cert.tbs_certificate;

            let subject = cert.tbs_certificate.subject.to_string();
            let issuer = cert.tbs_certificate.issuer.to_string();

            // Extract public key algorithm from certificate
            let key_algorithm = {
                let oid_str = tbs_cert.subject_pki.algorithm.algorithm.to_string();
                // Map OID to algorithm name
                if oid_str.contains("1.2.840.113549.1.1.1") {
                    "RSA".to_string()
                } else if oid_str.contains("1.2.840.10045.2.1") {
                    "ECDSA".to_string()
                } else if oid_str.contains("1.3.101.112") {
                    "Ed25519".to_string()
                } else if oid_str.contains("1.3.101.113") {
                    "Ed448".to_string()
                } else {
                    // Return OID if unknown
                    oid_str
                }
            };

            let oids = extract_certificate_oids(&cert).unwrap_or_else(|_| Vec::new());
            let unique_oids: HashSet<String> = oids.into_iter().collect();
            let serialized_oids = serialize_json(&unique_oids);

            log::info!("Extracting validity period for domain: {domain}");
            let valid_from_str =
                tbs_cert.validity.not_before.to_rfc2822().map_err(|e| {
                    anyhow::anyhow!("RFC2822 conversion error for not_before: {}", e)
                })?;
            let valid_from =
                NaiveDateTime::parse_from_str(&valid_from_str, "%a, %d %b %Y %H:%M:%S %z")
                    .map_err(|_| anyhow::anyhow!("Failed to parse not_before"))?;

            let valid_to_str =
                tbs_cert.validity.not_after.to_rfc2822().map_err(|e| {
                    anyhow::anyhow!("RFC2822 conversion error for not_after: {}", e)
                })?;
            let valid_to = NaiveDateTime::parse_from_str(&valid_to_str, "%a, %d %b %Y %H:%M:%S %z")
                .map_err(|_| anyhow::anyhow!("Failed to parse not_after"))?;

            info!("SSL certificate info extracted for domain: {domain}");

            return Ok(CertificateInfo {
                tls_version: Some(tls_version),
                subject: Some(subject),
                issuer: Some(issuer),
                valid_from: Some(valid_from),
                valid_to: Some(valid_to),
                oids: Some(serialized_oids),
                cipher_suite,
                key_algorithm: Some(key_algorithm),
            });
        }
    }

    Err(anyhow::anyhow!(
        "Failed to retrieve certificate information for {}",
        domain
    ))
}
