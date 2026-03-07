//! TLS/SSL certificate information extraction.
//!
//! This module connects to HTTPS endpoints and extracts certificate details:
//! - Certificate subject and issuer
//! - Validity period (not before/after dates)
//! - Subject Alternative Names (SANs)
//! - Certificate OIDs (policies, extended key usage, extensions)
//! - Cipher suite and key algorithm
//! - TLS version
//!
//! Uses `tokio-rustls` for async TLS connections and `x509-parser` for certificate parsing.

mod extract;

use anyhow::Result;
use chrono::NaiveDateTime;
use log::error;
use rustls::pki_types::{CertificateDer, ServerName};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;

use crate::models::CertificateInfo;

use extract::{extract_certificate_oids, extract_certificate_sans};

/// A certificate verifier that always accepts certificates.
/// This allows us to extract certificate information even from invalid certificates,
/// and we'll record certificate issues as security warnings.
#[derive(Debug)]
struct AcceptAllVerifier;

impl rustls::client::danger::ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Always accept - we'll validate and record issues ourselves
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Return all supported schemes
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

async fn resolve_public_tls_addr(domain: &str) -> Result<SocketAddr> {
    crate::security::validate_url_safe(&format!("https://{domain}/"))?;

    let mut addrs = tokio::net::lookup_host((domain, 443))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to resolve {}: {}", domain, e))?;

    addrs
        .find(|addr| crate::security::safe_resolver::is_public_ip(addr.ip()))
        .ok_or_else(|| anyhow::anyhow!("No public IP addresses resolved for {}", domain))
}

fn parse_certificate_info_from_der(
    cert_der: &[u8],
    tls_version: crate::models::TlsVersion,
    cipher_suite: Option<String>,
) -> Result<CertificateInfo> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)?;
    let tbs_cert = &cert.tbs_certificate;
    let subject = cert.tbs_certificate.subject.to_string();
    let issuer = cert.tbs_certificate.issuer.to_string();
    let key_algorithm = {
        let oid_str = tbs_cert.subject_pki.algorithm.algorithm.to_string();
        crate::models::KeyAlgorithm::from_oid(&oid_str)
    };
    let unique_oids: HashSet<String> = extract_certificate_oids(&cert).into_iter().collect();
    let sans = extract_certificate_sans(&cert);

    let valid_from_str = tbs_cert
        .validity
        .not_before
        .to_rfc2822()
        .map_err(|e| anyhow::anyhow!("RFC2822 conversion error for not_before: {}", e))?;
    let valid_from = NaiveDateTime::parse_from_str(&valid_from_str, "%a, %d %b %Y %H:%M:%S %z")
        .map_err(|_| anyhow::anyhow!("Failed to parse not_before"))?;

    let valid_to_str = tbs_cert
        .validity
        .not_after
        .to_rfc2822()
        .map_err(|e| anyhow::anyhow!("RFC2822 conversion error for not_after: {}", e))?;
    let valid_to = NaiveDateTime::parse_from_str(&valid_to_str, "%a, %d %b %Y %H:%M:%S %z")
        .map_err(|_| anyhow::anyhow!("Failed to parse not_after"))?;

    Ok(CertificateInfo {
        tls_version: Some(tls_version),
        subject: Some(subject),
        issuer: Some(issuer),
        valid_from: Some(valid_from),
        valid_to: Some(valid_to),
        oids: Some(unique_oids),
        cipher_suite,
        key_algorithm: Some(key_algorithm),
        subject_alternative_names: if sans.is_empty() { None } else { Some(sans) },
    })
}

/// Retrieves SSL/TLS certificate information for a domain.
///
/// This function establishes a **separate** TLS connection to the domain and extracts
/// certificate details including version, subject, issuer, validity period, and OIDs.
/// OIDs are extracted from Certificate Policies, Extended Key Usage, and other extensions.
///
/// **Known inefficiency:** This opens a second TCP+TLS connection per HTTPS URL,
/// independent of the reqwest connection used for the HTTP request. Eliminating this
/// duplication requires injecting a certificate-capturing `ServerCertVerifier` into
/// reqwest's `ClientBuilder::use_preconfigured_tls()` and sharing the captured cert
/// data via a concurrent map keyed by host. This is a non-trivial refactoring tracked
/// as a future optimization.
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
// Large function handling comprehensive TLS certificate extraction with connection setup and certificate parsing.
// Consider refactoring into smaller focused functions in Phase 4.
#[allow(clippy::too_many_lines)]
pub async fn get_ssl_certificate_info(domain: String) -> Result<CertificateInfo> {
    log::debug!("Attempting to get SSL info for domain: {domain}");

    // Diagnostic certificate capture still accepts invalid certificates so we can
    // inspect misconfigured endpoints separately from the main HTTP transport.
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
        .with_no_client_auth();

    log::debug!("Attempting to resolve server name for domain: {domain}");
    // Note: ServerName::try_from requires 'static lifetime, so we must clone or pass String
    // The clone is necessary because we need domain for error messages later
    let server_name = match ServerName::try_from(domain.clone()) {
        Ok(name) => name,
        Err(e) => {
            error!("Invalid domain name: {e}");
            return Err(anyhow::anyhow!("Invalid domain name: {}", e));
        }
    };

    log::debug!("Attempting to connect to domain: {domain}");
    let socket_addr = resolve_public_tls_addr(&domain).await?;
    let sock = match tokio::time::timeout(
        std::time::Duration::from_secs(crate::config::TCP_CONNECT_TIMEOUT_SECS),
        TcpStream::connect(socket_addr),
    )
    .await
    {
        Ok(Ok(sock)) => sock,
        Ok(Err(e)) => {
            error!("Failed to connect to {domain} ({socket_addr}) - {e}");
            return Err(anyhow::anyhow!(
                "Failed to connect to {} via {}",
                domain,
                socket_addr
            ));
        }
        Err(_) => {
            error!("TCP connection timeout for {domain} via {socket_addr}");
            return Err(anyhow::anyhow!(
                "TCP connection timeout for {} via {} ({}s)",
                domain,
                socket_addr,
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

    log::debug!("Extracting TLS version for domain: {domain}");
    let tls_version = {
        use rustls::ProtocolVersion;
        tls_stream
            .get_ref()
            .1
            .protocol_version()
            .map(|v| match v {
                ProtocolVersion::TLSv1_0 => crate::models::TlsVersion::Tls10,
                ProtocolVersion::TLSv1_1 => crate::models::TlsVersion::Tls11,
                ProtocolVersion::TLSv1_2 => crate::models::TlsVersion::Tls12,
                ProtocolVersion::TLSv1_3 => crate::models::TlsVersion::Tls13,
                ProtocolVersion::SSLv2 | ProtocolVersion::SSLv3 => crate::models::TlsVersion::Ssl30,
                _ => crate::models::TlsVersion::Unknown,
            })
            .unwrap_or(crate::models::TlsVersion::Unknown)
    };

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
            let parsed = parse_certificate_info_from_der(cert.as_ref(), tls_version, cipher_suite)?;
            log::debug!("SSL certificate info extracted for domain: {domain}");
            return Ok(parsed);
        }
    }

    Err(anyhow::anyhow!(
        "Failed to retrieve certificate information for {}",
        domain
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    };

    fn init_crypto_for_test() {
        // Initialize crypto provider for TLS tests
        crate::initialization::init_crypto_provider();
    }

    #[tokio::test]
    #[ignore] // Requires network access - run with `cargo test -- --ignored`
    async fn test_get_ssl_certificate_info_valid_domain() {
        init_crypto_for_test();
        // Test with a well-known domain that should have a valid certificate
        let result = get_ssl_certificate_info("example.com".to_string()).await;
        // This may succeed or fail depending on network, but should not panic
        match result {
            Ok(cert_info) => {
                // If successful, verify we got some certificate data
                assert!(cert_info.subject.is_some() || cert_info.issuer.is_some());
            }
            Err(_e) => {
                // Network errors are acceptable in tests - just verify it's an error
                // Don't check error message as it may vary
            }
        }
    }

    #[tokio::test]
    async fn test_get_ssl_certificate_info_invalid_domain() {
        init_crypto_for_test();
        // Test with an invalid domain name
        let result = get_ssl_certificate_info("".to_string()).await;
        match result {
            Ok(_) => panic!("Expected error for invalid domain"),
            Err(e) => {
                let error_msg = e.to_string();
                assert!(
                    error_msg.contains("Invalid domain name") || error_msg.contains("invalid"),
                    "Expected invalid domain error, got: {}",
                    error_msg
                );
            }
        }
    }

    #[tokio::test]
    async fn test_get_ssl_certificate_info_invalid_domain_format() {
        init_crypto_for_test();
        // Test with various invalid domain formats
        let invalid_domains = vec![
            "..",               // Invalid format
            "domain..com",      // Double dots
            "domain@invalid",   // Invalid character
            "domain space.com", // Space in domain
        ];

        for domain in invalid_domains {
            let result = get_ssl_certificate_info(domain.to_string()).await;
            // Should fail at domain validation or connection
            assert!(
                result.is_err(),
                "Expected error for invalid domain: {}",
                domain
            );
        }
    }

    #[tokio::test]
    async fn test_get_ssl_certificate_info_connection_refused() {
        init_crypto_for_test();
        // Use a port that's guaranteed to be closed (connection refused)
        // Port 1 is typically reserved and closed
        let result = get_ssl_certificate_info("127.0.0.1".to_string()).await;
        // Should fail with connection error or timeout
        match result {
            Ok(_) => panic!("Expected error for connection refused"),
            Err(e) => {
                let error_msg = e.to_string();
                assert!(
                    error_msg.contains("Failed to connect")
                        || error_msg.contains("connection")
                        || error_msg.contains("timeout")
                        || error_msg.contains("refused"),
                    "Expected connection error, got: {}",
                    error_msg
                );
            }
        }
    }

    #[tokio::test]
    async fn test_get_ssl_certificate_info_nonexistent_domain_dns() {
        init_crypto_for_test();
        // Test with a domain that definitely doesn't exist (DNS failure)
        let result = get_ssl_certificate_info(
            "this-domain-definitely-does-not-exist-12345.invalid".to_string(),
        )
        .await;
        // Should fail with DNS or connection error
        match result {
            Ok(_) => panic!("Expected error for nonexistent domain"),
            Err(e) => {
                let error_msg = e.to_string();
                assert!(
                    error_msg.contains("Failed to connect")
                        || error_msg.contains("connection")
                        || error_msg.contains("timeout")
                        || error_msg.contains("Invalid domain name"),
                    "Expected DNS/connection error, got: {}",
                    error_msg
                );
            }
        }
    }

    #[tokio::test]
    async fn test_get_ssl_certificate_info_tcp_timeout() {
        init_crypto_for_test();
        // Test with a domain that will timeout (using a non-routable IP)
        // 192.0.2.0/24 is reserved for documentation (TEST-NET-1)
        // It should timeout rather than fail immediately
        let result = get_ssl_certificate_info("192.0.2.1".to_string()).await;
        // Should fail with timeout or connection error
        match result {
            Ok(_) => panic!("Expected error for timeout scenario"),
            Err(e) => {
                let error_msg = e.to_string();
                assert!(
                    error_msg.contains("timeout")
                        || error_msg.contains("Failed to connect")
                        || error_msg.contains("connection"),
                    "Expected timeout or connection error, got: {}",
                    error_msg
                );
            }
        }
    }

    fn test_certificate_der() -> Vec<u8> {
        let mut params = CertificateParams::new(vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
        ])
        .expect("certificate params");
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "example.com");
        params.distinguished_name = distinguished_name;
        params.is_ca = IsCa::ExplicitNoCa;
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params
            .self_signed(&KeyPair::generate().expect("key pair"))
            .expect("certificate")
            .der()
            .to_vec()
    }

    #[test]
    fn test_parse_certificate_info_from_der_extracts_contract() {
        let parsed = parse_certificate_info_from_der(
            &test_certificate_der(),
            crate::models::TlsVersion::Tls13,
            Some("TLS13_AES_256_GCM_SHA384".to_string()),
        )
        .expect("parse certificate");

        assert_eq!(parsed.tls_version, Some(crate::models::TlsVersion::Tls13));
        assert_eq!(
            parsed.subject_alternative_names,
            Some(vec![
                "example.com".to_string(),
                "www.example.com".to_string()
            ])
        );
        assert_eq!(
            parsed.cipher_suite.as_deref(),
            Some("TLS13_AES_256_GCM_SHA384")
        );
        assert!(parsed
            .subject
            .as_deref()
            .is_some_and(|subject| subject.contains("example.com")));
        assert!(parsed
            .issuer
            .as_deref()
            .is_some_and(|issuer| issuer.contains("example.com")));
        assert!(parsed.valid_from.is_some());
        assert!(parsed.valid_to.is_some());
        assert!(parsed
            .oids
            .as_ref()
            .is_some_and(|oids| oids.contains("2.5.29.17")));
        assert!(matches!(
            parsed.key_algorithm,
            Some(crate::models::KeyAlgorithm::ECDSA | crate::models::KeyAlgorithm::Ed25519)
        ));
    }

    #[test]
    fn test_parse_certificate_info_from_der_rejects_invalid_der() {
        let error = parse_certificate_info_from_der(
            b"not-a-certificate",
            crate::models::TlsVersion::Tls12,
            None,
        )
        .expect_err("invalid DER should fail");
        assert!(error.to_string().contains("Parsing Error"));
    }
}
