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
use hickory_resolver::TokioResolver;
use log::error;
use rustls::pki_types::{CertificateDer, ServerName};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
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

/// Resolves all public (non-private, non-loopback, non-link-local) IP addresses for
/// `domain`, ordered with IPv4 addresses first.
///
/// IPv4-first ordering approximates Happy Eyeballs behavior for this diagnostic
/// side-channel: when IPv6 egress is broken (a common misconfiguration), trying IPv4
/// first avoids wasting the connect timeout on an address family that can't route.
async fn resolve_public_tls_addrs(
    domain: &str,
    resolver: &TokioResolver,
) -> Result<Vec<SocketAddr>> {
    crate::security::validate_url_safe(&format!("https://{domain}/"))?;

    let response = resolver
        .lookup_ip(domain)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to resolve {domain}: {e}"))?;

    let addrs = order_public_addrs_ipv4_first(
        response
            .iter()
            .filter(|ip| crate::security::safe_resolver::is_public_ip(*ip)),
    );

    if addrs.is_empty() {
        return Err(anyhow::anyhow!(
            "No public IP addresses resolved for {domain}"
        ));
    }

    Ok(addrs
        .into_iter()
        .map(|ip| SocketAddr::new(ip, 443))
        .collect())
}

/// Orders an iterator of IP addresses with all IPv4 addresses before IPv6 addresses,
/// preserving relative order within each family (the resolver's original preference).
fn order_public_addrs_ipv4_first(
    ips: impl Iterator<Item = std::net::IpAddr>,
) -> Vec<std::net::IpAddr> {
    let (mut v4, v6): (Vec<_>, Vec<_>) = ips.partition(std::net::IpAddr::is_ipv4);
    v4.extend(v6);
    v4
}

/// Attempts a TCP connect to each candidate address in order, returning the first
/// successful connection. Each attempt is bounded by the standard TCP connect timeout.
/// If every attempt fails, returns an error listing all attempted addresses.
async fn connect_tls_tcp(domain: &str, addrs: &[SocketAddr]) -> Result<(TcpStream, SocketAddr)> {
    let mut last_errors: Vec<String> = Vec::with_capacity(addrs.len());

    for &socket_addr in addrs {
        match tokio::time::timeout(
            std::time::Duration::from_secs(crate::config::TCP_CONNECT_TIMEOUT_SECS),
            TcpStream::connect(socket_addr),
        )
        .await
        {
            Ok(Ok(sock)) => return Ok((sock, socket_addr)),
            Ok(Err(e)) => {
                error!("Failed to connect to {domain} ({socket_addr}) - {e}");
                last_errors.push(format!("{socket_addr} ({e})"));
            }
            Err(_) => {
                error!("TCP connection timeout for {domain} via {socket_addr}");
                last_errors.push(format!("{socket_addr} (timeout)"));
            }
        }
    }

    Err(anyhow::anyhow!(
        "Failed to connect to {domain} via any of: {}",
        last_errors.join(", ")
    ))
}

fn parse_certificate_info_from_der(
    cert_der: &[u8],
    tls_version: crate::models::TlsVersion,
    cipher_suite: Option<String>,
) -> Result<CertificateInfo> {
    // Compute SHA-256 fingerprint of the raw DER certificate
    let fingerprint_sha256 = {
        let hash = Sha256::digest(cert_der);
        Some(format!("{hash:x}"))
    };

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

    // Cert intelligence: serial, self-signed, wildcard
    let serial_number = Some(tbs_cert.raw_serial_as_string());
    let is_self_signed = Some(subject == issuer);
    let is_wildcard = Some(sans.iter().any(|san| san.starts_with("*.")));

    let valid_from_str = tbs_cert
        .validity
        .not_before
        .to_rfc2822()
        .map_err(|e| anyhow::anyhow!("RFC2822 conversion error for not_before: {e}"))?;
    let valid_from = NaiveDateTime::parse_from_str(&valid_from_str, "%a, %d %b %Y %H:%M:%S %z")
        .map_err(|_| anyhow::anyhow!("Failed to parse not_before"))?;

    let valid_to_str = tbs_cert
        .validity
        .not_after
        .to_rfc2822()
        .map_err(|e| anyhow::anyhow!("RFC2822 conversion error for not_after: {e}"))?;
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
        fingerprint_sha256,
        serial_number,
        is_self_signed,
        is_wildcard,
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
/// * `resolver` - DNS resolver (hickory with configured timeout); avoids bypassing timeout via system DNS
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
#[allow(clippy::too_many_lines)] // Sequential TLS handshake + certificate field extraction; splitting would obscure the flow
pub async fn get_ssl_certificate_info(
    domain: String,
    resolver: &TokioResolver,
) -> Result<CertificateInfo> {
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
            return Err(anyhow::anyhow!("Invalid domain name: {e}"));
        }
    };

    log::debug!("Attempting to connect to domain: {domain}");
    let socket_addrs = resolve_public_tls_addrs(&domain, resolver).await?;
    let (sock, socket_addr) = connect_tls_tcp(&domain, &socket_addrs).await?;
    log::debug!("Connected to {domain} via {socket_addr}");

    let connector = TlsConnector::from(Arc::new(config));
    let tls_stream = match tokio::time::timeout(
        std::time::Duration::from_secs(crate::config::TLS_HANDSHAKE_TIMEOUT_SECS),
        connector.connect(server_name, sock),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            error!("TLS connection failed for {domain}: {e}");
            return Err(anyhow::anyhow!("TLS connection failed for {domain}"));
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
            .map_or(crate::models::TlsVersion::Unknown, |v| match v {
                ProtocolVersion::TLSv1_0 => crate::models::TlsVersion::Tls10,
                ProtocolVersion::TLSv1_1 => crate::models::TlsVersion::Tls11,
                ProtocolVersion::TLSv1_2 => crate::models::TlsVersion::Tls12,
                ProtocolVersion::TLSv1_3 => crate::models::TlsVersion::Tls13,
                ProtocolVersion::SSLv2 | ProtocolVersion::SSLv3 => crate::models::TlsVersion::Ssl30,
                _ => crate::models::TlsVersion::Unknown,
            })
    };

    // Extract negotiated cipher suite
    let cipher_suite = tls_stream
        .get_ref()
        .1
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()));

    // Certificates are available immediately after handshake; no HTTP request needed.
    // (Removing the GET request also eliminates unbounded TCP write hang risk.)
    if let Some(certs) = tls_stream.get_ref().1.peer_certificates() {
        if let Some(cert) = certs.first() {
            let parsed = parse_certificate_info_from_der(cert.as_ref(), tls_version, cipher_suite)?;
            log::debug!("SSL certificate info extracted for domain: {domain}");
            return Ok(parsed);
        }
    }

    Err(anyhow::anyhow!(
        "Failed to retrieve certificate information for {domain}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::initialization::test_resolver;
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
        let resolver = test_resolver();
        // Test with a well-known domain that should have a valid certificate
        let result = get_ssl_certificate_info("example.com".to_string(), resolver.as_ref()).await;
        let cert_info = result.unwrap_or_else(|e| {
            panic!("ignored live TLS test must handshake example.com, got {e}")
        });
        assert!(
            cert_info.subject.is_some() || cert_info.issuer.is_some(),
            "certificate should include subject or issuer"
        );
    }

    #[tokio::test]
    async fn test_get_ssl_certificate_info_invalid_domain() {
        init_crypto_for_test();
        let resolver = test_resolver();
        // Test with an invalid domain name
        let result = get_ssl_certificate_info("".to_string(), resolver.as_ref()).await;
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

        let resolver = test_resolver();
        for domain in invalid_domains {
            let result = get_ssl_certificate_info(domain.to_string(), resolver.as_ref()).await;
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
        let resolver = test_resolver();
        // Use a port that's guaranteed to be closed (connection refused)
        // Port 1 is typically reserved and closed
        let result = get_ssl_certificate_info("127.0.0.1".to_string(), resolver.as_ref()).await;
        // Should fail with connection error or timeout
        match result {
            Ok(_) => panic!("Expected error for connection refused"),
            Err(e) => {
                let error_msg = e.to_string();
                assert!(
                    error_msg.contains("Failed to connect")
                        || error_msg.contains("connection")
                        || error_msg.contains("timeout")
                        || error_msg.contains("refused")
                        || error_msg.contains("Unsafe URL")
                        || error_msg.contains("private"),
                    "Expected connection or safety error, got: {}",
                    error_msg
                );
            }
        }
    }

    #[tokio::test]
    async fn test_get_ssl_certificate_info_nonexistent_domain_dns() {
        init_crypto_for_test();
        let resolver = test_resolver();
        // Test with a domain that definitely doesn't exist (DNS failure)
        let result = get_ssl_certificate_info(
            "this-domain-definitely-does-not-exist-12345.invalid".to_string(),
            resolver.as_ref(),
        )
        .await;
        // Should fail with DNS or connection error
        match result {
            Ok(_) => panic!("Expected error for nonexistent domain"),
            Err(e) => {
                let error_msg = e.to_string();
                assert!(
                    error_msg.contains("Failed to connect")
                        || error_msg.contains("Failed to resolve")
                        || error_msg.contains("connection")
                        || error_msg.contains("timeout")
                        || error_msg.contains("Invalid domain name")
                        || error_msg.contains("lookup"),
                    "Expected DNS/connection error, got: {}",
                    error_msg
                );
            }
        }
    }

    #[tokio::test]
    async fn test_get_ssl_certificate_info_tcp_timeout() {
        init_crypto_for_test();
        let resolver = test_resolver();
        // 192.0.2.0/24 is documentation (TEST-NET-1). We block it for SSRF before any connection,
        // so we get "Unsafe URL: private IPv4 address" rather than a TCP timeout.
        let result = get_ssl_certificate_info("192.0.2.1".to_string(), resolver.as_ref()).await;
        match result {
            Ok(_) => panic!("Expected error for 192.0.2.1 (blocked or timeout)"),
            Err(e) => {
                let error_msg = e.to_string();
                assert!(
                    error_msg.contains("timeout")
                        || error_msg.contains("Failed to connect")
                        || error_msg.contains("connection")
                        || error_msg.contains("private IPv4 address")
                        || error_msg.contains("not allowed"),
                    "Expected SSRF rejection or timeout/connection error, got: {}",
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
    fn test_order_public_addrs_ipv4_first_prefers_ipv4() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let ips = vec![
            std::net::IpAddr::V6(Ipv6Addr::LOCALHOST),
            std::net::IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            std::net::IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946,
            )),
            std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        ];
        let ordered = order_public_addrs_ipv4_first(ips.into_iter());
        assert_eq!(
            ordered,
            vec![
                std::net::IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                std::net::IpAddr::V6(Ipv6Addr::LOCALHOST),
                std::net::IpAddr::V6(Ipv6Addr::new(
                    0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946,
                )),
            ]
        );
    }

    #[test]
    fn test_order_public_addrs_ipv4_first_empty() {
        let ordered = order_public_addrs_ipv4_first(std::iter::empty());
        assert!(ordered.is_empty());
    }

    #[tokio::test]
    async fn test_connect_tls_tcp_tries_each_addr_and_reports_all_on_failure() {
        // 127.0.0.1:1 is a reserved, normally-closed port; used here purely to force
        // a connection failure without any network dependency.
        let addrs = vec![
            SocketAddr::from(([127, 0, 0, 1], 1)),
            SocketAddr::from(([127, 0, 0, 1], 2)),
        ];
        let err = connect_tls_tcp("example.test", &addrs)
            .await
            .expect_err("both addresses should fail to connect");
        let msg = err.to_string();
        assert!(msg.contains("127.0.0.1:1"), "message: {msg}");
        assert!(msg.contains("127.0.0.1:2"), "message: {msg}");
        assert!(msg.contains("example.test"), "message: {msg}");
    }

    #[tokio::test]
    async fn test_connect_tls_tcp_returns_no_addrs_error_when_empty() {
        let err = connect_tls_tcp("example.test", &[])
            .await
            .expect_err("no addresses should fail");
        assert!(err.to_string().contains("any of"));
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

    fn fixture_server_identity() -> (Vec<u8>, Vec<u8>) {
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
        let key_pair = KeyPair::generate().expect("key pair");
        let cert = params.self_signed(&key_pair).expect("certificate");
        (cert.der().to_vec(), key_pair.serialize_der())
    }

    async fn handshake_local_tls_fixture() -> crate::models::CertificateInfo {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::net::{TcpListener, TcpStream};
        use tokio_rustls::TlsAcceptor;

        init_crypto_for_test();
        let (cert_der, key_der) = fixture_server_identity();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert_der)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
            )
            .expect("server TLS config");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local TLS listener");
        let addr = listener.local_addr().expect("listener addr");
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept TLS client");
            let _session = acceptor.accept(tcp).await.expect("server handshake");
            let _ = release_rx.await;
        });

        let client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
            .with_no_client_auth();
        let sock = TcpStream::connect(addr).await.expect("connect to fixture");
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from("example.com".to_string()).expect("SNI");
        let tls_stream = connector
            .connect(server_name, sock)
            .await
            .expect("client handshake");

        use rustls::ProtocolVersion;
        let tls_version = tls_stream.get_ref().1.protocol_version().map_or(
            crate::models::TlsVersion::Unknown,
            |v| match v {
                ProtocolVersion::TLSv1_0 => crate::models::TlsVersion::Tls10,
                ProtocolVersion::TLSv1_1 => crate::models::TlsVersion::Tls11,
                ProtocolVersion::TLSv1_2 => crate::models::TlsVersion::Tls12,
                ProtocolVersion::TLSv1_3 => crate::models::TlsVersion::Tls13,
                ProtocolVersion::SSLv2 | ProtocolVersion::SSLv3 => crate::models::TlsVersion::Ssl30,
                _ => crate::models::TlsVersion::Unknown,
            },
        );
        let cipher_suite = tls_stream
            .get_ref()
            .1
            .negotiated_cipher_suite()
            .map(|cs| format!("{:?}", cs.suite()));
        let cert = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .expect("peer certificate after handshake");
        let parsed = parse_certificate_info_from_der(cert.as_ref(), tls_version, cipher_suite)
            .expect("parse handshake certificate");
        drop(tls_stream);
        let _ = release_tx.send(());
        parsed
    }

    #[tokio::test]
    async fn test_local_tls_handshake_fields_persist_to_sqlite() {
        use crate::storage::insert::url::{insert_url_record, UrlRecordInsertParams};
        use crate::storage::models::UrlRecord;
        use crate::storage::test_helpers::{create_test_pool, create_test_run};
        use sqlx::Row;
        use std::collections::HashMap;

        let parsed = handshake_local_tls_fixture().await;
        assert!(
            parsed
                .subject
                .as_deref()
                .is_some_and(|s| s.contains("example.com")),
            "handshake subject should include fixture CN"
        );
        assert_eq!(
            parsed.subject_alternative_names,
            Some(vec![
                "example.com".to_string(),
                "www.example.com".to_string()
            ])
        );

        let pool = create_test_pool().await;
        create_test_run(&pool, "tls-fixture-run", 1_704_067_200_000).await;

        let mut record = UrlRecord::test_default();
        record.run_id = Some("tls-fixture-run".to_string());
        record.tls_version = parsed.tls_version;
        record.ssl_cert_subject = parsed.subject.clone();
        record.ssl_cert_issuer = parsed.issuer.clone();
        record.ssl_cert_valid_from = parsed.valid_from;
        record.ssl_cert_valid_to = parsed.valid_to;
        record.cipher_suite = parsed.cipher_suite.clone();
        record.key_algorithm = parsed.key_algorithm.clone();
        record.cert_fingerprint_sha256 = parsed.fingerprint_sha256.clone();
        record.cert_serial_number = parsed.serial_number.clone();
        record.cert_is_self_signed = parsed.is_self_signed;
        record.cert_is_wildcard = parsed.is_wildcard;

        let empty_headers = HashMap::new();
        let oids = parsed.oids.clone().unwrap_or_default();
        let sans = parsed.subject_alternative_names.clone().unwrap_or_default();
        let id = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &empty_headers,
            http_headers: &empty_headers,
            oids: &oids,
            redirect_chain: &[],
            technologies: &[],
            subject_alternative_names: &sans,
            cname_records: None,
            aaaa_records: None,
            caa_records: None,
            csp_domains: &[],
            cookies: &[],
            resource_hints: &[],
            script_hosts: &[],
            security_txt: None,
            robots_txt: None,
        })
        .await
        .expect("insert handshake certificate");

        let row = sqlx::query(
            "SELECT ssl_cert_subject, cert_fingerprint_sha256, cert_is_self_signed \
             FROM url_status WHERE id = ?",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("url_status cert columns");
        assert_eq!(
            row.get::<Option<String>, _>("ssl_cert_subject"),
            parsed.subject
        );
        assert_eq!(
            row.get::<Option<String>, _>("cert_fingerprint_sha256"),
            parsed.fingerprint_sha256
        );
        assert_eq!(row.get::<Option<i64>, _>("cert_is_self_signed"), Some(1));

        let db_sans: Vec<String> = sqlx::query_scalar(
            "SELECT san_value FROM url_certificate_sans WHERE url_status_id = ? ORDER BY san_value",
        )
        .bind(id)
        .fetch_all(&pool)
        .await
        .expect("sans");
        let mut expected_sans = sans;
        expected_sans.sort();
        assert_eq!(db_sans, expected_sans);

        let oid_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM url_certificate_oids WHERE url_status_id = ?")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("oid count");
        assert!(
            oid_count > 0,
            "handshake OIDs must persist to url_certificate_oids"
        );
    }
}
