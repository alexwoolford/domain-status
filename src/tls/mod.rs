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
#[cfg(test)]
mod test_certs;

use anyhow::Result;
use chrono::NaiveDateTime;
use hickory_resolver::TokioResolver;
use log::{debug, error};
use rustls::pki_types::{CertificateDer, ServerName};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use tokio::net::TcpStream;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;

use crate::models::CertificateInfo;

use extract::{extract_certificate_oids, extract_certificate_sans};

/// Accepts every presented certificate so capture can record facts from
/// misconfigured endpoints. This is not a trust decision (ADR 0003).
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
        rustls::crypto::CryptoProvider::get_default()
            .map(|provider| {
                provider
                    .signature_verification_algorithms
                    .supported_schemes()
            })
            .unwrap_or_else(|| {
                rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms
                    .supported_schemes()
            })
    }
}

fn capture_client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        Arc::new(
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
                .with_no_client_auth(),
        )
    }))
}

fn parse_tls_server_name(domain: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(domain.to_owned()).map_err(|e| {
        error!("Invalid domain name: {e}");
        anyhow::anyhow!("Invalid domain name: {e}")
    })
}

fn tls_version_from_protocol(
    version: Option<rustls::ProtocolVersion>,
) -> crate::models::TlsVersion {
    use rustls::ProtocolVersion;
    match version {
        Some(ProtocolVersion::TLSv1_0) => crate::models::TlsVersion::Tls10,
        Some(ProtocolVersion::TLSv1_1) => crate::models::TlsVersion::Tls11,
        Some(ProtocolVersion::TLSv1_2) => crate::models::TlsVersion::Tls12,
        Some(ProtocolVersion::TLSv1_3) => crate::models::TlsVersion::Tls13,
        Some(ProtocolVersion::SSLv2 | ProtocolVersion::SSLv3) => crate::models::TlsVersion::Ssl30,
        Some(_) | None => crate::models::TlsVersion::Unknown,
    }
}

fn naive_utc_from_unix_timestamp(secs: i64, field: &str) -> Result<NaiveDateTime> {
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.naive_utc())
        .ok_or_else(|| anyhow::anyhow!("Certificate {field} timestamp out of range: {secs}"))
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

    public_tls_socket_addrs(domain, response.iter())
}

/// Filters to public IPs, IPv4-first, and binds them to port 443.
fn public_tls_socket_addrs(
    domain: &str,
    ips: impl IntoIterator<Item = IpAddr>,
) -> Result<Vec<SocketAddr>> {
    let addrs = order_public_addrs_ipv4_first(
        ips.into_iter()
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
fn order_public_addrs_ipv4_first(ips: impl Iterator<Item = IpAddr>) -> Vec<IpAddr> {
    let (mut v4, v6): (Vec<_>, Vec<_>) = ips.partition(IpAddr::is_ipv4);
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
                debug!("Failed to connect to {domain} ({socket_addr}) - {e}");
                last_errors.push(format!("{socket_addr} ({e})"));
            }
            Err(_) => {
                debug!("TCP connection timeout for {domain} via {socket_addr}");
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
    let fingerprint_sha256 = Some(crate::utils::sha256_hex(cert_der));

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

    let serial_number = Some(tbs_cert.raw_serial_as_string());
    // Heuristic: identical subject and issuer DNs. Not a cryptographic verify.
    let is_self_signed = Some(subject == issuer);
    let is_wildcard = Some(sans.iter().any(|san| san.starts_with("*.")));

    let valid_from =
        naive_utc_from_unix_timestamp(tbs_cert.validity.not_before.timestamp(), "not_before")?;
    let valid_to =
        naive_utc_from_unix_timestamp(tbs_cert.validity.not_after.timestamp(), "not_after")?;

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

async fn handshake_and_parse(domain: &str, sock: TcpStream) -> Result<CertificateInfo> {
    let server_name = parse_tls_server_name(domain)?;
    let connector = TlsConnector::from(capture_client_config());
    let tls_stream = match tokio::time::timeout(
        std::time::Duration::from_secs(crate::config::TLS_HANDSHAKE_TIMEOUT_SECS),
        connector.connect(server_name, sock),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            error!("TLS connection failed for {domain}: {e}");
            return Err(anyhow::anyhow!("TLS connection failed for {domain}: {e}"));
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

    debug!("Extracting TLS version for domain: {domain}");
    let conn = tls_stream.get_ref().1;
    let tls_version = tls_version_from_protocol(conn.protocol_version());
    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()));

    // Certificates are available immediately after handshake; no HTTP request needed.
    if let Some(cert) = conn.peer_certificates().and_then(|certs| certs.first()) {
        let parsed = parse_certificate_info_from_der(cert.as_ref(), tls_version, cipher_suite)?;
        debug!("SSL certificate info extracted for domain: {domain}");
        return Ok(parsed);
    }

    Err(anyhow::anyhow!(
        "Failed to retrieve certificate information for {domain}"
    ))
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
pub async fn get_ssl_certificate_info(
    domain: &str,
    resolver: &TokioResolver,
) -> Result<CertificateInfo> {
    debug!("Attempting to get SSL info for domain: {domain}");
    parse_tls_server_name(domain)?;
    debug!("Attempting to connect to domain: {domain}");
    let socket_addrs = resolve_public_tls_addrs(domain, resolver).await?;
    let (sock, socket_addr) = connect_tls_tcp(domain, &socket_addrs).await?;
    debug!("Connected to {domain} via {socket_addr}");
    handshake_and_parse(domain, sock).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::initialization::test_resolver;
    use pretty_assertions::assert_eq;

    fn init_crypto_for_test() {
        crate::initialization::init_crypto_provider();
    }

    #[tokio::test]
    #[ignore] // Requires network access - run with `cargo test -- --ignored`
    async fn test_get_ssl_certificate_info_valid_domain() {
        init_crypto_for_test();
        let resolver = test_resolver();
        let cert_info = get_ssl_certificate_info("example.com", resolver.as_ref())
            .await
            .unwrap_or_else(|e| {
                panic!("ignored live TLS test must handshake example.com, got {e}")
            });
        assert!(
            cert_info.subject.is_some(),
            "certificate should include subject"
        );
        assert!(
            cert_info.issuer.is_some(),
            "certificate should include issuer"
        );
        assert!(
            matches!(
                cert_info.tls_version,
                Some(crate::models::TlsVersion::Tls12 | crate::models::TlsVersion::Tls13)
            ),
            "example.com should negotiate TLS 1.2 or 1.3, got {:?}",
            cert_info.tls_version
        );
        assert_eq!(
            cert_info.fingerprint_sha256.as_ref().map(String::len),
            Some(64)
        );
    }

    #[test]
    fn parse_tls_server_name_rejects_invalid() {
        for domain in ["", "..", "domain@invalid", "domain space.com"] {
            let err =
                parse_tls_server_name(domain).expect_err("invalid SNI should fail before DNS");
            assert!(
                err.to_string().contains("Invalid domain name"),
                "{domain}: {err}"
            );
        }
    }

    fn expected_dns_sans() -> Vec<String> {
        vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
            "*.example.com".to_string(),
        ]
    }

    #[test]
    fn test_parse_certificate_info_from_der_extracts_contract() {
        let cert = test_certs::generate(test_certs::TestCertOptions::default());
        let parsed = parse_certificate_info_from_der(
            &cert.der,
            crate::models::TlsVersion::Tls13,
            Some("TLS13_AES_256_GCM_SHA384".to_string()),
        )
        .expect("parse certificate");

        assert_eq!(parsed.tls_version, Some(crate::models::TlsVersion::Tls13));
        assert_eq!(parsed.subject_alternative_names, Some(expected_dns_sans()));
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
        assert_eq!(parsed.is_self_signed, Some(true));
        assert_eq!(parsed.is_wildcard, Some(true));
        assert!(parsed
            .serial_number
            .as_ref()
            .is_some_and(|serial| !serial.is_empty()));
        let expected_fp = crate::utils::sha256_hex(&cert.der);
        assert_eq!(
            parsed.fingerprint_sha256.as_deref(),
            Some(expected_fp.as_str())
        );
        assert_eq!(
            parsed.fingerprint_sha256.as_ref().map(String::len),
            Some(64)
        );
        assert_eq!(
            parsed.valid_from,
            Some(
                chrono::DateTime::from_timestamp(test_certs::DAY1_NOT_BEFORE_UNIX, 0)
                    .expect("day-1 from")
                    .naive_utc()
            )
        );
        assert_eq!(
            parsed.valid_to,
            Some(
                chrono::DateTime::from_timestamp(test_certs::DAY9_NOT_AFTER_UNIX, 0)
                    .expect("day-9 to")
                    .naive_utc()
            )
        );
        assert!(parsed.valid_from < parsed.valid_to);
        let oids = parsed.oids.expect("oids");
        assert!(oids.contains("2.5.29.17"));
        assert!(oids.contains(test_certs::DV_POLICY_OID));
        assert!(oids.contains(test_certs::CUSTOM_EKU_OID));
        assert!(matches!(
            parsed.key_algorithm,
            Some(crate::models::KeyAlgorithm::ECDSA | crate::models::KeyAlgorithm::Ed25519)
        ));
    }

    #[test]
    fn test_order_public_addrs_ipv4_first_prefers_ipv4() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let ips = vec![
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946,
            )),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        ];
        let ordered = order_public_addrs_ipv4_first(ips.into_iter());
        assert_eq!(
            ordered,
            vec![
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::new(
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

    #[test]
    fn public_tls_socket_addrs_skips_private_and_uses_port_443() {
        let addrs = public_tls_socket_addrs(
            "example.test",
            [
                IpAddr::from([127, 0, 0, 1]),
                IpAddr::from([1, 1, 1, 1]),
                IpAddr::from([10, 0, 0, 1]),
            ],
        )
        .expect("public ip");
        assert_eq!(addrs, vec![SocketAddr::from(([1, 1, 1, 1], 443))]);
    }

    #[test]
    fn public_tls_socket_addrs_errors_when_none_public() {
        let err = public_tls_socket_addrs("example.test", [IpAddr::from([127, 0, 0, 1])])
            .expect_err("loopback only");
        assert!(
            err.to_string()
                .contains("No public IP addresses resolved for example.test"),
            "{err}"
        );
    }

    #[test]
    fn tls_version_from_protocol_maps_known_versions() {
        use rustls::ProtocolVersion;
        assert_eq!(
            tls_version_from_protocol(Some(ProtocolVersion::TLSv1_2)),
            crate::models::TlsVersion::Tls12
        );
        assert_eq!(
            tls_version_from_protocol(Some(ProtocolVersion::TLSv1_3)),
            crate::models::TlsVersion::Tls13
        );
        assert_eq!(
            tls_version_from_protocol(Some(ProtocolVersion::SSLv3)),
            crate::models::TlsVersion::Ssl30
        );
        assert_eq!(
            tls_version_from_protocol(None),
            crate::models::TlsVersion::Unknown
        );
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
        let msg = err.to_string();
        assert!(msg.contains("example.test"), "message: {msg}");
        assert!(msg.contains("via any of: "), "message: {msg}");
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

    async fn handshake_local_tls_fixture() -> crate::models::CertificateInfo {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::net::{TcpListener, TcpStream};
        use tokio_rustls::TlsAcceptor;

        init_crypto_for_test();
        let cert = test_certs::generate(test_certs::TestCertOptions::default());
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_der)),
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

        let sock = TcpStream::connect(addr).await.expect("connect to fixture");
        let parsed = handshake_and_parse("example.com", sock)
            .await
            .expect("client handshake");
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
        assert_eq!(parsed.subject_alternative_names, Some(expected_dns_sans()));
        assert!(
            matches!(
                parsed.tls_version,
                Some(crate::models::TlsVersion::Tls12 | crate::models::TlsVersion::Tls13)
            ),
            "local fixture should negotiate TLS 1.2 or 1.3, got {:?}",
            parsed.tls_version
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
