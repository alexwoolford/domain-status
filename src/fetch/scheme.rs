//! Scheme-less HTTP fallback.
//!
//! Bare hosts are normalized to `https` first. This module tries `http` on the
//! same host and port only when that attempt never completes. A completed HTTPS
//! status, including 4xx/5xx and a redirect toward HTTP, is kept. Fallback is a
//! new request, not an https→http redirect hop.

use anyhow::Error;
use std::error::Error as StdError;

use super::handler::{handle_http_request, UrlProcessOutcome};
use super::ProcessingContext;

/// Fetches `url`, falling back from HTTPS to HTTP when the input omitted a scheme
/// and the HTTPS attempt never completed.
///
/// A successful fallback returns only the HTTP page. The failed HTTPS attempt is
/// not stored (no paired `url_status` and `url_failures` row).
///
/// # Errors
///
/// Returns the HTTPS error when fallback does not apply, or the HTTP error when
/// the fallback attempt also fails.
pub(crate) async fn handle_http_request_with_fallback(
    ctx: &ProcessingContext,
    url: &str,
    start_time: std::time::Instant,
    scheme_omitted: bool,
) -> Result<UrlProcessOutcome, Error> {
    match handle_http_request(ctx, url, start_time).await {
        Ok(outcome) => Ok(outcome),
        Err(error) if should_try_http_fallback(scheme_omitted, url, &error) => {
            let Some(http_url) = crate::app::url::http_fallback_url(url) else {
                return Err(error);
            };
            log::info!("HTTPS attempt did not complete for {url}; trying {http_url}");
            handle_http_request(ctx, &http_url, start_time).await
        }
        Err(error) => Err(error),
    }
}

fn should_try_http_fallback(scheme_omitted: bool, url: &str, error: &Error) -> bool {
    if !scheme_omitted {
        return false;
    }
    match url::Url::parse(url) {
        Ok(parsed) if parsed.scheme() == "https" => https_attempt_never_completed(error),
        _ => false,
    }
}

/// Connection refused, timeout, TLS handshake failure, or the peer aborting the
/// handshake, with no HTTP status.
///
/// A wrapped I/O error often has [`std::io::ErrorKind::Other`], so the OS
/// message is required as well as the kind. Windows says "forcibly closed"
/// (os error 10054). Other platforms say "connection reset" or "broken pipe".
fn https_attempt_never_completed(error: &Error) -> bool {
    let Some(reqwest_err) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<reqwest::Error>())
    else {
        return false;
    };
    if reqwest_err.status().is_some() {
        return false;
    }
    if reqwest_err.is_timeout() {
        return true;
    }
    if chain_has_rustls_error(reqwest_err) || chain_text_has_tls(reqwest_err) {
        return true;
    }
    peer_closed_before_http_status(reqwest_err)
}

fn peer_closed_before_http_status(err: &reqwest::Error) -> bool {
    const KINDS: [std::io::ErrorKind; 4] = [
        std::io::ErrorKind::ConnectionRefused,
        std::io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::ConnectionAborted,
        std::io::ErrorKind::BrokenPipe,
    ];
    if KINDS.iter().any(|kind| chain_has_io_kind(err, *kind)) {
        return true;
    }
    const NEEDLES: [&str; 4] = [
        "connection refused",
        "connection reset",
        "forcibly closed",
        "broken pipe",
    ];
    NEEDLES.iter().any(|needle| chain_text_has(err, needle))
}

fn chain_any(err: &reqwest::Error, pred: impl Fn(&(dyn StdError + 'static)) -> bool) -> bool {
    if pred(err) {
        return true;
    }
    let mut source = err.source();
    while let Some(cause) = source {
        if pred(cause) {
            return true;
        }
        source = cause.source();
    }
    false
}

fn chain_has_rustls_error(err: &reqwest::Error) -> bool {
    chain_any(err, |cause| cause.downcast_ref::<rustls::Error>().is_some())
}

fn chain_has_io_kind(err: &reqwest::Error, kind: std::io::ErrorKind) -> bool {
    chain_any(err, |cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == kind)
    })
}

fn chain_text_has_tls(err: &reqwest::Error) -> bool {
    chain_text_has(err, "tls")
        || chain_text_has(err, "handshake")
        || chain_text_has(err, "certificate")
        // rustls reports a plaintext HTTP byte as a corrupt handshake record.
        || chain_text_has(err, "corrupt message")
        || chain_text_has(err, "invalidcontenttype")
        || chain_text_has(err, "invalid content type")
}

fn chain_text_has(err: &reqwest::Error, needle: &str) -> bool {
    chain_any(err, |cause| {
        cause.to_string().to_ascii_lowercase().contains(needle)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ProcessingStats;
    use crate::fetch::{NetworkContext, ProcessingContext, RuntimeContext};
    use crate::initialization::test_resolver;
    use crate::utils::TimingStats;
    use httptest::{matchers::*, responders::*, Expectation, Server};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn http_message(status: u16, reason: &str, extra: &str, body: &str) -> Vec<u8> {
        let mut message =
            format!("HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\n");
        message.push_str(&format!("Content-Length: {}\r\n", body.len()));
        message.push_str("Connection: close\r\n");
        message.push_str(extra);
        message.push('\r');
        message.push('\n');
        message.push_str(body);
        message.into_bytes()
    }

    fn page_body() -> &'static str {
        "<html><title>Page</title></html>"
    }

    async fn discard_headers<S: AsyncRead + Unpin>(stream: &mut S) {
        let mut buf = [0u8; 1024];
        let mut seen = Vec::new();
        loop {
            let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
            let Ok(Ok(n)) = read else {
                return;
            };
            if n == 0 || seen.len() > 8192 {
                return;
            }
            seen.extend_from_slice(&buf[..n]);
            if seen.windows(4).any(|window| window == b"\r\n\r\n") {
                return;
            }
        }
    }

    struct HttpProbe {
        addr: std::net::SocketAddr,
        tls_hellos: Arc<AtomicUsize>,
        http_responses: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for HttpProbe {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn spawn_http_probe() -> HttpProbe {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind http probe");
        let addr = listener.local_addr().expect("http probe addr");
        let tls_hellos = Arc::new(AtomicUsize::new(0));
        let http_responses = Arc::new(AtomicUsize::new(0));
        let body = Arc::<[u8]>::from(http_message(200, "OK", "", page_body()).into_boxed_slice());
        let task = tokio::spawn(serve_http_probe(
            listener,
            Arc::clone(&tls_hellos),
            Arc::clone(&http_responses),
            body,
        ));
        HttpProbe {
            addr,
            tls_hellos,
            http_responses,
            task,
        }
    }

    async fn serve_http_probe(
        listener: TcpListener,
        tls_hellos: Arc<AtomicUsize>,
        http_responses: Arc<AtomicUsize>,
        body: Arc<[u8]>,
    ) {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let tls_hellos = Arc::clone(&tls_hellos);
            let http_responses = Arc::clone(&http_responses);
            let body = Arc::clone(&body);
            tokio::spawn(async move {
                if first_byte(&mut sock).await == Some(0x16) {
                    tls_hellos.fetch_add(1, Ordering::SeqCst);
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    return;
                }
                http_responses.fetch_add(1, Ordering::SeqCst);
                discard_headers(&mut sock).await;
                let _ = sock.write_all(&body).await;
            });
        }
    }

    async fn first_byte(sock: &mut TcpStream) -> Option<u8> {
        let mut prefix = [0u8; 1];
        let peeked = tokio::time::timeout(Duration::from_secs(2), sock.peek(&mut prefix)).await;
        match peeked {
            Ok(Ok(1)) => Some(prefix[0]),
            _ => None,
        }
    }

    struct HttpsProbe {
        addr: std::net::SocketAddr,
        plaintext_requests: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for HttpsProbe {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn localhost_tls_material() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
        };
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        let mut ca_name = DistinguishedName::new();
        ca_name.push(DnType::CommonName, "example.com");
        ca_params.distinguished_name = ca_name;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params =
            CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("leaf params");
        let mut leaf_name = DistinguishedName::new();
        leaf_name.push(DnType::CommonName, "127.0.0.1");
        leaf_params.distinguished_name = leaf_name;
        leaf_params.is_ca = IsCa::ExplicitNoCa;
        let issuer = Issuer::from_params(&ca_params, &ca_key);
        let leaf = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf cert");
        (
            ca_cert.der().to_vec(),
            leaf.der().to_vec(),
            leaf_key.serialize_der(),
        )
    }

    async fn spawn_https_probe(response: Vec<u8>) -> (HttpsProbe, reqwest::Client) {
        crate::initialization::init_crypto_provider();
        let (ca_der, leaf_der, leaf_key) = localhost_tls_material();
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(leaf_der)],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key),
                ),
            )
            .expect("server tls config");
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind https probe");
        let addr = listener.local_addr().expect("https probe addr");
        let plaintext_requests = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(serve_https_probe(
            listener,
            acceptor,
            Arc::clone(&plaintext_requests),
            Arc::<[u8]>::from(response.into_boxed_slice()),
        ));
        let ca = reqwest::Certificate::from_der(&ca_der).expect("trust anchor");
        let client = reqwest::Client::builder()
            .add_root_certificate(ca)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(2))
            .build()
            .expect("trusting client");
        (
            HttpsProbe {
                addr,
                plaintext_requests,
                task,
            },
            client,
        )
    }

    async fn serve_https_probe(
        listener: TcpListener,
        acceptor: tokio_rustls::TlsAcceptor,
        plaintext_requests: Arc<AtomicUsize>,
        body: Arc<[u8]>,
    ) {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let plaintext_requests = Arc::clone(&plaintext_requests);
            let body = Arc::clone(&body);
            tokio::spawn(async move {
                if first_byte(&mut sock).await.is_some_and(|byte| byte != 0x16) {
                    plaintext_requests.fetch_add(1, Ordering::SeqCst);
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    return;
                }
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    return;
                };
                discard_headers(&mut tls).await;
                let _ = tls.write_all(&body).await;
                let _ = tls.shutdown().await;
            });
        }
    }

    fn plain_client() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(2))
            .build()
            .expect("client")
    }

    async fn memory_ctx(client: reqwest::Client) -> ProcessingContext {
        let client = Arc::new(client);
        let ctx = ProcessingContext::new(
            NetworkContext::new(Arc::clone(&client), Arc::clone(&client), test_resolver()),
            Arc::new(
                sqlx::SqlitePool::connect("sqlite::memory:")
                    .await
                    .expect("pool"),
            ),
            RuntimeContext::new(
                Arc::new(ProcessingStats::new()),
                Arc::new(TimingStats::new()),
                None,
                false,
                std::path::PathBuf::from("/tmp/domain_status_whois_test"),
                false,
                Arc::new(crate::runtime_metrics::RuntimeMetrics::default()),
                true,
            ),
            Arc::new(crate::fingerprint::FingerprintRuleset::empty_for_tests()),
        );
        crate::storage::run_migrations(&ctx.pool)
            .await
            .expect("migrate");
        ctx
    }

    async fn row_count(pool: &crate::storage::DbPool, sql: &'static str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(pool.as_ref())
            .await
            .expect("count")
    }

    async fn stored_page(pool: &crate::storage::DbPool) -> (i64, String, Option<String>) {
        let status: i64 = sqlx::query_scalar("SELECT http_status FROM url_status")
            .fetch_one(pool.as_ref())
            .await
            .expect("http_status");
        let initial: String = sqlx::query_scalar("SELECT initial_url FROM url_status")
            .fetch_one(pool.as_ref())
            .await
            .expect("initial_url");
        let subject: Option<String> = sqlx::query_scalar("SELECT ssl_cert_subject FROM url_status")
            .fetch_one(pool.as_ref())
            .await
            .expect("ssl_cert_subject");
        (status, initial, subject)
    }

    #[tokio::test]
    async fn explicit_http_is_not_upgraded_and_skips_certificate_probe() {
        let probe = spawn_http_probe().await;
        let ctx = memory_ctx(plain_client()).await;
        let url = format!("http://{}/page", probe.addr);
        handle_http_request_with_fallback(&ctx, &url, std::time::Instant::now(), false)
            .await
            .expect("explicit http page");

        let (status, initial, subject) = stored_page(&ctx.pool).await;
        assert_eq!(status, 200);
        assert!(
            initial.starts_with(&format!("http://{}", probe.addr)),
            "{initial}"
        );
        assert!(subject.is_none(), "explicit http stores no certificate");
        assert_eq!(
            probe.tls_hellos.load(Ordering::SeqCst),
            0,
            "explicit http must not open a TLS connection on the page port"
        );
        assert_eq!(
            ctx.runtime
                .error_stats
                .get_error_count(crate::error_handling::ErrorType::TlsCertificateError),
            0,
            "explicit http must not probe for a certificate"
        );
        assert_eq!(
            row_count(&ctx.pool, "SELECT COUNT(*) FROM url_status").await,
            1
        );
        assert_eq!(
            row_count(&ctx.pool, "SELECT COUNT(*) FROM url_failures").await,
            0
        );
    }

    #[tokio::test]
    async fn bare_host_tls_failure_falls_back_to_http_once() {
        let probe = spawn_http_probe().await;
        let ctx = memory_ctx(plain_client()).await;
        let url = format!("https://{}/page", probe.addr);
        handle_http_request_with_fallback(&ctx, &url, std::time::Instant::now(), true)
            .await
            .expect("http fallback page");

        let (status, initial, subject) = stored_page(&ctx.pool).await;
        assert_eq!(status, 200);
        assert!(
            initial.starts_with(&format!("http://{}", probe.addr)),
            "{initial}"
        );
        assert!(subject.is_none(), "http fallback stores no certificate");
        assert!(
            probe.tls_hellos.load(Ordering::SeqCst) >= 1,
            "https attempt should reach the port"
        );
        assert!(
            probe.http_responses.load(Ordering::SeqCst) >= 1,
            "http fallback should fetch the page"
        );
        assert_eq!(
            ctx.runtime
                .error_stats
                .get_error_count(crate::error_handling::ErrorType::TlsCertificateError),
            0
        );
        assert_eq!(
            row_count(&ctx.pool, "SELECT COUNT(*) FROM url_status").await,
            1
        );
        assert_eq!(
            row_count(&ctx.pool, "SELECT COUNT(*) FROM url_failures").await,
            0,
            "successful fallback stores the http page only"
        );
    }

    #[tokio::test]
    async fn explicit_https_transport_failure_does_not_fall_back() {
        let probe = spawn_http_probe().await;
        let ctx = memory_ctx(plain_client()).await;
        let url = format!("https://{}/page", probe.addr);
        let error = handle_http_request_with_fallback(&ctx, &url, std::time::Instant::now(), false)
            .await
            .expect_err("explicit https is not rewritten to http");
        assert!(
            https_attempt_never_completed(&error),
            "transport failure should be the kind fallback would use, got {error:#}"
        );
        assert_eq!(probe.http_responses.load(Ordering::SeqCst), 0);
        assert!(probe.tls_hellos.load(Ordering::SeqCst) >= 1);
        assert_eq!(
            row_count(&ctx.pool, "SELECT COUNT(*) FROM url_status").await,
            0
        );
    }

    #[tokio::test]
    async fn bare_host_https_status_is_kept() {
        let response = http_message(404, "Not Found", "", page_body());
        let (probe, client) = spawn_https_probe(response).await;
        let ctx = memory_ctx(client).await;
        let url = format!("https://{}/missing", probe.addr);
        let outcome =
            handle_http_request_with_fallback(&ctx, &url, std::time::Instant::now(), true)
                .await
                .expect("404 is the page");
        assert_eq!(outcome, UrlProcessOutcome::Inserted);

        let (status, initial, _) = stored_page(&ctx.pool).await;
        assert_eq!(status, 404);
        assert!(initial.starts_with("https://"), "{initial}");
        assert_eq!(
            probe.plaintext_requests.load(Ordering::SeqCst),
            0,
            "a completed https status must not fall back to http"
        );
        assert_eq!(
            row_count(&ctx.pool, "SELECT COUNT(*) FROM url_failures").await,
            0
        );
    }

    #[tokio::test]
    async fn bare_host_https_500_does_not_fall_back() {
        let response = http_message(500, "Internal Server Error", "", "nope");
        let (probe, client) = spawn_https_probe(response).await;
        let ctx = memory_ctx(client).await;
        let url = format!("https://{}/err", probe.addr);
        let error = handle_http_request_with_fallback(&ctx, &url, std::time::Instant::now(), true)
            .await
            .expect_err("500 stays the https result");
        assert_eq!(
            ctx.runtime
                .error_stats
                .get_error_count(crate::error_handling::ErrorType::HttpRequestInternalServerError),
            1,
            "completed 500 must be recorded as the https status, got {error:#}"
        );
        assert!(!https_attempt_never_completed(&error), "{error:#}");
        assert_eq!(probe.plaintext_requests.load(Ordering::SeqCst), 0);
        assert_eq!(
            row_count(&ctx.pool, "SELECT COUNT(*) FROM url_status").await,
            0
        );
    }

    #[tokio::test]
    async fn https_to_http_redirect_is_not_followed() {
        let http_server = Server::run();
        http_server.expect(
            Expectation::matching(any())
                .times(0)
                .respond_with(status_code(200).body("should-not-be-fetched")),
        );
        let location = http_server.url("/secret").to_string();
        let response = http_message(
            302,
            "Found",
            &format!("Location: {location}\r\n"),
            page_body(),
        );
        let (probe, client) = spawn_https_probe(response).await;
        let ctx = memory_ctx(client).await;
        let url = format!("https://{}/start", probe.addr);
        handle_http_request_with_fallback(&ctx, &url, std::time::Instant::now(), true)
            .await
            .expect("https redirect response is the page");

        let (status, initial, _) = stored_page(&ctx.pool).await;
        assert_eq!(status, 302);
        assert!(initial.starts_with("https://"), "{initial}");
        assert_eq!(
            probe.plaintext_requests.load(Ordering::SeqCst),
            0,
            "https to http redirect is not a fallback"
        );
    }

    #[tokio::test]
    async fn peer_reset_during_handshake_is_classified() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind reset port");
        let addr = listener.local_addr().expect("addr");
        let hold = tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                let std_stream = sock.into_std().expect("std stream");
                socket2::SockRef::from(&std_stream)
                    .set_linger(Some(Duration::ZERO))
                    .expect("linger");
                drop(std_stream);
            }
        });
        let error = plain_client()
            .get(format!("https://{addr}/"))
            .send()
            .await
            .expect_err("reset handshake");
        let error = Error::from(error);
        assert!(
            https_attempt_never_completed(&error),
            "peer reset should allow fallback, got {error:#}"
        );
        hold.abort();
    }

    #[tokio::test]
    async fn connection_refused_counts_as_https_never_completed() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind closed port");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        let error = plain_client()
            .get(format!("https://{addr}/"))
            .send()
            .await
            .expect_err("closed port");
        let error = Error::from(error);
        assert!(
            https_attempt_never_completed(&error),
            "connection refused should allow fallback, got {error:#}"
        );
    }

    #[tokio::test]
    async fn timeout_counts_as_https_never_completed() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stalling port");
        let addr = listener.local_addr().expect("addr");
        let hold = tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_secs(5)).await;
                drop(sock);
            }
        });
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(200))
            .connect_timeout(Duration::from_millis(200))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client");
        let error = client
            .get(format!("https://{addr}/"))
            .send()
            .await
            .expect_err("stalled handshake");
        let error = Error::from(error);
        assert!(
            https_attempt_never_completed(&error),
            "timeout should allow fallback, got {error:#}"
        );
        hold.abort();
    }

    #[test]
    fn non_transport_error_does_not_fall_back() {
        let error = anyhow::anyhow!("dns lookup failed");
        assert!(!https_attempt_never_completed(&error));
        assert!(!should_try_http_fallback(
            true,
            "https://example.com/",
            &error
        ));
        assert!(!should_try_http_fallback(
            false,
            "https://example.com/",
            &anyhow::anyhow!("connection refused")
        ));
        assert!(!should_try_http_fallback(
            true,
            "http://example.com/",
            &anyhow::anyhow!("connection refused")
        ));
    }
}
