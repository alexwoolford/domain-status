use anyhow::{Error, Result};
use hickory_resolver::TokioAsyncResolver;
use lazy_static::lazy_static;
use log::{error, info};
use publicsuffix::{List, Psl};
use regex::Regex;
use reqwest::Url;
use rustls::pki_types::ServerName;
use scraper::{Html, Selector};
use sqlx::SqlitePool;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use x509_parser::extensions::ParsedExtension;
// removed unused Serialize import
use crate::database::{insert_url_record, UrlRecord};
use crate::error_handling::{get_retry_strategy, update_error_stats, ErrorStats, ErrorType};
use serde_json;

lazy_static! {
    static ref TITLE_SELECTOR: Selector = Selector::parse("title").unwrap();
    static ref META_KEYWORDS_SELECTOR: Selector = Selector::parse("meta[name='keywords']").unwrap();
    static ref META_DESCRIPTION_SELECTOR: Selector =
        Selector::parse("meta[name='description']").unwrap();
}

fn extract_domain(list: &List, url: &str) -> Result<String, anyhow::Error> {
    let parsed = Url::parse(url)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Failed to extract host from {url}"))?;
    let d = list
        .domain(host.as_bytes())
        .ok_or_else(|| anyhow::anyhow!("Failed to extract domain from {url}"))?;
    Ok(String::from_utf8_lossy(d.as_bytes()).to_string())
}

fn serialize_with_sorted_keys<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value)
        .and_then(|json| {
            let deserialized: serde_json::Value = serde_json::from_str(&json).unwrap();
            serde_json::to_string(&deserialized)
        })
        .unwrap_or_else(|_| "{}".to_string())
}

async fn handle_response(
    response: reqwest::Response,
    url: &str,
    pool: &SqlitePool,
    extractor: &List,
    resolver: &TokioAsyncResolver,
    error_stats: &ErrorStats,
    elapsed: f64,
    redirect_chain_json: Option<String>,
) -> Result<(), Error> {
    log::debug!("Started processing response for {url}");

    // Determine the final URL after all redirects (passed-in) and keep provided redirect chain JSON
    let final_url = response.url().to_string();

    log::debug!("Final url after redirects: {final_url}");

    // Extract the final domain using the extractor
    let final_domain = extract_domain(extractor, &final_url)?;

    log::debug!("Final domain extracted: {final_domain}");

    // Parse host once for TLS/DNS
    let url = Url::parse(&final_url)?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::Error::msg("Failed to extract host"))?;

    let (tls_version, subject, issuer, valid_from, valid_to, oids) =
        if final_url.starts_with("https://") {
            // Use the actual host (e.g., www.bbc.co.uk) for SSL extraction
            match get_ssl_certificate_info(host.to_string()).await {
                Ok(cert_info) => (
                    cert_info.tls_version,
                    cert_info.subject,
                    cert_info.issuer,
                    cert_info.valid_from,
                    cert_info.valid_to,
                    cert_info.oids,
                ),
                Err(e) => {
                    log::error!("Failed to get SSL certificate info for {final_domain}: {e}");
                    (None, None, None, None, None, None)
                }
            }
        } else {
            (None, None, None, None, None, None)
        };

    log::debug!("Extracted SSL info for {final_domain}: {tls_version:?}, {subject:?}, {issuer:?}, {valid_from:?}, {valid_to:?}");

    let headers = response.headers().clone();
    let status = response.status();
    let status_desc = status.canonical_reason().unwrap_or("Unknown Status Code");

    // Enforce HTML content-type, else skip
    if let Some(ct) = headers.get(reqwest::header::CONTENT_TYPE) {
        let ct = ct.to_str().unwrap_or("");
        if !ct.starts_with("text/html") {
            log::debug!("Skipping non-HTML content-type: {ct}");
            return Ok(());
        }
    }

    // Cap body size (~2MB)
    let body = match response.bytes().await {
        Ok(bytes) => {
            if bytes.len() > 2 * 1024 * 1024 {
                log::debug!("Skipping large body: {} bytes", bytes.len());
                return Ok(());
            }
            String::from_utf8_lossy(&bytes).to_string()
        }
        Err(_) => String::new(),
    };

    let title = extract_title(&body, error_stats);

    log::debug!("Extracted title for {final_domain}: {title:?}");

    let keywords = extract_meta_keywords(&body, error_stats);
    let keywords_str = keywords.map(|kw| kw.join(", "));

    log::debug!("Extracted keywords for {final_domain}: {keywords_str:?}");

    let description = extract_meta_description(&body, error_stats);

    log::debug!("Extracted description for {final_domain}: {description:?}");

    let linkedin_slug = extract_linkedin_slug(&body, error_stats);

    log::debug!("Extracted LinkedIn slug for {final_domain}: {linkedin_slug:?}");

    let initial_domain = extract_domain(extractor, &url.to_string())?;

    log::debug!("Resolved host: {host}");

    let ip_address = resolve_host_to_ip_with(host, resolver).await?;

    log::debug!("Resolved IP address: {ip_address}");

    let reverse_dns_name = reverse_dns_lookup_with(&ip_address, resolver).await?;

    log::debug!("Resolved reverse DNS name: {reverse_dns_name:?}");

    let security_headers = extract_security_headers(&headers);
    let security_headers_json = serialize_with_sorted_keys(&security_headers);

    let is_mobile_friendly = is_mobile_friendly(&body);

    let timestamp = chrono::Utc::now().timestamp_millis();

    log::debug!("Preparing to insert record for URL: {final_url}");

    log::info!("Attempting to insert record into database for domain: {initial_domain}");

    let record = UrlRecord {
        initial_domain,
        final_domain,
        ip_address,
        reverse_dns_name,
        status: status.as_u16(),
        status_desc: status_desc.to_string(),
        response_time: elapsed,
        title,
        keywords: keywords_str,
        description,
        linkedin_slug,
        security_headers: security_headers_json,
        tls_version,
        ssl_cert_subject: subject,
        ssl_cert_issuer: issuer,
        ssl_cert_valid_from: valid_from,
        ssl_cert_valid_to: valid_to,
        oids,
        is_mobile_friendly,
        timestamp,
        redirect_chain: redirect_chain_json,
    };

    let update_result = insert_url_record(pool, &record).await;

    match update_result {
        Ok(_) => log::info!("Record successfully inserted for URL: {final_url}"),
        Err(e) => log::error!("Failed to insert record for URL {final_url}: {e}"),
    };

    Ok(())
}

fn extract_security_headers(headers: &reqwest::header::HeaderMap) -> HashMap<String, String> {
    let headers_list = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
    ];

    headers_list
        .iter()
        .filter_map(|&header_name| {
            headers.get(header_name).map(|value| {
                (
                    header_name.to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
        })
        .collect()
}

async fn handle_http_request(
    client: &reqwest::Client,
    url: &str,
    pool: &SqlitePool,
    extractor: &List,
    resolver: &TokioAsyncResolver,
    error_stats: &ErrorStats,
    start_time: std::time::Instant,
) -> Result<(), Error> {
    log::debug!("Resolving redirects for {url}");

    // Resolve redirect chain manually using a client with redirects disabled
    let (final_url_string, redirect_chain_json) = resolve_redirect_chain(url, 10).await?;

    log::debug!("Sending request to final URL {final_url_string}");

    let res = client
        .get(&final_url_string)
        .header(reqwest::header::ACCEPT, "text/html,application/xhtml+xml")
        .send()
        .await;

    let elapsed = start_time.elapsed().as_secs_f64();

    let response = match res {
        Ok(response) => {
            log::debug!("Received response from {url}");
            response
        }
        Err(e) => {
            log::error!("Error occurred while accessing {url}: {e:?}");
            update_error_stats(error_stats, &e).await;
            return Err(e.into());
        }
    };

    log::debug!("Handling response for {final_url_string}");
    let handle_result = handle_response(
        response,
        &final_url_string,
        pool,
        extractor,
        resolver,
        error_stats,
        elapsed,
        Some(redirect_chain_json),
    )
    .await;

    match &handle_result {
        Ok(_) => log::debug!("Handled response for {url}"),
        Err(e) => log::error!("Failed to handle response for {url}: {e}"),
    }

    handle_result
}

fn extract_title(html: &str, error_stats: &ErrorStats) -> String {
    let parsed_html = Html::parse_document(html);

    // Use the pre-created selector.
    match parsed_html.select(&TITLE_SELECTOR).next() {
        Some(element) => element.inner_html().trim().to_string(),
        None => {
            error_stats.increment(ErrorType::TitleExtractError);
            String::from("")
        }
    }
}

fn extract_meta_keywords(html: &str, error_stats: &ErrorStats) -> Option<Vec<String>> {
    let parsed_html = Html::parse_document(html);
    let meta_keywords = parsed_html
        .select(&META_KEYWORDS_SELECTOR)
        .next()
        .and_then(|element| element.value().attr("content"));

    match meta_keywords {
        Some(content) => {
            let keywords: Vec<String> = content
                .split(',')
                .map(|keyword| keyword.trim().to_lowercase())
                .filter(|keyword| !keyword.is_empty()) // Filter out any empty strings
                .collect();

            if keywords.is_empty() {
                // If after filtering we have no keywords, return None instead of an empty vector
                error_stats.increment(ErrorType::KeywordExtractError);
                None
            } else {
                Some(keywords)
            }
        }
        None => {
            // No keywords meta tag found
            error_stats.increment(ErrorType::KeywordExtractError);
            None
        }
    }
}

fn extract_meta_description(html: &str, error_stats: &ErrorStats) -> Option<String> {
    let parsed_html = Html::parse_document(html);
    let meta_description = parsed_html
        .select(&META_DESCRIPTION_SELECTOR)
        .next()
        .and_then(|element| {
            element
                .value()
                .attr("content")
                .map(|content| content.trim().to_string())
        });

    if meta_description.is_none() {
        error_stats.increment(ErrorType::MetaDescriptionExtractError);
    }

    meta_description
}

fn extract_linkedin_slug(html: &str, error_stats: &ErrorStats) -> Option<String> {
    let document = Html::parse_document(html);
    let selector = Selector::parse("a[href]").unwrap();
    let re = Regex::new(r"https?://www\.linkedin\.com/company/([^/?]+)").unwrap();

    for element in document.select(&selector) {
        if let Some(link) = element.value().attr("href") {
            if let Some(caps) = re.captures(link) {
                return caps.get(1).map(|m| m.as_str().to_string());
            }
        }
    }
    error_stats.increment(ErrorType::LinkedInSlugExtractError);
    None
}

fn is_mobile_friendly(html: &str) -> bool {
    html.contains("viewport")
}

struct CertificateInfo {
    tls_version: Option<String>,
    subject: Option<String>,
    issuer: Option<String>,
    valid_from: Option<chrono::NaiveDateTime>,
    valid_to: Option<chrono::NaiveDateTime>,
    oids: Option<String>,
}

fn extract_certificate_policies(
    cert: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<Vec<String>, anyhow::Error> {
    let mut oids: Vec<String> = Vec::new();

    for ext in cert.extensions() {
        // Dereference the result from parsed_extension()
        if let ParsedExtension::CertificatePolicies(ref policies) = *ext.parsed_extension() {
            oids.extend(policies.iter().map(|policy| policy.policy_id.to_string()));
        }
    }
    Ok(oids)
}

async fn resolve_host_to_ip_with(
    host: &str,
    resolver: &TokioAsyncResolver,
) -> Result<String, Error> {
    let response = resolver.lookup_ip(host).await.map_err(Error::new)?;
    let ip = response
        .iter()
        .next()
        .ok_or_else(|| Error::msg("No IP addresses found"))?
        .to_string();
    Ok(ip)
}

async fn reverse_dns_lookup_with(
    ip: &str,
    resolver: &TokioAsyncResolver,
) -> Result<Option<String>, Error> {
    match resolver.reverse_lookup(ip.parse()?).await {
        Ok(response) => {
            let name = response.iter().next().map(|name| name.to_utf8());
            Ok(name)
        }
        Err(e) => {
            log::warn!("Failed to perform reverse DNS lookup for {ip}: {e}");
            Ok(None)
        }
    }
}

// src/utils.rs

async fn resolve_redirect_chain(
    start_url: &str,
    max_hops: usize,
) -> Result<(String, String), Error> {
    let mut chain: Vec<String> = Vec::new();
    let mut current = start_url.to_string();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    for _ in 0..max_hops {
        chain.push(current.clone());
        let resp = client.get(&current).send().await?;
        if let Some(loc) = resp.headers().get(reqwest::header::LOCATION) {
            let loc = loc.to_str().unwrap_or("").to_string();
            let new_url = Url::parse(&loc)
                .or_else(|_| Url::parse(&current).and_then(|base| base.join(&loc)))?;
            current = new_url.to_string();
            // continue loop for next hop
            continue;
        }
        // no redirect
        break;
    }
    let chain_json = serde_json::to_string(&chain).unwrap_or_else(|_| "[]".to_string());
    Ok((current, chain_json))
}

async fn get_ssl_certificate_info(domain: String) -> Result<CertificateInfo, anyhow::Error> {
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
    let sock = match TcpStream::connect((domain.clone(), 443)).await {
        Ok(sock) => sock,
        Err(e) => {
            error!("Failed to connect to {domain}:443 - {e}");
            return Err(anyhow::anyhow!("Failed to connect to {}:443", domain));
        }
    };

    let connector = TlsConnector::from(Arc::new(config));
    let mut tls_stream = match connector.connect(server_name, sock).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("TLS connection failed for {domain}: {e}");
            return Err(anyhow::anyhow!("TLS connection failed for {}", domain));
        }
    };

    log::info!("Extracting TLS version for domain: {domain}");
    let tls_version = tls_stream
        .get_ref()
        .1
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "Unknown".to_string());

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

            let oids = extract_certificate_policies(&cert).unwrap_or_else(|_| Vec::new());
            let unique_oids: HashSet<String> = oids.into_iter().collect();
            let serialized_oids = serialize_with_sorted_keys(&unique_oids);

            log::info!("Extracting validity period for domain: {domain}");
            let valid_from_str =
                tbs_cert.validity.not_before.to_rfc2822().map_err(|e| {
                    anyhow::anyhow!("RFC2822 conversion error for not_before: {}", e)
                })?;
            let valid_from =
                chrono::NaiveDateTime::parse_from_str(&valid_from_str, "%a, %d %b %Y %H:%M:%S %z")
                    .map_err(|_| anyhow::anyhow!("Failed to parse not_before"))?;

            let valid_to_str =
                tbs_cert.validity.not_after.to_rfc2822().map_err(|e| {
                    anyhow::anyhow!("RFC2822 conversion error for not_after: {}", e)
                })?;
            let valid_to =
                chrono::NaiveDateTime::parse_from_str(&valid_to_str, "%a, %d %b %Y %H:%M:%S %z")
                    .map_err(|_| anyhow::anyhow!("Failed to parse not_after"))?;

            info!("SSL certificate info extracted for domain: {domain}");

            return Ok(CertificateInfo {
                tls_version: Some(tls_version),
                subject: Some(subject),
                issuer: Some(issuer),
                valid_from: Some(valid_from),
                valid_to: Some(valid_to),
                oids: Some(serialized_oids),
            });
        }
    }

    Err(anyhow::anyhow!(
        "Failed to retrieve certificate information for {}",
        domain
    ))
}

pub async fn process_url(
    url: String,
    client: Arc<reqwest::Client>,
    pool: Arc<SqlitePool>,
    extractor: Arc<List>,
    resolver: Arc<TokioAsyncResolver>,
    error_stats: Arc<ErrorStats>,
) {
    log::debug!("Starting process for URL: {url}");

    let retry_strategy = get_retry_strategy();
    let start_time = std::time::Instant::now();

    let future = tokio_retry::Retry::spawn(retry_strategy, || {
        let client = client.clone();
        let url = url.clone();
        let pool = pool.clone();
        let extractor = extractor.clone();
        let error_stats = error_stats.clone();
        let resolver = resolver.clone();

        tokio::task::spawn(async move {
            handle_http_request(
                &client,
                &url,
                &pool,
                &extractor,
                &resolver,
                &error_stats,
                start_time,
            )
            .await
        })
    });

    match future.await {
        Ok(_) => {}
        Err(e) => error!("Error after retries: {e}"),
    }
}
