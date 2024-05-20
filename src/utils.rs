
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use anyhow::{Result, Error, Context};
use scraper::{Html, Selector};
use log::{info, error};
use sqlx::SqlitePool;
use structopt::lazy_static::lazy_static;
use tldextract::TldExtractor;
use tokio::io::AsyncWriteExt;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use trust_dns_resolver::TokioAsyncResolver;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use reqwest::Url;
use regex::Regex;
use x509_parser::extensions::ParsedExtension;

use crate::database::update_database;
use crate::error_handling::{ErrorStats, ErrorType, get_retry_strategy, update_error_stats};

lazy_static! {
    static ref TITLE_SELECTOR: Selector = Selector::parse("title").unwrap();
    static ref META_KEYWORDS_SELECTOR: Selector = Selector::parse("meta[name='keywords']").unwrap();
    static ref META_DESCRIPTION_SELECTOR: Selector = Selector::parse("meta[name='description']").unwrap();
}

fn extract_domain(extractor: &TldExtractor, url: &str) -> Result<String, anyhow::Error> {
    extractor.extract(url)
        .map_err(|e| anyhow::anyhow!("Extractor error: {}", e))
        .and_then(|extract| {
            if let Some(main_domain) = extract.domain {
                Ok(format!(
                    "{}.{}",
                    main_domain.to_lowercase(),
                    extract.suffix.unwrap_or_default()
                ))
            } else {
                // Domain not present in the URL, return an error
                Err(anyhow::anyhow!("Failed to extract domain from {}", url))
            }
        })
}

async fn handle_response(
    response: reqwest::Response,
    url: &str,
    pool: &SqlitePool,
    extractor: &TldExtractor,
    error_stats: &ErrorStats,
    elapsed: f64,
) -> Result<(), Error> {
    let (tls_version, subject, issuer, valid_from, valid_to, oids) = if url.starts_with("https://") {
        match extract_domain(&extractor, url) {
            Ok(domain) => match get_ssl_certificate_info(domain.clone()).await {
                Ok(cert_info) => (cert_info.tls_version, cert_info.subject, cert_info.issuer, cert_info.valid_from, cert_info.valid_to, cert_info.oids),
                Err(e) => {
                    error!("Failed to get SSL certificate info for {}: {}", domain, e);
                    (None, None, None, None, None, None)
                }
            },
            Err(_) => (None, None, None, None, None, None),
        }
    } else {
        (None, None, None, None, None, None)
    };

    let headers = response.headers().clone();
    let final_url = response.url().to_string();
    let status = response.status();
    let status_desc = status.canonical_reason().unwrap_or_else(|| "Unknown Status Code");

    let body = response.text().await.unwrap_or_default();

    let title = extract_title(&body, error_stats);
    let keywords = extract_meta_keywords(&body, error_stats);
    let keywords_str = keywords.map(|kw| kw.join(", "));
    let description = extract_meta_description(&body, error_stats);

    let linkedin_slug = extract_linkedin_slug(&body, error_stats);

    let initial_domain = extract_domain(&extractor, url)?;
    let final_domain = extract_domain(&extractor, &final_url)?;

    let url = Url::parse(&final_url)?;
    let host = url.host_str().ok_or_else(|| anyhow::Error::msg("Failed to extract host"))?;
    let ip_address = resolve_host_to_ip(host).await?;
    let reverse_dns_name = reverse_dns_lookup(&ip_address).await?;

    let security_headers = extract_security_headers(&headers);
    let security_headers_json = serde_json::to_string(&security_headers).unwrap_or_else(|_| "{}".to_string());

    let timestamp = chrono::Utc::now().timestamp_millis();

    log::debug!("Preparing to insert record for URL: {}", url);

    update_database(
        &initial_domain,
        &final_domain,
        &ip_address,
        &reverse_dns_name,
        &status,
        status_desc,
        elapsed,
        &title,
        keywords_str.as_deref(),
        description.as_deref(),
        linkedin_slug.as_deref(),
        &security_headers_json,
        timestamp,
        &tls_version,
        &subject,
        &issuer,
        valid_from,
        valid_to,
        oids,
        pool
    ).await.map_err(|e| anyhow::anyhow!(e))?;

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

    headers_list.iter().filter_map(|&header_name| {
        headers.get(header_name).map(|value| {
            (header_name.to_string(), value.to_str().unwrap_or_default().to_string())
        })
    }).collect()
}

async fn handle_http_request(
    client: &reqwest::Client,
    url: &str,
    pool: &SqlitePool,
    extractor: &TldExtractor,
    error_stats: &ErrorStats,
    start_time: std::time::Instant,
) -> Result<(), Error> {
    let res = client.get(url).send().await;

    let elapsed = start_time.elapsed().as_secs_f64();

    let response = match res {
        Ok(response) => response,
        Err(e) => {
            update_error_stats(error_stats, &e).await;
            return Err(e.into());
        }
    };

    handle_response(response, url, pool, extractor, error_stats, elapsed).await
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
    let meta_keywords = parsed_html.select(&META_KEYWORDS_SELECTOR).next()
        .and_then(|element| element.value().attr("content"));

    match meta_keywords {
        Some(content) => {
            let keywords: Vec<String> = content.split(',')
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
        },
        None => {
            // No keywords meta tag found
            error_stats.increment(ErrorType::KeywordExtractError);
            None
        }
    }
}

fn extract_meta_description(html: &str, error_stats: &ErrorStats) -> Option<String> {
    let parsed_html = Html::parse_document(html);
    let meta_description = parsed_html.select(&META_DESCRIPTION_SELECTOR).next()
        .and_then(|element| element.value().attr("content").map(|content| content.trim().to_string()));

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

struct CertificateInfo {
    tls_version: Option<String>,
    subject: Option<String>,
    issuer: Option<String>,
    valid_from: Option<chrono::NaiveDateTime>,
    valid_to: Option<chrono::NaiveDateTime>,
    oids: Option<String>
}

fn extract_certificate_policies(cert: &x509_parser::certificate::X509Certificate<'_>) -> Result<Vec<String>, anyhow::Error> {
    let mut oids: Vec<String> = Vec::new();

    for ext in cert.extensions() {
        // Dereference the result from parsed_extension()
        match *ext.parsed_extension() {
            // Now match against the ParsedExtension variants directly
            ParsedExtension::CertificatePolicies(ref policies) => {
                // Now we can iterate over the policies
                oids.extend(policies.iter().map(|policy| policy.policy_id.to_string()));
            },
            // Ignore other cases; we only care about CertificatePolicies
            _ => {}
        }
    }
    Ok(oids)
}

async fn resolve_host_to_ip(host: &str) -> Result<String, Error> {
    // Create the resolver
    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .map_err(|e| Error::new(e))?;

    // Perform the DNS query asynchronously
    let response = resolver.lookup_ip(host).await
        .map_err(|e| Error::new(e))?;

    // Extract the first IP address from the response
    let ip = response.iter().next()
        .ok_or_else(|| Error::msg("No IP addresses found"))?
        .to_string();

    Ok(ip)
}

async fn reverse_dns_lookup(ip: &str) -> Result<Option<String>, Error> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf().map_err(Error::new)?;

    let response = resolver.reverse_lookup(ip.parse()?).await.map_err(Error::new)?;

    // Take the first name found; there could be multiple names.
    let name = response.iter().next().map(|name| name.to_utf8());

    Ok(name)
}


async fn get_ssl_certificate_info(domain: String) -> Result<CertificateInfo, anyhow::Error> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
    );

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = ServerName::try_from(domain.clone())
        .with_context(|| format!("Invalid domain name: {}", domain))?;

    let sock = TcpStream::connect((domain.clone(), 443)).await
        .with_context(|| format!("Failed to connect to {}:443", domain))?;

    let connector = TlsConnector::from(Arc::new(config));

    let mut tls_stream = connector.connect(server_name, sock).await
        .with_context(|| "TLS connection failed")?;

    let tls_version = tls_stream.get_ref().1.protocol_version()
        .map(|v| format!("{:?}", v)) // Convert the version enum to a string
        .unwrap_or_else(|| "Unknown".to_string());

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: close\r\n\
         Accept-Encoding: identity\r\n\
         \r\n",
        domain
    );

    tls_stream.write_all(request.as_bytes()).await?;

    let serialized_oids;

    if let Some(certs) = tls_stream.get_ref().1.peer_certificates() {
        if let Some(cert) = certs.first() {
            let (_, cert) = x509_parser::parse_x509_certificate(cert.as_ref())?;
            let tbs_cert = &cert.tbs_certificate;

            let subject = cert.tbs_certificate.subject.to_string();
            let issuer = cert.tbs_certificate.issuer.to_string();

            let oids = extract_certificate_policies(&cert);
            match oids {
                Ok(oids) => {
                    let unique_oids: HashSet<String> = oids.into_iter().collect(); // De-duplication
                    serialized_oids = serde_json::to_string(&unique_oids)?;
                },
                Err(e) => return Err(e),
            }

            let valid_from_str = tbs_cert.validity.not_before.to_rfc2822()
                .map_err(|e| anyhow::anyhow!("RFC2822 conversion error for not_before: {}", e))?;

            let valid_from = chrono::NaiveDateTime::parse_from_str(&valid_from_str, "%a, %d %b %Y %H:%M:%S %z")
                .map_err(|_| anyhow::anyhow!("Failed to parse not_before"))?;

            let valid_to_str = tbs_cert.validity.not_after.to_rfc2822()
                .map_err(|e| anyhow::anyhow!("RFC2822 conversion error for not_after: {}", e))?;

            let valid_to = chrono::NaiveDateTime::parse_from_str(&valid_to_str, "%a, %d %b %Y %H:%M:%S %z")
                .map_err(|_| anyhow::anyhow!("Failed to parse not_after"))?;

            info!("Domain: {:?}; OIDs: {}", domain, serialized_oids);

            return Ok(CertificateInfo {
                tls_version: Some(tls_version),
                subject:Some(subject),
                issuer: Some(issuer),
                valid_from: Some(valid_from),
                valid_to: Some(valid_to),
                oids: Some(serialized_oids),
            });
        }
    }

    Err(anyhow::anyhow!("Failed to retrieve certificate information for {}", domain))

}

pub async fn process_url(
    url: String,
    client: Arc<reqwest::Client>,
    pool: Arc<SqlitePool>,
    extractor: Arc<TldExtractor>,
    error_stats: Arc<ErrorStats>,
) {
    let retry_strategy = get_retry_strategy();
    let start_time = std::time::Instant::now();

    let future = tokio_retry::Retry::spawn(retry_strategy, || {
        let client = client.clone();
        let url = url.clone();
        let pool = pool.clone();
        let extractor = extractor.clone();
        let error_stats = error_stats.clone();

        tokio::task::spawn(async move {
            handle_http_request(&*client, &url, &*pool, &*extractor, &error_stats, start_time).await
        })
    });

    match future.await {
        Ok(_) => {}
        Err(e) => error!("Error after retries: {}", e),
    }
}
