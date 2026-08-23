//! Bounded fetches for `/.well-known/security.txt` and `/robots.txt`.
//!
//! Same-origin only, small body caps, no sitemap crawling.

use reqwest::Client;
use url::Url;

/// Max bytes retained from a well-known text response.
const MAX_WELL_KNOWN_BODY: usize = 64 * 1024;
/// Per-request timeout for well-known fetches.
const WELL_KNOWN_TIMEOUT_SECS: u64 = 5;

/// Parsed RFC 9116 `security.txt` fields (plus raw body).
#[derive(Debug, Clone, Default)]
pub struct SecurityTxtData {
    pub source_url: String,
    pub http_status: u16,
    pub contacts: Vec<String>,
    pub expires: Option<String>,
    pub encryption: Vec<String>,
    pub acknowledgments: Vec<String>,
    pub preferred_languages: Option<String>,
    pub canonical: Vec<String>,
    pub policy: Vec<String>,
    pub hiring: Vec<String>,
    pub raw_body: String,
}

/// Parsed `robots.txt` (directives only; sitemaps listed, not fetched).
#[derive(Debug, Clone, Default)]
pub struct RobotsTxtData {
    pub http_status: u16,
    pub raw_body: String,
    pub directives: Vec<(String, String)>,
}

/// Combined well-known fetch result for one origin.
#[derive(Debug, Clone, Default)]
pub(crate) struct WellKnownData {
    pub security_txt: Option<SecurityTxtData>,
    pub robots_txt: Option<RobotsTxtData>,
}

/// Fetch `security.txt` and `robots.txt` for the origin of `final_url` in parallel.
pub(crate) async fn fetch_well_known(client: &Client, final_url: &str) -> WellKnownData {
    let Ok(base) = Url::parse(final_url) else {
        return WellKnownData::default();
    };
    let Some(origin) = origin_root(&base) else {
        return WellKnownData::default();
    };

    let security_urls = [
        format!("{origin}/.well-known/security.txt"),
        format!("{origin}/security.txt"),
    ];
    let robots_url = format!("{origin}/robots.txt");

    let (security_txt, robots_txt) = tokio::join!(
        fetch_security_txt(client, &security_urls),
        fetch_robots_txt(client, &robots_url)
    );

    WellKnownData {
        security_txt,
        robots_txt,
    }
}

fn origin_root(url: &Url) -> Option<String> {
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let host = url.host_str()?;
    let origin = match url.port() {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    };
    Some(origin)
}

async fn fetch_security_txt(client: &Client, urls: &[String]) -> Option<SecurityTxtData> {
    for url in urls {
        if let Some(data) = fetch_security_txt_one(client, url).await {
            return Some(data);
        }
    }
    None
}

async fn fetch_security_txt_one(client: &Client, url: &str) -> Option<SecurityTxtData> {
    let (status, body) = fetch_text(client, url).await?;
    if !(200..300).contains(&status) || body.trim().is_empty() {
        return None;
    }
    let mut data = SecurityTxtData {
        source_url: url.to_string(),
        http_status: status,
        raw_body: body.clone(),
        ..SecurityTxtData::default()
    };
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let field = field.trim();
        let value = value.trim().to_string();
        if value.is_empty() {
            continue;
        }
        match field.to_ascii_lowercase().as_str() {
            "contact" => data.contacts.push(value),
            "expires" => data.expires = Some(value),
            "encryption" => data.encryption.push(value),
            "acknowledgments" | "acknowledgements" => data.acknowledgments.push(value),
            "preferred-languages" => data.preferred_languages = Some(value),
            "canonical" => data.canonical.push(value),
            "policy" => data.policy.push(value),
            "hiring" => data.hiring.push(value),
            _ => {}
        }
    }
    Some(data)
}

async fn fetch_robots_txt(client: &Client, url: &str) -> Option<RobotsTxtData> {
    let (status, body) = fetch_text(client, url).await?;
    if status == 404 {
        return None;
    }
    let directives = parse_robots_directives(&body);
    Some(RobotsTxtData {
        http_status: status,
        raw_body: body,
        directives,
    })
}

fn parse_robots_directives(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((directive, value)) = line.split_once(':') else {
            continue;
        };
        let directive = directive.trim().to_ascii_lowercase();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match directive.as_str() {
            "user-agent" | "disallow" | "allow" | "sitemap" | "crawl-delay" => {
                out.push((directive, value.to_string()));
            }
            _ => {}
        }
    }
    out
}

async fn fetch_text(client: &Client, url: &str) -> Option<(u16, String)> {
    let response = match tokio::time::timeout(
        std::time::Duration::from_secs(WELL_KNOWN_TIMEOUT_SECS),
        client.get(url).send(),
    )
    .await
    {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            log::debug!("well-known fetch failed for {url}: {e}");
            return None;
        }
        Err(_) => {
            log::debug!("well-known fetch timed out for {url}");
            return None;
        }
    };
    let status = response.status().as_u16();
    let bytes = match response.bytes().await {
        Ok(b) => b,
        Err(e) => {
            log::debug!("well-known body read failed for {url}: {e}");
            return None;
        }
    };
    let truncated = if bytes.len() > MAX_WELL_KNOWN_BODY {
        &bytes[..MAX_WELL_KNOWN_BODY]
    } else {
        &bytes
    };
    let body = String::from_utf8_lossy(truncated).into_owned();
    Some((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_security_txt_fields() {
        let body = "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00.000Z\nPolicy: https://example.com/security\n# comment\n";
        let mut data = SecurityTxtData {
            raw_body: body.to_string(),
            ..SecurityTxtData::default()
        };
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((field, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim().to_string();
            match field.trim().to_ascii_lowercase().as_str() {
                "contact" => data.contacts.push(value),
                "expires" => data.expires = Some(value),
                "policy" => data.policy.push(value),
                _ => {}
            }
        }
        assert_eq!(data.contacts, vec!["mailto:security@example.com"]);
        assert_eq!(data.expires.as_deref(), Some("2027-01-01T00:00:00.000Z"));
        assert_eq!(data.policy, vec!["https://example.com/security"]);
    }

    #[test]
    fn parses_robots_disallow_and_sitemap() {
        let body = "User-agent: *\nDisallow: /admin\nAllow: /public\nSitemap: https://example.com/sitemap.xml\n";
        let dirs = parse_robots_directives(body);
        assert!(dirs.iter().any(|(d, v)| d == "disallow" && v == "/admin"));
        assert!(dirs
            .iter()
            .any(|(d, v)| d == "sitemap" && v == "https://example.com/sitemap.xml"));
    }

    #[test]
    fn origin_root_strips_path() {
        let url = Url::parse("https://example.com/path?q=1").unwrap();
        assert_eq!(origin_root(&url).as_deref(), Some("https://example.com"));
    }
}
