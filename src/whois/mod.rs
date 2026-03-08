//! WHOIS/RDAP domain lookup using whois-service crate

mod cache;
mod parse;
mod types;

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::time::Duration;

use whois_service::WhoisClient;

pub use types::WhoisResult;

use cache::WhoisCacheStore;
use parse::{convert_parsed_data, enrich_result_from_raw_text};

/// Default cache directory for WHOIS data
const DEFAULT_CACHE_DIR: &str = ".whois_cache";

/// Performs a WHOIS lookup for a domain
///
/// This function uses the `whois-service` crate which:
/// - Automatically tries RDAP first, then falls back to WHOIS
/// - Handles IANA bootstrap for TLD discovery
/// - Implements per-server rate limiting
/// - Provides structured parsing
///
/// # Arguments
///
/// * `domain` - The domain to look up (e.g., "example.com")
/// * `cache_dir` - Optional cache directory for storing WHOIS data
///
/// # Returns
///
/// Returns WHOIS information if available, or None if lookup fails
///
/// `None` is not limited to "domain not found". It also covers timeouts,
/// backend failures, and other best-effort lookup failures.
///
/// # Examples
///
/// ```no_run
/// use domain_status::lookup_whois;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// if let Some(result) = lookup_whois("example.com", None).await? {
///     println!("{:?}", result.registrar);
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Errors
/// Returns `Err` when the WHOIS client cannot be created or the lookup fails.
pub async fn lookup_whois(domain: &str, cache_dir: Option<&Path>) -> Result<Option<WhoisResult>> {
    lookup_whois_with_lookup(domain, cache_dir, |lookup_domain| {
        let domain = lookup_domain.to_string();
        async move {
            let client = WhoisClient::new()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to create WHOIS client: {}", e))?;
            client.lookup(&domain).await.map_err(anyhow::Error::from)
        }
    })
    .await
}

async fn lookup_whois_with_lookup<F, Fut>(
    domain: &str,
    cache_dir: Option<&Path>,
    lookup: F,
) -> Result<Option<WhoisResult>>
where
    F: FnOnce(&str) -> Fut,
    Fut: std::future::Future<Output = Result<whois_service::WhoisResponse>>,
{
    let cache_path = cache_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CACHE_DIR));
    let cache = WhoisCacheStore::default();

    if let Some(cached) = cache.load(&cache_path, domain).await? {
        log::debug!("WHOIS cache hit for {}", domain);
        let result = enrich_result_from_raw_text(WhoisResult::from(cached.result));
        return Ok(Some(result));
    }

    log::info!("Starting WHOIS lookup for domain: {}", domain);
    match tokio::time::timeout(
        Duration::from_secs(crate::config::WHOIS_TIMEOUT_SECS),
        lookup(domain),
    )
    .await
    {
        Ok(response) => {
            let response = match response {
                Ok(response) => response,
                Err(e) => {
                    log::warn!("WHOIS lookup failed for {}: {}", domain, e);
                    return Ok(None);
                }
            };
            log::debug!("WHOIS lookup successful for {}", domain);
            let result = convert_parsed_data(&response);

            cache.save(&cache_path, domain, &result).await?;

            Ok(Some(result))
        }
        Err(_) => {
            log::warn!(
                "WHOIS lookup timed out for {} after {}s",
                domain,
                crate::config::WHOIS_TIMEOUT_SECS
            );
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tempfile::TempDir;
    use whois_service::{ParsedWhoisData, WhoisResponse};

    fn fake_response() -> WhoisResponse {
        WhoisResponse {
            domain: "example.com".to_string(),
            whois_server: "whois.example.com".to_string(),
            raw_data: "Registrant Organization: Example Org\nRegistrant Country: US\nraw whois"
                .to_string(),
            parsed_data: Some(ParsedWhoisData {
                registrar: Some("Example Registrar".to_string()),
                creation_date: Some("2024-01-15T10:30:45Z".to_string()),
                expiration_date: None,
                updated_date: None,
                name_servers: vec!["ns1.example.com".to_string()],
                status: vec!["clientTransferProhibited".to_string()],
                registrant_name: Some("Example Org".to_string()),
                registrant_email: None,
                admin_email: None,
                tech_email: None,
                created_ago: None,
                updated_ago: None,
                expires_in: None,
            }),
            cached: false,
            query_time_ms: 25,
            parsing_analysis: None,
        }
    }

    #[tokio::test]
    async fn test_lookup_whois_caches_first_lookup_and_hits_cache_next_time() {
        let temp_dir = TempDir::new().expect("temp dir");
        let calls = Arc::new(AtomicUsize::new(0));

        let first = lookup_whois_with_lookup("example.com", Some(temp_dir.path()), {
            let calls = Arc::clone(&calls);
            move |_| {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(fake_response())
                }
            }
        })
        .await
        .expect("lookup should succeed");

        let second = lookup_whois_with_lookup("example.com", Some(temp_dir.path()), {
            let calls = Arc::clone(&calls);
            move |_| {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(fake_response())
                }
            }
        })
        .await
        .expect("cached lookup should succeed");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let first = first.expect("first result");
        let second = second.expect("second result");
        assert_eq!(first.registrar.as_deref(), Some("Example Registrar"));
        assert_eq!(second.registrar.as_deref(), Some("Example Registrar"));
        assert_eq!(first.registrant_org.as_deref(), Some("Example Org"));
        assert_eq!(second.registrant_country.as_deref(), Some("US"));
    }

    #[tokio::test]
    async fn test_lookup_whois_returns_none_on_backend_error() {
        let temp_dir = TempDir::new().expect("temp dir");
        let result = lookup_whois_with_lookup("example.com", Some(temp_dir.path()), |_| async {
            Err(anyhow::anyhow!("backend failure"))
        })
        .await
        .expect("lookup wrapper should not fail");

        assert!(result.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn test_lookup_whois_returns_none_on_timeout() {
        let temp_dir = TempDir::new().expect("temp dir");
        let lookup = lookup_whois_with_lookup("example.com", Some(temp_dir.path()), |_| async {
            tokio::time::sleep(Duration::from_secs(crate::config::WHOIS_TIMEOUT_SECS + 1)).await;
            Ok(fake_response())
        });

        tokio::pin!(lookup);
        tokio::time::advance(Duration::from_secs(crate::config::WHOIS_TIMEOUT_SECS + 1)).await;

        let result = lookup.await.expect("wrapper should not fail");
        assert!(result.is_none());
    }
}
