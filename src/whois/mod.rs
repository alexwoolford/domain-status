//! WHOIS/RDAP domain lookup using whois-service crate

mod cache;
mod parse;
mod types;

use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use whois_service::{LookupStatus, WhoisClient};

pub use types::WhoisResult;

use cache::WhoisCacheStore;
use parse::{convert_parsed_data, enrich_result_from_raw_text};

/// Process-wide WHOIS/RDAP client (IANA bootstrap once, in-process cache + coalescing).
pub(crate) type SharedWhoisClient = Arc<WhoisClient>;

/// Build the shared scan client. Failures are best-effort (ADR 0002).
pub(crate) async fn init_shared_client() -> Result<SharedWhoisClient> {
    WhoisClient::new()
        .await
        .map(Arc::new)
        .map_err(|e| anyhow::anyhow!("Failed to create WHOIS client: {e}"))
}

fn whois_result_is_usable(result: &WhoisResult) -> bool {
    result.registrar.as_deref().is_some_and(|s| !s.is_empty())
        || result
            .raw_text
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
}

/// Vendor `LookupStatus` is the cache gate: rate-limit banners must not look like a 7-day hit.
fn lookup_status_is_cacheable(status: LookupStatus, domain: &str) -> bool {
    match status {
        LookupStatus::Found => true,
        LookupStatus::RateLimited => {
            log::warn!("WHOIS rate-limited for {domain}; not caching");
            false
        }
        LookupStatus::NotFound => {
            log::debug!("WHOIS not found for {domain}");
            false
        }
    }
}

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
    lookup_whois_with_client(domain, cache_dir, None).await
}

/// Scan-path lookup using the process-wide client when one was built at init.
pub(crate) async fn lookup_whois_with_client(
    domain: &str,
    cache_dir: Option<&Path>,
    client: Option<&WhoisClient>,
) -> Result<Option<WhoisResult>> {
    let existing = client.cloned();
    lookup_whois_with_lookup(domain, cache_dir, move |lookup_domain| {
        let domain = lookup_domain.to_string();
        async move {
            let client = match existing {
                Some(client) => client,
                None => WhoisClient::new()
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to create WHOIS client: {e}"))?,
            };
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
    let cache_path = cache_dir.map_or_else(
        || crate::cache_paths::whois_dir(&crate::cache_paths::resolve_cache_root(None)),
        std::path::Path::to_path_buf,
    );
    let cache = WhoisCacheStore::default();

    if let Some(cached) = cache.load(&cache_path, domain).await? {
        let result = enrich_result_from_raw_text(WhoisResult::from(cached.result));
        if whois_result_is_usable(&result) {
            log::debug!("WHOIS cache hit for {domain}");
            return Ok(Some(result));
        }
        log::warn!("Ignoring empty cached WHOIS for {domain}");
    }

    log::debug!("Starting WHOIS lookup for domain: {domain}");
    if let Ok(response) = tokio::time::timeout(
        Duration::from_secs(crate::config::WHOIS_TIMEOUT_SECS),
        lookup(domain),
    )
    .await
    {
        let response = match response {
            Ok(response) => response,
            Err(e) => {
                log::warn!("WHOIS lookup failed for {domain}: {e}");
                return Ok(None);
            }
        };
        if !lookup_status_is_cacheable(response.lookup_status, domain) {
            return Ok(None);
        }

        log::debug!("WHOIS lookup successful for {domain}");
        let result = convert_parsed_data(&response);
        if !whois_result_is_usable(&result) {
            log::warn!(
                "WHOIS lookup returned no usable fields for {domain}; not caching empty result"
            );
            return Ok(None);
        }

        cache.save(&cache_path, domain, &result).await?;

        Ok(Some(result))
    } else {
        log::warn!(
            "WHOIS lookup timed out for {} after {}s",
            domain,
            crate::config::WHOIS_TIMEOUT_SECS
        );
        Ok(None)
    }
}

/// Persist a WHOIS cache entry so tests can exercise `enable_whois` without the network.
///
/// `cache_dir` is the WHOIS cache directory (the `whois/` subdirectory of the scan cache root).
///
/// # Errors
///
/// Returns an error if the cache directory cannot be created or the entry cannot be written.
#[cfg(any(test, feature = "test-utils"))]
pub async fn seed_whois_cache(cache_dir: &Path, domain: &str, result: &WhoisResult) -> Result<()> {
    WhoisCacheStore::default()
        .save(cache_dir, domain, result)
        .await
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
            lookup_status: LookupStatus::Found,
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

    fn empty_response() -> WhoisResponse {
        WhoisResponse {
            domain: "empty.example".to_string(),
            whois_server: "whois.example.com".to_string(),
            raw_data: String::new(),
            parsed_data: None,
            lookup_status: LookupStatus::Found,
            cached: false,
            query_time_ms: 1,
            parsing_analysis: None,
        }
    }

    #[tokio::test]
    async fn test_lookup_whois_does_not_cache_empty_payload() {
        let temp_dir = TempDir::new().expect("temp dir");
        let calls = Arc::new(AtomicUsize::new(0));

        let first = lookup_whois_with_lookup("empty.example", Some(temp_dir.path()), {
            let calls = Arc::clone(&calls);
            move |_| {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(empty_response())
                }
            }
        })
        .await
        .expect("lookup wrapper should not fail");
        assert!(first.is_none());

        let second = lookup_whois_with_lookup("empty.example", Some(temp_dir.path()), {
            let calls = Arc::clone(&calls);
            move |_| {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(empty_response())
                }
            }
        })
        .await
        .expect("second lookup should not use an empty cache entry");

        assert!(second.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    fn rate_limited_response() -> WhoisResponse {
        WhoisResponse {
            domain: "throttled.example".to_string(),
            whois_server: "whois.example.com".to_string(),
            raw_data: "Number of allowed queries exceeded.".to_string(),
            parsed_data: Some(ParsedWhoisData {
                registrar: Some("Example Registrar".to_string()),
                ..Default::default()
            }),
            lookup_status: LookupStatus::RateLimited,
            cached: false,
            query_time_ms: 1,
            parsing_analysis: None,
        }
    }

    fn not_found_response() -> WhoisResponse {
        WhoisResponse {
            domain: "missing.example".to_string(),
            whois_server: "RDAP: https://rdap.example.com".to_string(),
            raw_data: "Domain not found".to_string(),
            parsed_data: None,
            lookup_status: LookupStatus::NotFound,
            cached: false,
            query_time_ms: 1,
            parsing_analysis: None,
        }
    }

    #[tokio::test]
    async fn test_lookup_whois_does_not_cache_rate_limited() {
        let temp_dir = TempDir::new().expect("temp dir");
        let calls = Arc::new(AtomicUsize::new(0));

        let first = lookup_whois_with_lookup("throttled.example", Some(temp_dir.path()), {
            let calls = Arc::clone(&calls);
            move |_| {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(rate_limited_response())
                }
            }
        })
        .await
        .expect("lookup wrapper should not fail");
        assert!(first.is_none());

        let second = lookup_whois_with_lookup("throttled.example", Some(temp_dir.path()), {
            let calls = Arc::clone(&calls);
            move |_| {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(rate_limited_response())
                }
            }
        })
        .await
        .expect("rate-limited result must not be disk-cached");

        assert!(second.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_lookup_whois_returns_none_on_not_found() {
        let temp_dir = TempDir::new().expect("temp dir");
        let calls = Arc::new(AtomicUsize::new(0));

        let first = lookup_whois_with_lookup("missing.example", Some(temp_dir.path()), {
            let calls = Arc::clone(&calls);
            move |_| {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(not_found_response())
                }
            }
        })
        .await
        .expect("lookup wrapper should not fail");
        assert!(first.is_none());

        let second = lookup_whois_with_lookup("missing.example", Some(temp_dir.path()), {
            let calls = Arc::clone(&calls);
            move |_| {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(not_found_response())
                }
            }
        })
        .await
        .expect("not-found result must not be disk-cached");

        assert!(second.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
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
