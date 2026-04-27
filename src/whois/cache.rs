//! WHOIS cache management.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use crate::clock::{Clock, SystemClock};

/// Process-wide count of WHOIS cache saves. Used to skip the full directory scan
/// when the cache is below the limit (common case).
static WHOIS_SAVE_COUNT: AtomicUsize = AtomicUsize::new(0);

use super::types::{WhoisCacheEntry, WhoisResult};

/// Default cache TTL: 7 days (WHOIS data changes infrequently)
pub(crate) const CACHE_TTL_SECS: u64 = crate::config::WHOIS_CACHE_TTL_SECS;

/// When over the entry limit, run the full directory-scan eviction at most every N saves.
/// This avoids an O(N²) I/O bomb where every save after the limit triggered a scan.
const ENFORCE_INTERVAL_WHEN_OVER_LIMIT: usize = 1000;

/// Cache store with injectable time source for deterministic tests.
pub(crate) struct WhoisCacheStore<C = SystemClock> {
    clock: C,
    max_entries: usize,
}

impl Default for WhoisCacheStore<SystemClock> {
    fn default() -> Self {
        Self::new(SystemClock, crate::config::MAX_WHOIS_CACHE_ENTRIES)
    }
}

impl<C: Clock> WhoisCacheStore<C> {
    pub(crate) fn new(clock: C, max_entries: usize) -> Self {
        Self { clock, max_entries }
    }

    fn cache_file(cache_path: &Path, domain: &str) -> PathBuf {
        cache_path.join(format!("{}.json", domain.replace('.', "_")))
    }

    pub(crate) async fn load(
        &self,
        cache_path: &Path,
        domain: &str,
    ) -> Result<Option<WhoisCacheEntry>> {
        let cache_file = Self::cache_file(cache_path, domain);
        // Distinguish "file doesn't exist" (cache miss, return Ok(None)) from "I/O
        // error checking existence" (e.g. permission denied on the cache dir).
        // The previous `unwrap_or(false)` collapsed both cases into a cache miss,
        // hiding transient failures and bypassing the cache without any signal.
        match tokio::fs::try_exists(&cache_file).await {
            Ok(true) => {}
            Ok(false) => return Ok(None),
            Err(e) => {
                // I/O error: warn and treat as a miss so the scan still progresses,
                // but the operator gets a log entry to investigate.
                log::warn!(
                    "Failed to check WHOIS cache file existence for {} ({}): {e}; treating as cache miss",
                    cache_file.display(),
                    domain
                );
                return Ok(None);
            }
        }

        let metadata = tokio::fs::metadata(&cache_file)
            .await
            .context("Failed to stat cache file")?;
        if metadata.len() > crate::config::MAX_WHOIS_CACHE_FILE_SIZE {
            log::warn!(
                "Skipping oversized WHOIS cache file {} ({} bytes, max: {} bytes)",
                cache_file.display(),
                metadata.len(),
                crate::config::MAX_WHOIS_CACHE_FILE_SIZE
            );
            if let Err(e) = tokio::fs::remove_file(&cache_file).await {
                log::debug!(
                    "Failed to remove oversized WHOIS cache file {}: {}",
                    cache_file.display(),
                    e
                );
            }
            return Ok(None);
        }

        let content = tokio::fs::read_to_string(&cache_file)
            .await
            .context("Failed to read cache file")?;
        let entry: WhoisCacheEntry =
            serde_json::from_str(&content).context("Failed to parse cache file")?;

        let age = self
            .clock
            .now()
            .duration_since(entry.cached_at)
            .unwrap_or_default();
        if age.as_secs() > CACHE_TTL_SECS {
            if let Err(e) = tokio::fs::remove_file(&cache_file).await {
                log::debug!(
                    "Failed to remove expired WHOIS cache file {}: {}",
                    cache_file.display(),
                    e
                );
            }
            return Ok(None);
        }

        Ok(Some(entry))
    }

    pub(crate) async fn save(
        &self,
        cache_path: &Path,
        domain: &str,
        result: &WhoisResult,
    ) -> Result<()> {
        tokio::fs::create_dir_all(cache_path)
            .await
            .context("Failed to create cache directory")?;

        let cache_file = Self::cache_file(cache_path, domain);
        let entry = WhoisCacheEntry {
            result: result.into(),
            cached_at: self.clock.now(),
            domain: domain.to_string(),
        };

        let content =
            serde_json::to_string_pretty(&entry).context("Failed to serialize cache entry")?;
        tokio::fs::write(&cache_file, content)
            .await
            .context("Failed to write cache file")?;

        let mut count = WHOIS_SAVE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        // On first save, seed the counter with the actual number of existing cache files
        // so the quota isn't bypassed after a restart with a pre-populated cache directory.
        if count == 1 {
            let existing = std::fs::read_dir(cache_path)
                .map(|rd| rd.flatten().count())
                .unwrap_or(0);
            if existing > 1 {
                // Set the counter to existing count (atomic, so other threads see it too)
                WHOIS_SAVE_COUNT.store(existing, Ordering::Relaxed);
                count = existing;
            }
        }
        let over_limit = count >= self.max_entries;
        let first_time_over = over_limit && count.saturating_sub(self.max_entries) <= 1;
        let interval_hit = over_limit
            && count > self.max_entries
            && (count - self.max_entries - 1) % ENFORCE_INTERVAL_WHEN_OVER_LIMIT == 0;
        let should_enforce = count == 1 || first_time_over || interval_hit;
        if should_enforce {
            self.enforce_cache_limit(cache_path).await?;
        }
        Ok(())
    }

    async fn enforce_cache_limit(&self, cache_path: &Path) -> Result<()> {
        let cache_path_owned = cache_path.to_path_buf();
        let mut entries =
            tokio::task::spawn_blocking(move || -> Result<Vec<(PathBuf, SystemTime)>> {
                let mut files = Vec::new();
                let dir = std::fs::read_dir(&cache_path_owned)
                    .context("Failed to read cache directory")?;

                for entry in dir.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|ext| ext == "json") {
                        let modified = entry
                            .metadata()
                            .ok()
                            .and_then(|metadata| metadata.modified().ok())
                            .unwrap_or(SystemTime::UNIX_EPOCH);
                        files.push((path, modified));
                    }
                }

                Ok(files)
            })
            .await
            .context("Blocking task panicked")??;

        if entries.len() <= self.max_entries {
            return Ok(());
        }

        entries.sort_by_key(|(_, modified)| *modified);
        let to_delete = entries.len() - self.max_entries;
        for (path, _) in entries.into_iter().take(to_delete) {
            if let Err(e) = tokio::fs::remove_file(&path).await {
                log::debug!("Failed to evict WHOIS cache file {}: {}", path.display(), e);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};
    use tempfile::TempDir;

    #[derive(Clone)]
    struct TestClock {
        now: Arc<Mutex<SystemTime>>,
    }

    impl TestClock {
        fn new(now: SystemTime) -> Self {
            Self {
                now: Arc::new(Mutex::new(now)),
            }
        }

        fn set(&self, now: SystemTime) {
            *self.now.lock().expect("clock lock") = now;
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> SystemTime {
            *self.now.lock().expect("clock lock")
        }
    }

    fn create_test_whois_result() -> WhoisResult {
        WhoisResult {
            creation_date: Some(chrono::Utc::now()),
            expiration_date: Some(chrono::Utc::now() + chrono::Duration::days(365)),
            updated_date: Some(chrono::Utc::now()),
            registrar: Some("Test Registrar".to_string()),
            registrant_country: Some("US".to_string()),
            registrant_org: Some("Test Org".to_string()),
            status: vec!["clientTransferProhibited".to_string()],
            nameservers: vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()],
            raw_text: Some("Raw WHOIS text".to_string()),
        }
    }

    #[tokio::test]
    async fn test_save_to_cache() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";
        let result = create_test_whois_result();
        let store = WhoisCacheStore::new(TestClock::new(SystemTime::UNIX_EPOCH), 10);

        assert!(store.save(cache_path, domain, &result).await.is_ok());

        let cache_file = cache_path.join("example_com.json");
        assert!(cache_file.exists(), "Cache file should be created");
    }

    #[tokio::test]
    async fn test_load_from_cache_not_found() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let store = WhoisCacheStore::new(TestClock::new(SystemTime::UNIX_EPOCH), 10);

        let result = store
            .load(cache_path, "nonexistent.com")
            .await
            .expect("Should not error");
        assert!(
            result.is_none(),
            "Should return None for non-existent cache"
        );
    }

    #[tokio::test]
    async fn test_load_from_cache_found() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";
        let result = create_test_whois_result();
        let clock = TestClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(10));
        let store = WhoisCacheStore::new(clock.clone(), 10);

        store
            .save(cache_path, domain, &result)
            .await
            .expect("Should save to cache");

        let cached = store
            .load(cache_path, domain)
            .await
            .expect("Should load from cache");
        assert!(cached.is_some(), "Should find cached entry");

        let entry = cached.unwrap();
        assert_eq!(entry.domain, domain);

        // Convert to WhoisResult to verify data integrity
        let whois_result: WhoisResult = entry.result.into();
        assert!(whois_result.creation_date.is_some());
        assert_eq!(whois_result.registrar, Some("Test Registrar".to_string()));
    }

    #[tokio::test]
    async fn test_load_from_cache_expired() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";
        let result = create_test_whois_result();
        let clock = TestClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(1));
        let store = WhoisCacheStore::new(clock.clone(), 10);

        store
            .save(cache_path, domain, &result)
            .await
            .expect("Should save to cache");
        clock.set(SystemTime::UNIX_EPOCH + Duration::from_secs(CACHE_TTL_SECS + 2));

        let cached = store
            .load(cache_path, domain)
            .await
            .expect("Should handle expired cache");
        assert!(cached.is_none(), "Should return None for expired cache");
        let cache_file = cache_path.join("example_com.json");
        assert!(!cache_file.exists(), "Expired cache file should be deleted");
    }

    #[tokio::test]
    async fn test_cache_domain_name_sanitization() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";
        let result = create_test_whois_result();
        let store = WhoisCacheStore::new(TestClock::new(SystemTime::UNIX_EPOCH), 10);

        store
            .save(cache_path, domain, &result)
            .await
            .expect("Should save to cache");

        let cache_file = cache_path.join("example_com.json");
        assert!(cache_file.exists(), "Cache file should use sanitized name");
    }

    #[tokio::test]
    async fn test_cache_invalid_json() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";

        // Create invalid JSON file
        let cache_file = cache_path.join("example_com.json");
        std::fs::create_dir_all(cache_path).expect("Should create directory");
        std::fs::write(&cache_file, "invalid json").expect("Should write file");
        let store = WhoisCacheStore::new(TestClock::new(SystemTime::UNIX_EPOCH), 10);

        let result = store.load(cache_path, domain).await;
        assert!(result.is_err(), "Should error on invalid JSON");
    }

    #[tokio::test]
    async fn test_cache_missing_fields_handles_gracefully() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";

        // Create cache file with missing cached_at field
        let cache_file = cache_path.join("example_com.json");
        std::fs::create_dir_all(cache_path).expect("Should create directory");
        std::fs::write(&cache_file, r#"{"domain": "example.com", "result": {}}"#)
            .expect("Should write file");
        let store = WhoisCacheStore::new(TestClock::new(SystemTime::UNIX_EPOCH), 10);

        let result = store.load(cache_path, domain).await;
        assert!(result.is_err(), "Should error on missing required fields");
    }

    #[tokio::test]
    async fn test_cache_fresh_returns_data() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";
        let result = create_test_whois_result();
        let clock = TestClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(60));
        let store = WhoisCacheStore::new(clock.clone(), 10);

        store
            .save(cache_path, domain, &result)
            .await
            .expect("Should save to cache");
        clock.set(SystemTime::UNIX_EPOCH + Duration::from_secs(CACHE_TTL_SECS - 1));

        let cached = store
            .load(cache_path, domain)
            .await
            .expect("Should load from cache");
        assert!(cached.is_some(), "Should return cached data when fresh");

        let entry = cached.unwrap();
        assert_eq!(entry.domain, domain, "Cached domain should match");
        // Verify data integrity
        let whois_result: WhoisResult = entry.result.into();
        assert_eq!(
            whois_result.registrar,
            Some("Test Registrar".to_string()),
            "Cached registrar should match"
        );
    }

    #[tokio::test]
    async fn test_cache_near_expiration_still_valid() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";
        let result = create_test_whois_result();
        let clock = TestClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(5));
        let store = WhoisCacheStore::new(clock.clone(), 10);

        store
            .save(cache_path, domain, &result)
            .await
            .expect("Should save cache entry");
        clock.set(SystemTime::UNIX_EPOCH + Duration::from_secs(CACHE_TTL_SECS - 1));

        let cached = store
            .load(cache_path, domain)
            .await
            .expect("Should load from cache");
        assert!(
            cached.is_some(),
            "Should return cached data when just before expiration"
        );
    }

    /// Depends on global `WHOIS_SAVE_COUNT` being low (1,2,3) so eviction runs.
    /// Run in isolation: `cargo test test_enforce_cache_limit_evicts_oldest_entries`
    #[tokio::test]
    #[ignore]
    async fn test_enforce_cache_limit_evicts_oldest_entries() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let result = create_test_whois_result();
        let clock = TestClock::new(SystemTime::UNIX_EPOCH);
        let store = WhoisCacheStore::new(clock.clone(), 2);

        for i in 0..3 {
            let domain = format!("domain{}.com", i);
            store
                .save(cache_path, &domain, &result)
                .await
                .expect("Should save to cache");
            clock.set(
                SystemTime::UNIX_EPOCH
                    + Duration::from_secs(u64::try_from(i + 1).expect("positive index")),
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        let file_count = std::fs::read_dir(cache_path)
            .expect("Should read dir")
            .filter(|e| e.is_ok())
            .count();
        assert_eq!(file_count, 2, "Only the newest entries should remain");
        assert!(!cache_path.join("domain0_com.json").exists());
        assert!(cache_path.join("domain1_com.json").exists());
        assert!(cache_path.join("domain2_com.json").exists());
    }
}
