//! Tiny shared helpers for on-disk caches (`GeoIP`, fingerprint, WHOIS, UA).
//!
//! Not a cache framework — just atomic write and TTL age checks that used to
//! be copy-pasted (and for writes, only `GeoIP` was atomic).

use anyhow::Result;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Writes `bytes` to `path` via a temp file + rename (crash-safe replace).
///
/// Creates parent directories as needed. Staging file is `.{file_name}.tmp`
/// beside the destination.
pub(crate) async fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    tokio::fs::create_dir_all(parent).await?;

    let file_name = path.file_name().map_or_else(
        || "cache.tmp".to_string(),
        |name| name.to_string_lossy().into_owned(),
    );
    let temp_path = parent.join(format!(".{file_name}.tmp"));

    tokio::fs::write(&temp_path, bytes).await?;
    if let Err(error) = tokio::fs::rename(&temp_path, path).await {
        if path.exists() {
            tokio::fs::remove_file(path).await?;
            tokio::fs::rename(&temp_path, path).await?;
        } else {
            return Err(error.into());
        }
    }
    Ok(())
}

/// Returns true when a cache entry aged past `ttl_secs`.
///
/// If `last_updated` is in the future (`elapsed()` fails), returns
/// `expire_on_clock_skew` — `GeoIP` fails closed (`true`); UA/fingerprint
/// treat future timestamps as still fresh (`false`).
pub(crate) fn cache_ttl_exceeded(
    last_updated: SystemTime,
    ttl_secs: u64,
    expire_on_clock_skew: bool,
) -> bool {
    match last_updated.elapsed() {
        Ok(age) => duration_exceeds_ttl(age, ttl_secs),
        Err(_) => expire_on_clock_skew,
    }
}

/// True when `age` is at least `ttl_secs` (inclusive boundary = expired).
pub(crate) fn duration_exceeds_ttl(age: Duration, ttl_secs: u64) -> bool {
    age.as_secs() >= ttl_secs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_write_atomic_round_trip() {
        let dir = TempDir::new().expect("temp");
        let path = dir.path().join("data.bin");
        write_atomic(&path, b"hello").await.expect("write");
        let got = tokio::fs::read(&path).await.expect("read");
        assert_eq!(got, b"hello");
    }

    #[test]
    fn test_cache_ttl_exceeded_boundaries() {
        let now = SystemTime::now();
        assert!(!cache_ttl_exceeded(now, 3600, true));

        let old = now
            .checked_sub(Duration::from_secs(3600))
            .expect("subtract");
        assert!(cache_ttl_exceeded(old, 3600, true));

        let future = now.checked_add(Duration::from_secs(60)).expect("add");
        assert!(cache_ttl_exceeded(future, 3600, true));
        assert!(!cache_ttl_exceeded(future, 3600, false));
    }

    #[test]
    fn test_duration_exceeds_ttl() {
        assert!(!duration_exceeds_ttl(Duration::from_secs(59), 60));
        assert!(duration_exceeds_ttl(Duration::from_secs(60), 60));
        assert!(duration_exceeds_ttl(Duration::from_secs(61), 60));
    }
}
