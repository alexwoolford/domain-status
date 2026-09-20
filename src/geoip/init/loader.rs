//! `GeoIP` database loading from files and URLs.

use anyhow::{Context, Result};
use maxminddb::Reader;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use crate::config::MAX_GEOIP_DOWNLOAD_SIZE;
use crate::geoip::extract::extract_mmdb_from_tar_gz;
use crate::geoip::metadata::{extract_metadata, load_metadata, save_metadata, write_atomic};
use crate::geoip::types::GeoIpMetadata;
use crate::geoip::{self};
use crate::security::validate_url_safe;

/// Loads `GeoIP` database from a local file path
pub(crate) async fn load_from_file(path: &str) -> Result<(Reader<Vec<u8>>, GeoIpMetadata)> {
    log::info!("Loading GeoIP database from: {path}");

    let db_bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("Failed to read GeoIP database from {path}"))?;

    tokio::task::spawn_blocking({
        let path = path.to_string();
        move || {
            let reader = Reader::from_source(db_bytes)
                .with_context(|| format!("Failed to parse GeoIP database from {path}"))?;
            let metadata = extract_metadata(&reader, &path);
            Ok((reader, metadata))
        }
    })
    .await
    .map_err(|error| anyhow::anyhow!("GeoIP file parse task failed: {error}"))?
}

pub(super) fn geoip_cache_paths(cache_dir: &Path, db_name: &str) -> (PathBuf, PathBuf) {
    let cache_file = cache_dir.join(format!("{db_name}.mmdb"));
    let metadata_file = cache_dir.join(format!("{}_metadata.json", db_name.to_lowercase()));
    (cache_file, metadata_file)
}

/// Checks if a cached `GeoIP` database exists and is fresh.
///
/// Returns the cached reader and metadata if cache is valid and fresh.
/// Returns `None` if cache doesn't exist, is expired, or is corrupted.
///
/// # Arguments
///
/// * `cache_file` - Path to the cached database file
/// * `metadata_file` - Path to the metadata file
///
/// # Returns
///
/// `Ok(Some((reader, metadata)))` if cache is fresh and valid
/// `Ok(None)` if cache doesn't exist, is expired, or is corrupted
/// `Err(...)` if there's an error checking the cache
async fn try_load_from_cache(
    cache_file: &Path,
    metadata_file: &Path,
) -> Result<Option<(Reader<Vec<u8>>, GeoIpMetadata)>> {
    // Check if metadata exists
    let Ok(metadata) = load_metadata(metadata_file).await else {
        return Ok(None); // No metadata, cache doesn't exist
    };

    // Check if cache is fresh (fail closed on clock skew)
    if crate::utils::cache::cache_ttl_exceeded(metadata.last_updated, geoip::CACHE_TTL_SECS, true) {
        return Ok(None); // Cache expired
    }

    // Cache is fresh, try to load the file
    if !cache_file.exists() {
        return Ok(None); // Cache file doesn't exist
    }

    let Some(cache_path) = cache_file.to_str() else {
        log::warn!(
            "Cache file path contains invalid UTF-8: {}",
            cache_file.display()
        );
        return Ok(None);
    };

    // Try to load from cache file
    match load_from_file(cache_path).await {
        Ok((reader, _)) => {
            log::info!("Loaded GeoIP database from cache: {}", cache_file.display());
            Ok(Some((reader, metadata)))
        }
        Err(_) => {
            // Cache file is corrupted or invalid, treat as if it doesn't exist
            Ok(None)
        }
    }
}

/// Downloads `GeoIP` database from URL and caches it locally.
///
/// Handles both direct .mmdb file downloads and tar.gz archives (`MaxMind` format).
///
/// # Arguments
///
/// * `url` - Download URL
/// * `cache_dir` - Cache directory
/// * `db_name` - Database name for cache file (e.g., "GeoLite2-City" or "GeoLite2-ASN")
pub(crate) async fn load_from_url(
    url: &str,
    cache_dir: &Path,
    db_name: &str,
) -> Result<(Reader<Vec<u8>>, GeoIpMetadata)> {
    // Create cache directory if it doesn't exist
    tokio::fs::create_dir_all(cache_dir)
        .await
        .with_context(|| format!("Failed to create cache directory: {}", cache_dir.display()))?;

    let (cache_file, metadata_file) = geoip_cache_paths(cache_dir, db_name);

    // Check if cached version exists and is fresh
    if let Some(cached) = try_load_from_cache(&cache_file, &metadata_file).await? {
        return Ok(cached);
    }

    // SSRF protection: validate URL before downloading
    let url_for_log = super::source_for_log(url);
    validate_url_safe(url).with_context(|| format!("Unsafe GeoIP URL rejected: {url_for_log}"))?;

    // Download database with retries and size limits
    log::info!("Downloading GeoIP database from: {url_for_log}");

    let bytes = crate::utils::retry::with_network_download_retry(
        &format!("download GeoIP database from {url_for_log}"),
        2, // Exponential backoff: 2s, 4s, 8s (longer for large files)
        || download_geoip_with_size_limit(url),
    )
    .await?;

    process_downloaded_geoip(bytes, url, db_name, &cache_file, &metadata_file).await
}

/// Downloads `GeoIP` database with size limit enforcement
async fn download_geoip_with_size_limit(url: &str) -> Result<Vec<u8>> {
    use crate::fetch::stream::{
        reject_if_content_length_exceeds, stream_bytes_with_limit, OnLimit,
    };
    use crate::initialization::build_download_client;

    let client = build_download_client(Duration::from_secs(300))?; // 5 minutes for large file

    let url_for_log = super::source_for_log(url);
    let response = client.get(url).send().await.map_err(|error| {
        anyhow::anyhow!(
            "Failed to download GeoIP database from {url_for_log}: {}",
            error.to_string().replace(url, url_for_log)
        )
    })?;

    if !response.status().is_success() {
        let status = response.status();
        let error_body = response
            .text()
            .await
            .unwrap_or_else(|_| "No error details".to_string());
        // Log expected errors as WARN to reduce noise in test output:
        // - "Invalid license key" when using test/invalid keys
        // - HTML responses when hitting wrong URLs (common in tests)
        if error_body.contains("Invalid license key")
            || (error_body.trim_start().starts_with("<!") && error_body.contains("<html"))
        {
            log::warn!("MaxMind API error response: {error_body}");
        } else {
            log::error!("MaxMind API error response: {error_body}");
        }
        return Err(anyhow::anyhow!(
            "Failed to download GeoIP database: {status} - {error_body}"
        ));
    }

    reject_if_content_length_exceeds(&response, MAX_GEOIP_DOWNLOAD_SIZE, "GeoIP database")?;

    let streamed = stream_bytes_with_limit(
        response,
        MAX_GEOIP_DOWNLOAD_SIZE,
        OnLimit::Error,
        "GeoIP download",
    )
    .await?;

    Ok(streamed.into_bytes())
}

/// Processes downloaded `GeoIP` bytes (extraction, caching, metadata)
async fn process_downloaded_geoip(
    downloaded_bytes: Vec<u8>,
    url: &str,
    db_name: &str,
    cache_file: &Path,
    metadata_file: &Path,
) -> Result<(Reader<Vec<u8>>, GeoIpMetadata)> {
    // Extract .mmdb file from tar.gz if needed, or use directly if it's already .mmdb
    let (db_bytes, metadata, reader) = tokio::task::spawn_blocking({
        let url = url.to_string();
        let db_name = db_name.to_string();
        move || -> Result<(Vec<u8>, GeoIpMetadata, Reader<Vec<u8>>)> {
            let url_path = std::path::Path::new(&url);
            let db_bytes = if url.ends_with(".tar.gz") || url.contains("suffix=tar.gz") {
                extract_mmdb_from_tar_gz(&downloaded_bytes, &db_name)?
            } else if url_path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("mmdb"))
            {
                downloaded_bytes
            } else if downloaded_bytes.len() > 2
                && downloaded_bytes[0] == 0x1f
                && downloaded_bytes[1] == 0x8b
            {
                extract_mmdb_from_tar_gz(&downloaded_bytes, &db_name)?
            } else {
                downloaded_bytes
            };

            let reader = Reader::from_source(db_bytes.clone())
                .with_context(|| "Failed to create owned reader from downloaded database")?;
            let metadata = extract_metadata(&reader, &url);

            Ok((db_bytes, metadata, reader))
        }
    })
    .await
    .map_err(|error| anyhow::anyhow!("GeoIP archive parse task failed: {error}"))??;

    write_atomic(cache_file, &db_bytes)
        .await
        .with_context(|| format!("Failed to write cache file: {}", cache_file.display()))?;
    save_metadata(&metadata, metadata_file).await?;

    Ok((reader, metadata))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geoip::metadata::save_metadata;
    use std::time::{Duration, SystemTime};
    use tempfile::TempDir;

    fn city_cache_paths(dir: &Path) -> (PathBuf, PathBuf) {
        geoip_cache_paths(dir, "GeoLite2-City")
    }

    async fn write_fresh_city_metadata(metadata_file: &Path) {
        save_metadata(
            &GeoIpMetadata {
                source: "test://source".to_string(),
                version: "1.0".to_string(),
                last_updated: SystemTime::now(),
            },
            metadata_file,
        )
        .await
        .expect("save metadata");
    }

    #[tokio::test]
    async fn test_load_from_file_not_found() {
        let nonexistent_path = Path::new("nonexistent")
            .join("path")
            .join("to")
            .join("database.mmdb");
        let result = load_from_file(nonexistent_path.to_str().unwrap()).await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Failed to read")
                || error_msg.contains("No such file")
                || error_msg.contains("not found"),
            "Expected file not found error, got: {error_msg}"
        );
    }

    #[tokio::test]
    async fn test_load_from_file_invalid_or_empty() {
        let temp_dir = TempDir::new().expect("temp dir");
        let invalid = temp_dir.path().join("invalid.mmdb");
        tokio::fs::write(&invalid, b"not a valid mmdb file")
            .await
            .expect("write");
        let err = load_from_file(invalid.to_str().unwrap())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Failed to parse") || err.contains("parse"),
            "Expected parse error, got: {err}"
        );

        let empty = temp_dir.path().join("empty.mmdb");
        tokio::fs::File::create(&empty).await.expect("create");
        let empty_err = load_from_file(empty.to_str().unwrap())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            empty_err.contains("parse") || empty_err.contains("Failed to parse"),
            "empty file must fail parse: {empty_err}"
        );
    }

    #[tokio::test]
    async fn test_load_from_url_ssrf_protection() {
        let temp_dir = TempDir::new().expect("temp dir");
        for (url, needle) in [
            ("http://192.168.1.1/database.mmdb", "Unsafe"),
            ("http://localhost/database.mmdb", "Unsafe"),
            ("file:///etc/passwd", "Unsafe"),
        ] {
            let error_msg = load_from_url(url, temp_dir.path(), "GeoLite2-City")
                .await
                .unwrap_err()
                .to_string();
            assert!(
                error_msg.contains(needle),
                "SSRF must reject {url}: {error_msg}"
            );
        }
    }

    #[tokio::test]
    async fn test_load_from_url_redacts_license_key_in_errors() {
        let temp_dir = TempDir::new().expect("temp dir");
        let url = "http://192.168.1.1/database.mmdb?license_key=supersecret&suffix=tar.gz";
        let error_msg = load_from_url(url, temp_dir.path(), "GeoLite2-City")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error_msg.contains("Unsafe"),
            "expected SSRF rejection: {error_msg}"
        );
        assert!(
            !error_msg.contains("supersecret") && !error_msg.contains("license_key="),
            "license_key must not appear in GeoIP errors: {error_msg}"
        );
    }

    #[tokio::test]
    async fn test_try_load_from_cache_misses() {
        let temp_dir = TempDir::new().expect("temp dir");
        let (cache_file, metadata_file) = city_cache_paths(temp_dir.path());

        let none = try_load_from_cache(&cache_file, &metadata_file)
            .await
            .expect("missing metadata is a cache miss");
        assert!(none.is_none(), "no metadata → miss");

        write_fresh_city_metadata(&metadata_file).await;
        let missing_file = try_load_from_cache(&cache_file, &metadata_file)
            .await
            .expect("missing cache file is a miss");
        assert!(missing_file.is_none(), "metadata without MMDB → miss");

        tokio::fs::write(&cache_file, b"corrupted mmdb data")
            .await
            .expect("write");
        let corrupt = try_load_from_cache(&cache_file, &metadata_file)
            .await
            .expect("corrupt MMDB is a miss");
        assert!(corrupt.is_none(), "corrupt MMDB → miss");

        save_metadata(
            &GeoIpMetadata {
                source: "test://source".to_string(),
                version: "1.0".to_string(),
                last_updated: SystemTime::now() - Duration::from_secs(geoip::CACHE_TTL_SECS + 1),
            },
            &metadata_file,
        )
        .await
        .expect("save expired");
        let expired = try_load_from_cache(&cache_file, &metadata_file)
            .await
            .expect("expired cache is a miss");
        assert!(expired.is_none(), "expired metadata → miss");
    }

    #[tokio::test]
    async fn test_load_from_url_corrupt_cache_falls_through_to_download() {
        let temp_dir = TempDir::new().expect("temp dir");
        let (cache_file, metadata_file) = city_cache_paths(temp_dir.path());
        tokio::fs::write(&cache_file, b"corrupted mmdb data")
            .await
            .expect("write");
        write_fresh_city_metadata(&metadata_file).await;

        let error_msg = load_from_url(
            "http://192.168.1.1/db.mmdb",
            temp_dir.path(),
            "GeoLite2-City",
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error_msg.contains("Unsafe"),
            "corrupt cache must fall through to download, got: {error_msg}"
        );
        assert!(
            !error_msg.contains("parse"),
            "must not surface cache parse as the load_from_url error: {error_msg}"
        );
    }

    #[tokio::test]
    async fn test_download_geoip_http_500() {
        use httptest::{matchers::*, responders::*, Expectation, Server};

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/geoip.mmdb"))
                .respond_with(status_code(500)),
        );
        let url = server.url("/geoip.mmdb").to_string();
        let error_msg = download_geoip_with_size_limit(&url)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error_msg.contains("500") || error_msg.contains("Failed to download"),
            "HTTP 500 must fail download: {error_msg}"
        );
    }

    /// Kills: `OnLimit::Error` accepting a streamed body one byte over
    /// `MAX_GEOIP_DOWNLOAD_SIZE` (message must contain `too large`).
    #[tokio::test]
    async fn test_download_geoip_rejects_oversized_body() {
        use httptest::{matchers::*, responders::*, Expectation, Server};

        let server = Server::run();
        let large_body = vec![0u8; crate::config::MAX_GEOIP_DOWNLOAD_SIZE + 1];
        server.expect(
            Expectation::matching(request::method_path("GET", "/geoip.mmdb"))
                .respond_with(status_code(200).body(large_body)),
        );
        let url = server.url("/geoip.mmdb").to_string();
        let error_msg = download_geoip_with_size_limit(&url)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error_msg.contains("too large"),
            "oversized GeoIP body must be rejected: {error_msg}"
        );
    }

    /// Serves one HTTP/1.1 200 with an explicit `Content-Length` that may not
    /// match `body`. httptest/hyper cannot do this (they panic on mismatch).
    async fn serve_content_length_lie(content_length: usize, body: &[u8]) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let body = body.to_vec();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 2048];
            let _ = socket.read(&mut buf).await;
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n"
            );
            let _ = socket.write_all(header.as_bytes()).await;
            let _ = socket.write_all(&body).await;
        });
        format!("http://{addr}/geoip.mmdb")
    }

    /// Kills: skipping `reject_if_content_length_exceeds` so a lying
    /// `Content-Length: MAX+1` with a tiny body is accepted.
    #[tokio::test]
    async fn test_download_geoip_rejects_lying_content_length() {
        let max = crate::config::MAX_GEOIP_DOWNLOAD_SIZE;
        let url = serve_content_length_lie(max + 1, b"tiny").await;
        let error_msg = download_geoip_with_size_limit(&url)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error_msg.contains("too large"),
            "lying Content-Length must be rejected: {error_msg}"
        );
        assert!(
            error_msg.contains(&max.to_string()),
            "error must name the max byte count {max}, got: {error_msg}"
        );
    }

    /// Kills: treating `Content-Length == MAX` as oversize (the header check
    /// is `>` not `>=`). Hyper then errors on the short body (`error decoding
    /// response body`); that is not a size-cap rejection.
    #[tokio::test]
    async fn test_download_geoip_accepts_content_length_at_cap() {
        let max = crate::config::MAX_GEOIP_DOWNLOAD_SIZE;
        let url = serve_content_length_lie(max, b"tiny").await;
        match download_geoip_with_size_limit(&url).await {
            Ok(bytes) => assert_eq!(bytes, b"tiny"),
            Err(err) => {
                let error_msg = err.to_string();
                assert!(
                    !error_msg.contains("too large"),
                    "Content-Length at the cap must pass the header check: {error_msg}"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_process_downloaded_geoip_tar_gz_vs_direct_mmdb() {
        let temp_dir = TempDir::new().expect("temp dir");
        let (cache_file, metadata_file) = city_cache_paths(temp_dir.path());

        let tar_err = process_downloaded_geoip(
            b"not a valid tar.gz".to_vec(),
            "https://example.com/db.tar.gz",
            "GeoLite2-City",
            &cache_file,
            &metadata_file,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            tar_err.contains("extract")
                || tar_err.contains("gzip")
                || tar_err.contains("tar")
                || tar_err.contains("Failed"),
            "suffix=tar.gz / .tar.gz URL must extract: {tar_err}"
        );

        let mmdb_err = process_downloaded_geoip(
            b"not a valid mmdb".to_vec(),
            "https://example.com/db.mmdb",
            "GeoLite2-City",
            &cache_file,
            &metadata_file,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            mmdb_err.contains("parse")
                || mmdb_err.contains("database")
                || mmdb_err.contains("Failed"),
            "direct .mmdb URL must skip extract and parse: {mmdb_err}"
        );
    }

    #[tokio::test]
    async fn test_process_downloaded_geoip_gzip_magic_without_url_hint() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        use tar::Builder;

        let mut tar_builder = Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_path("GeoLite2-ASN.mmdb").unwrap();
        header.set_size(3);
        header.set_cksum();
        tar_builder.append(&header, &b"asn"[..]).unwrap();
        let tar_bytes = tar_builder.into_inner().unwrap();
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        let gzip_bytes = encoder.finish().unwrap();

        let temp_dir = TempDir::new().expect("temp dir");
        let (cache_file, metadata_file) = city_cache_paths(temp_dir.path());
        let err = process_downloaded_geoip(
            gzip_bytes,
            "https://example.com/geoip",
            "GeoLite2-City",
            &cache_file,
            &metadata_file,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("GeoLite2-City.mmdb not found"),
            "gzip magic must extract even without .tar.gz URL, then miss City: {err}"
        );
    }
}
