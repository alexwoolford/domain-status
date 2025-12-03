//! Archive extraction utilities.
//!
//! This module provides functions to extract .mmdb files from tar.gz archives
//! downloaded from MaxMind.

use anyhow::{Context, Result};

/// Extracts .mmdb file from a tar.gz archive.
///
/// # Arguments
///
/// * `tar_gz_bytes` - The tar.gz archive bytes
/// * `db_name` - The database name to look for (e.g., "GeoLite2-City" or "GeoLite2-ASN")
pub(crate) fn extract_mmdb_from_tar_gz(tar_gz_bytes: &[u8], db_name: &str) -> Result<Vec<u8>> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    use tar::Archive;

    log::debug!("Extracting .mmdb file from tar.gz archive");

    // Decompress gzip
    let gz_decoder = GzDecoder::new(tar_gz_bytes);
    let mut tar_archive = Archive::new(gz_decoder);

    // Extract entries
    let entries = tar_archive
        .entries()
        .with_context(|| "Failed to read tar archive entries")?;

    for entry_result in entries {
        let mut entry = entry_result.with_context(|| "Failed to read tar entry")?;
        let path = entry.path().with_context(|| "Failed to get entry path")?;

        // Look for the specified database .mmdb file
        if let Some(file_name) = path.file_name() {
            let expected_name = format!("{}.mmdb", db_name);
            if file_name.to_str() == Some(&expected_name) {
                let mut mmdb_bytes = Vec::new();
                entry.read_to_end(&mut mmdb_bytes).with_context(|| {
                    format!("Failed to read {}.mmdb file from archive", db_name)
                })?;
                log::info!(
                    "Extracted {}.mmdb from tar.gz ({} bytes)",
                    db_name,
                    mmdb_bytes.len()
                );
                return Ok(mmdb_bytes);
            }
        }
    }

    Err(anyhow::anyhow!(
        "{}.mmdb not found in tar.gz archive",
        db_name
    ))
}
