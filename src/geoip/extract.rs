//! Archive extraction utilities.
//!
//! This module provides functions to extract .mmdb files from tar.gz archives
//! downloaded from `MaxMind`.

use anyhow::{bail, Context, Result};

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

    for (index, entry_result) in entries.enumerate() {
        if index >= crate::config::MAX_GEOIP_ARCHIVE_ENTRY_COUNT {
            bail!(
                "GeoIP archive exceeded entry inspection limit (max: {})",
                crate::config::MAX_GEOIP_ARCHIVE_ENTRY_COUNT
            );
        }

        let entry = entry_result.with_context(|| "Failed to read tar entry")?;
        let path = entry.path().with_context(|| "Failed to get entry path")?;

        // Look for the specified database .mmdb file
        if let Some(file_name) = path.file_name() {
            let expected_name = format!("{db_name}.mmdb");
            if file_name.to_str() == Some(&expected_name) {
                let declared_size = usize::try_from(entry.size()).unwrap_or(usize::MAX);
                if declared_size > crate::config::MAX_GEOIP_ARCHIVE_ENTRY_SIZE {
                    bail!(
                        "{}.mmdb entry too large: {} bytes (max: {} bytes)",
                        db_name,
                        declared_size,
                        crate::config::MAX_GEOIP_ARCHIVE_ENTRY_SIZE
                    );
                }

                let read_limit = u64::try_from(crate::config::MAX_GEOIP_ARCHIVE_ENTRY_SIZE + 1)
                    .context(
                        "MAX_GEOIP_ARCHIVE_ENTRY_SIZE + 1 must fit in u64; this is a constant bug",
                    )?;
                let capacity = declared_size.min(crate::config::MAX_GEOIP_ARCHIVE_ENTRY_SIZE);
                let mut mmdb_bytes = Vec::with_capacity(capacity);
                entry
                    .take(read_limit)
                    .read_to_end(&mut mmdb_bytes)
                    .with_context(|| format!("Failed to read {db_name}.mmdb file from archive"))?;
                if mmdb_bytes.len() > crate::config::MAX_GEOIP_ARCHIVE_ENTRY_SIZE {
                    bail!(
                        "{}.mmdb entry exceeded size limit while reading (max: {} bytes)",
                        db_name,
                        crate::config::MAX_GEOIP_ARCHIVE_ENTRY_SIZE
                    );
                }
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
        "{db_name}.mmdb not found in tar.gz archive"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    use tar::Builder;

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn create_test_tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_builder = Builder::new(Vec::new());
        for (name, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_size(u64::try_from(content.len()).expect("fixture size fits u64"));
            header.set_cksum();
            tar_builder.append(&header, *content).unwrap();
        }
        gzip(&tar_builder.into_inner().unwrap())
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_success() {
        let mmdb_content = b"fake mmdb content";
        let tar_gz = create_test_tar_gz(&[("GeoLite2-City.mmdb", mmdb_content)]);
        assert_eq!(
            extract_mmdb_from_tar_gz(&tar_gz, "GeoLite2-City").unwrap(),
            mmdb_content
        );
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_nested_and_skips_other_files() {
        let mmdb_content = b"fake mmdb content";
        let tar_gz = create_test_tar_gz(&[
            ("README.txt", b"readme"),
            ("GeoLite2-City_20240101/GeoLite2-City.mmdb", mmdb_content),
            ("GeoLite2-ASN.mmdb", b"asn"),
        ]);
        assert_eq!(
            extract_mmdb_from_tar_gz(&tar_gz, "GeoLite2-City").unwrap(),
            mmdb_content
        );
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_not_found() {
        let tar_gz = create_test_tar_gz(&[("GeoLite2-ASN.mmdb", b"asn")]);
        let err = extract_mmdb_from_tar_gz(&tar_gz, "GeoLite2-City")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("GeoLite2-City.mmdb not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_empty_or_invalid() {
        assert!(extract_mmdb_from_tar_gz(&create_test_tar_gz(&[]), "GeoLite2-City").is_err());
        assert!(extract_mmdb_from_tar_gz(b"not gzip", "GeoLite2-City").is_err());
        assert!(extract_mmdb_from_tar_gz(&gzip(b"not a tar"), "GeoLite2-City").is_err());
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_case_sensitive_filename() {
        let tar_gz = create_test_tar_gz(&[("geolite2-city.mmdb", b"nope")]);
        assert!(extract_mmdb_from_tar_gz(&tar_gz, "GeoLite2-City").is_err());
    }

    #[test]
    fn test_extract_mmdb_rejects_declared_size_over_limit() {
        let declared = u64::try_from(crate::config::MAX_GEOIP_ARCHIVE_ENTRY_SIZE)
            .unwrap()
            .saturating_add(1);
        let mut header = tar::Header::new_gnu();
        header.set_path("GeoLite2-City.mmdb").unwrap();
        header.set_size(declared);
        header.set_cksum();
        let mut tar_bytes = header.as_bytes().to_vec();
        tar_bytes.extend_from_slice(&[0u8; 1024]);
        let err = extract_mmdb_from_tar_gz(&gzip(&tar_bytes), "GeoLite2-City")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("too large") || err.contains("entry too large"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_extract_mmdb_rejects_too_many_archive_entries() {
        let mut tar_builder = Builder::new(Vec::new());
        let pad = b"x";
        for i in 0..crate::config::MAX_GEOIP_ARCHIVE_ENTRY_COUNT {
            let name = format!("pad-{i}.txt");
            let mut header = tar::Header::new_gnu();
            header.set_path(&name).unwrap();
            header.set_size(u64::try_from(pad.len()).expect("fixture size fits u64"));
            header.set_cksum();
            tar_builder.append(&header, &pad[..]).unwrap();
        }
        let mut header = tar::Header::new_gnu();
        header.set_path("GeoLite2-City.mmdb").unwrap();
        header.set_size(4);
        header.set_cksum();
        tar_builder.append(&header, &b"city"[..]).unwrap();
        let tar_gz = gzip(&tar_builder.into_inner().unwrap());
        let err = extract_mmdb_from_tar_gz(&tar_gz, "GeoLite2-City")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("entry inspection limit"),
            "unexpected error: {err}"
        );
    }
}
