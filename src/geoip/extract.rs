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

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    use tar::Builder;

    /// Creates a test tar.gz archive with the specified files.
    fn create_test_tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_builder = Builder::new(Vec::new());
        for (name, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_size(content.len() as u64);
            header.set_cksum();
            tar_builder.append(&header, *content).unwrap();
        }
        let tar_bytes = tar_builder.into_inner().unwrap();

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_success() {
        let mmdb_content = b"fake mmdb content";
        let tar_gz = create_test_tar_gz(&[("GeoLite2-City.mmdb", mmdb_content)]);

        let result = extract_mmdb_from_tar_gz(&tar_gz, "GeoLite2-City");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mmdb_content);
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_multiple_files() {
        let mmdb_content = b"fake mmdb content";
        let other_content = b"other file content";
        let tar_gz = create_test_tar_gz(&[
            ("README.txt", other_content),
            ("GeoLite2-City.mmdb", mmdb_content),
            ("LICENSE.txt", other_content),
        ]);

        let result = extract_mmdb_from_tar_gz(&tar_gz, "GeoLite2-City");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mmdb_content);
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_not_found() {
        let tar_gz = create_test_tar_gz(&[("README.txt", b"readme content")]);

        let result = extract_mmdb_from_tar_gz(&tar_gz, "GeoLite2-City");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("GeoLite2-City.mmdb not found"));
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_wrong_name() {
        let mmdb_content = b"fake mmdb content";
        let tar_gz = create_test_tar_gz(&[("GeoLite2-ASN.mmdb", mmdb_content)]);

        let result = extract_mmdb_from_tar_gz(&tar_gz, "GeoLite2-City");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("GeoLite2-City.mmdb not found"));
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_nested_path() {
        // Some archives have nested paths like "GeoLite2-City_20240101/GeoLite2-City.mmdb"
        let mmdb_content = b"fake mmdb content";
        let tar_gz =
            create_test_tar_gz(&[("GeoLite2-City_20240101/GeoLite2-City.mmdb", mmdb_content)]);

        let result = extract_mmdb_from_tar_gz(&tar_gz, "GeoLite2-City");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mmdb_content);
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_empty_archive() {
        let tar_gz = create_test_tar_gz(&[]);

        let result = extract_mmdb_from_tar_gz(&tar_gz, "GeoLite2-City");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_invalid_gzip() {
        let invalid_data = b"not a valid tar.gz file";
        let result = extract_mmdb_from_tar_gz(invalid_data, "GeoLite2-City");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_case_sensitive() {
        let mmdb_content = b"fake mmdb content";
        let tar_gz = create_test_tar_gz(&[("geolite2-city.mmdb", mmdb_content)]); // lowercase

        let result = extract_mmdb_from_tar_gz(&tar_gz, "GeoLite2-City"); // mixed case
        assert!(result.is_err()); // Should not match due to case sensitivity
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_very_large_file() {
        // Test extraction of very large .mmdb file (performance/memory edge case)
        let large_content = vec![0u8; 10_000_000]; // 10MB
        let tar_gz = create_test_tar_gz(&[("GeoLite2-City.mmdb", &large_content)]);

        let result = extract_mmdb_from_tar_gz(&tar_gz, "GeoLite2-City");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 10_000_000);
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_multiple_mmdb_files() {
        // Test archive with multiple .mmdb files (should extract first match)
        let city_content = b"city mmdb";
        let asn_content = b"asn mmdb";
        let tar_gz = create_test_tar_gz(&[
            ("GeoLite2-ASN.mmdb", asn_content),
            ("GeoLite2-City.mmdb", city_content),
        ]);

        let result = extract_mmdb_from_tar_gz(&tar_gz, "GeoLite2-City");
        assert!(result.is_ok());
        // Should extract City, not ASN (first match in iteration order)
        assert_eq!(result.unwrap(), city_content);
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_corrupted_tar() {
        // Test with corrupted tar (valid gzip but invalid tar)
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"not a valid tar file").unwrap();
        let corrupted_gz = encoder.finish().unwrap();

        let result = extract_mmdb_from_tar_gz(&corrupted_gz, "GeoLite2-City");
        assert!(result.is_err());
    }
}
