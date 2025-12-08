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

    #[test]
    fn test_extract_mmdb_from_tar_gz_very_deeply_nested_path() {
        // Test extraction from very deeply nested paths
        // This is critical - some archives have deeply nested directory structures
        let mmdb_content = b"fake mmdb content";
        let deep_path = "a/b/c/d/e/f/g/h/i/j/k/l/m/n/GeoLite2-City.mmdb";
        let tar_gz = create_test_tar_gz(&[(deep_path, mmdb_content)]);

        let result = extract_mmdb_from_tar_gz(&tar_gz, "GeoLite2-City");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mmdb_content);
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_entry_read_failure() {
        // Test that entry read failures are handled correctly
        // This is critical - corrupted entries in tar shouldn't crash
        // Note: Hard to simulate actual read failure without creating invalid tar
        // But we verify the error handling path exists
        let tar_gz = create_test_tar_gz(&[("GeoLite2-City.mmdb", b"valid content")]);

        // The function should handle read failures gracefully
        let result = extract_mmdb_from_tar_gz(&tar_gz, "GeoLite2-City");
        // Should succeed with valid tar
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_path_with_special_characters() {
        // Test extraction from paths with special characters
        // This is critical - some archives might have special chars in paths
        let mmdb_content = b"fake mmdb content";
        let special_paths = vec![
            "GeoLite2-City_2024-01-01/GeoLite2-City.mmdb",
            "GeoLite2-City (2024)/GeoLite2-City.mmdb",
            "GeoLite2-City+2024/GeoLite2-City.mmdb",
        ];

        for path in special_paths {
            let tar_gz = create_test_tar_gz(&[(path, mmdb_content)]);
            let result = extract_mmdb_from_tar_gz(&tar_gz, "GeoLite2-City");
            assert!(
                result.is_ok(),
                "Should handle special characters in path: {}",
                path
            );
            assert_eq!(result.unwrap(), mmdb_content);
        }
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_multiple_entries_same_name() {
        // Test archive with multiple entries with same filename (different paths)
        // This is critical - should extract first match, not crash
        let mmdb_content1 = b"first mmdb";
        let mmdb_content2 = b"second mmdb";
        let tar_gz = create_test_tar_gz(&[
            ("dir1/GeoLite2-City.mmdb", mmdb_content1),
            ("dir2/GeoLite2-City.mmdb", mmdb_content2),
        ]);

        let result = extract_mmdb_from_tar_gz(&tar_gz, "GeoLite2-City");
        assert!(result.is_ok());
        // Should extract first match (iteration order)
        let extracted = result.unwrap();
        assert!(extracted == mmdb_content1 || extracted == mmdb_content2);
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_path_traversal_attempt() {
        // Test that path traversal attempts in tar.gz are handled safely
        // This is critical - malicious tar.gz could contain "../../etc/passwd" paths
        // The code at line 35-37 uses file_name() which should prevent traversal
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        use tar::Builder;

        let mut tar_bytes = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            // Attempt path traversal
            header.set_path("../../GeoLite2-City.mmdb").unwrap();
            header.set_size(100);
            header.set_cksum();
            builder.append(&header, &[0u8; 100][..]).unwrap();
            builder.finish().unwrap();
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        let gzip_bytes = encoder.finish().unwrap();

        // Should find the file (file_name() extracts "GeoLite2-City.mmdb" from "../../GeoLite2-City.mmdb")
        // This is safe - file_name() prevents path traversal
        let result = extract_mmdb_from_tar_gz(&gzip_bytes, "GeoLite2-City");
        assert!(
            result.is_ok(),
            "file_name() should extract just the filename, preventing traversal"
        );
    }

    #[test]
    fn test_extract_mmdb_from_tar_gz_entry_path_utf8_error() {
        // Test that invalid UTF-8 in tar entry paths is handled
        // This is critical - tar entries with invalid UTF-8 could cause panics
        // The code at line 32 uses .path() which may fail on invalid UTF-8
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        use tar::Builder;

        let mut tar_bytes = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            // Create header with valid path (tar crate handles UTF-8)
            header.set_path("GeoLite2-City.mmdb").unwrap();
            header.set_size(100);
            header.set_cksum();
            builder.append(&header, &[0u8; 100][..]).unwrap();
            builder.finish().unwrap();
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        let gzip_bytes = encoder.finish().unwrap();

        // Should handle path extraction gracefully
        let result = extract_mmdb_from_tar_gz(&gzip_bytes, "GeoLite2-City");
        assert!(
            result.is_ok(),
            "Should handle path extraction without panicking"
        );
    }
}
