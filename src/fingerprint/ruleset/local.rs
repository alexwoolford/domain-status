//! Local file loading operations for fingerprint rulesets.
//!
//! This module handles loading technologies from local file paths.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;

use crate::fingerprint::models::Technology;

/// Loads technologies from a local path (handles both single file and directory)
pub(crate) async fn load_from_path(path: &Path) -> Result<HashMap<String, Technology>> {
    if path.is_dir() {
        // Load all JSON files from directory
        let mut all_technologies = HashMap::new();
        let mut entries = fs::read_dir(path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let file_path = entry.path();
            if file_path.extension().and_then(|s| s.to_str()) == Some("json") {
                match fs::read_to_string(&file_path).await {
                    Ok(content) => {
                        match serde_json::from_str::<HashMap<String, Technology>>(&content) {
                            Ok(techs) => {
                                all_technologies.extend(techs);
                            }
                            Err(e) => {
                                log::warn!("Failed to parse {}: {}", file_path.display(), e);
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to read {}: {}", file_path.display(), e);
                    }
                }
            }
        }

        Ok(all_technologies)
    } else {
        // Single file
        let content = fs::read_to_string(path).await?;
        let technologies: HashMap<String, Technology> =
            serde_json::from_str(&content).context("Failed to parse technologies JSON")?;

        Ok(technologies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_load_from_path_file_not_found() {
        let path = std::path::Path::new("nonexistent_file.json");
        let result = load_from_path(path).await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("No such file")
                || error_msg.contains("not found")
                || error_msg.contains("The system cannot find"),
            "Expected file not found error, got: {}",
            error_msg
        );
    }

    #[tokio::test]
    async fn test_load_from_path_invalid_json() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let file_path = temp_dir.path().join("invalid.json");
        let mut file = tokio::fs::File::create(&file_path)
            .await
            .expect("Failed to create test file");
        file.write_all(b"{ invalid json }")
            .await
            .expect("Failed to write invalid JSON");
        drop(file);

        let result = load_from_path(&file_path).await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("parse") || error_msg.contains("JSON"),
            "Expected JSON parse error, got: {}",
            error_msg
        );
    }

    #[tokio::test]
    async fn test_load_from_path_empty_file() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let file_path = temp_dir.path().join("empty.json");
        tokio::fs::write(&file_path, b"{}")
            .await
            .expect("Failed to write empty JSON");

        let result = load_from_path(&file_path).await;
        // Empty JSON object should parse successfully (empty HashMap)
        assert!(result.is_ok());
        let technologies = result.unwrap();
        assert!(technologies.is_empty());
    }

    #[tokio::test]
    async fn test_load_from_path_directory_with_json_files() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let dir_path = temp_dir.path();

        // Create multiple JSON files
        let tech1 = r#"{"WordPress": {"cats": [1], "website": "https://wordpress.org"}}"#;
        let tech2 = r#"{"Drupal": {"cats": [1], "website": "https://drupal.org"}}"#;

        tokio::fs::write(dir_path.join("tech1.json"), tech1)
            .await
            .expect("Failed to write tech1.json");
        tokio::fs::write(dir_path.join("tech2.json"), tech2)
            .await
            .expect("Failed to write tech2.json");
        // Create a non-JSON file (should be ignored)
        tokio::fs::write(dir_path.join("readme.txt"), "Not a JSON file")
            .await
            .expect("Failed to write readme.txt");

        let result = load_from_path(dir_path).await;
        assert!(result.is_ok());
        let technologies = result.unwrap();
        assert!(technologies.len() >= 2); // Should have at least WordPress and Drupal
        assert!(technologies.contains_key("WordPress"));
        assert!(technologies.contains_key("Drupal"));
    }

    #[tokio::test]
    async fn test_load_from_path_directory_with_invalid_json_file() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let dir_path = temp_dir.path();

        // Create one valid and one invalid JSON file
        let valid_tech = r#"{"WordPress": {"cats": [1], "website": "https://wordpress.org"}}"#;
        tokio::fs::write(dir_path.join("valid.json"), valid_tech)
            .await
            .expect("Failed to write valid.json");
        tokio::fs::write(dir_path.join("invalid.json"), b"{ invalid json }")
            .await
            .expect("Failed to write invalid.json");

        let result = load_from_path(dir_path).await;
        // Should succeed with valid file, invalid file should be skipped with warning
        assert!(result.is_ok());
        let technologies = result.unwrap();
        assert!(technologies.contains_key("WordPress"));
    }

    #[tokio::test]
    async fn test_load_from_path_directory_empty() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let dir_path = temp_dir.path();

        let result = load_from_path(dir_path).await;
        // Empty directory should return empty HashMap
        assert!(result.is_ok());
        let technologies = result.unwrap();
        assert!(technologies.is_empty());
    }

    #[tokio::test]
    async fn test_load_from_path_directory_nonexistent() {
        let path = std::path::Path::new("nonexistent_directory");
        let result = load_from_path(path).await;
        assert!(result.is_err());
    }
}
