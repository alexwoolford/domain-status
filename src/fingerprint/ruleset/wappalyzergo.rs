//! Wappalyzergo format loader.
//!
//! This module handles loading fingerprints in wappalyzergo's format:
//! - Wrapper structure: `{"apps": {"Technology": {...}}}`
//! - Uses `scriptSrc` instead of `script`
//! - Patterns are already normalized to lowercase

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;

use crate::fingerprint::models::Technology;

/// Wappalyzergo's fingerprint file structure
#[derive(serde::Deserialize)]
struct WappalyzergoFingerprints {
    apps: HashMap<String, Technology>,
}

/// Loads technologies from wappalyzergo's fingerprints_data.json format
pub(crate) async fn load_wappalyzergo_format(path: &Path) -> Result<HashMap<String, Technology>> {
    let content = fs::read_to_string(path).await.with_context(|| {
        format!(
            "Failed to read wappalyzergo fingerprints from: {}",
            path.display()
        )
    })?;

    let wapp_data: WappalyzergoFingerprints =
        serde_json::from_str(&content).with_context(|| {
            format!(
                "Failed to parse wappalyzergo fingerprints JSON from: {}",
                path.display()
            )
        })?;

    log::info!(
        "Loaded {} technologies from wappalyzergo format",
        wapp_data.apps.len()
    );

    Ok(wapp_data.apps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_load_wappalyzergo_format() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let file_path = temp_dir.path().join("fingerprints_data.json");

        // Create a wappalyzergo-format JSON file
        let wapp_json = r#"{
            "apps": {
                "WordPress": {
                    "cats": [1],
                    "website": "https://wordpress.org",
                    "scriptSrc": ["wp-content"],
                    "html": ["wp-content"]
                },
                "jQuery": {
                    "cats": [10],
                    "website": "https://jquery.com",
                    "scriptSrc": ["jquery"]
                }
            }
        }"#;

        let mut file = tokio::fs::File::create(&file_path)
            .await
            .expect("Failed to create test file");
        file.write_all(wapp_json.as_bytes())
            .await
            .expect("Failed to write test JSON");
        drop(file);

        let result = load_wappalyzergo_format(&file_path).await;
        assert!(result.is_ok());
        let technologies = result.unwrap();
        assert_eq!(technologies.len(), 2);
        assert!(technologies.contains_key("WordPress"));
        assert!(technologies.contains_key("jQuery"));

        // Verify scriptSrc was mapped to script
        let jquery = technologies.get("jQuery").unwrap();
        assert_eq!(jquery.script.len(), 1);
        assert_eq!(jquery.script[0], "jquery");
    }

    #[tokio::test]
    async fn test_load_wappalyzergo_format_invalid_json() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let file_path = temp_dir.path().join("invalid.json");

        let mut file = tokio::fs::File::create(&file_path)
            .await
            .expect("Failed to create test file");
        file.write_all(b"{ invalid json }")
            .await
            .expect("Failed to write invalid JSON");
        drop(file);

        let result = load_wappalyzergo_format(&file_path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_load_wappalyzergo_format_missing_apps() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let file_path = temp_dir.path().join("missing_apps.json");

        // wappalyzergo format requires "apps" key
        let wapp_json = r#"{"apps": {}}"#;

        let mut file = tokio::fs::File::create(&file_path)
            .await
            .expect("Failed to create test file");
        file.write_all(wapp_json.as_bytes())
            .await
            .expect("Failed to write JSON");
        drop(file);

        let result = load_wappalyzergo_format(&file_path).await;
        // Should succeed but return empty HashMap
        assert!(result.is_ok());
        let technologies = result.unwrap();
        assert!(technologies.is_empty());
    }
}
