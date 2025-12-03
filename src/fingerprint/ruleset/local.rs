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
