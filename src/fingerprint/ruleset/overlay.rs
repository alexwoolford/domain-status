//! First-party rules overlay merged after upstream Wappalyzer sources.
//!
//! Adds technologies missing from upstream (e.g. Payload) and tightens noisy
//! rules (Amazon S3 hosting headers only — not CSP/`scriptSrc` asset URLs).

use std::collections::HashMap;

use anyhow::{Context, Result};

use crate::fingerprint::models::Technology;

use super::ingest_technology;

const OVERLAY_JSON: &str = include_str!("../../../assets/fingerprints/overlay.json");

/// Merge overlay technologies into `technologies` (overlay wins on name clash).
pub(crate) fn apply_first_party_overlay(
    technologies: &mut HashMap<String, Technology>,
) -> Result<()> {
    let overlay: HashMap<String, Technology> =
        serde_json::from_str(OVERLAY_JSON).context("Failed to parse fingerprint overlay.json")?;
    for (name, tech) in overlay {
        if let Some(tech) = ingest_technology(tech) {
            technologies.insert(name, tech);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_adds_payload_and_tightens_s3() {
        let mut technologies = HashMap::new();
        let mut noisy_s3 = Technology::default();
        noisy_s3
            .headers
            .insert("content-security-policy".into(), "s3.amazonaws.com".into());
        noisy_s3.script.push("s3[^ ]*\\.amazonaws\\.com/".into());
        technologies.insert("Amazon S3".into(), noisy_s3);

        apply_first_party_overlay(&mut technologies).expect("overlay parses");

        assert!(technologies.contains_key("Payload"));
        let payload = &technologies["Payload"];
        assert!(payload.headers.contains_key("x-powered-by"));

        let s3 = &technologies["Amazon S3"];
        assert!(s3.script.is_empty(), "overlay must drop S3 scriptSrc");
        assert!(
            !s3.headers.contains_key("content-security-policy"),
            "overlay must drop S3 CSP patterns"
        );
        assert_eq!(
            s3.headers.get("server").map(String::as_str),
            Some("^AmazonS3$")
        );
        assert!(s3.headers.contains_key("x-amz-server-side-encryption"));
        assert_eq!(s3.implies, vec!["Amazon Web Services"]);
    }
}
