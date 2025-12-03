//! Technology detection with error handling.

use crate::fetch::response::{HtmlData, ResponseData};

/// Detects technologies with error handling and logging.
///
/// Returns a sorted vector of detected technology names, or an empty vector on error.
pub(crate) async fn detect_technologies_safely(
    html_data: &HtmlData,
    resp_data: &ResponseData,
    error_stats: &crate::error_handling::ProcessingStats,
) -> Vec<String> {
    match crate::fingerprint::detect_technologies(
        &html_data.meta_tags,
        &html_data.script_sources,
        &html_data.script_content,
        &html_data.html_text,
        &resp_data.headers,
        &resp_data.final_url,
        &html_data.script_tag_ids,
    )
    .await
    {
        Ok(techs) => {
            if !techs.is_empty() {
                log::debug!(
                    "Detected {} technologies for {}: {:?}",
                    techs.len(),
                    resp_data.final_domain,
                    techs
                );
                let mut tech_vec: Vec<String> = techs.into_iter().collect();
                tech_vec.sort();
                tech_vec
            } else {
                log::debug!("No technologies detected for {}", resp_data.final_domain);
                Vec::new()
            }
        }
        Err(e) => {
            log::warn!(
                "Failed to detect technologies for {}: {e}",
                resp_data.final_domain
            );
            error_stats.increment_error(crate::error_handling::ErrorType::TechnologyDetectionError);
            Vec::new()
        }
    }
}
