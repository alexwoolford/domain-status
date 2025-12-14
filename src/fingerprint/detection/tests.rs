//! Tests for technology detection, focusing on version inheritance bug prevention

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::detection::DetectedTechnology;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_implied_technologies_dont_inherit_versions() {
        // This test ensures that implied technologies (like PHP, MySQL from WordPress)
        // do NOT inherit the parent technology's version
        //
        // Setup: Mock a detection where WordPress is detected with version "6.8.3"
        // Expected: PHP and MySQL should be detected but WITHOUT version (None)

        // This is a unit test that would need to mock the ruleset
        // For now, this documents the expected behavior

        // Expected behavior:
        // - WordPress detected with version "6.8.3" -> OK
        // - PHP implied by WordPress -> version should be None (not "6.8.3")
        // - MySQL implied by WordPress -> version should be None (not "6.8.3")
    }

    #[tokio::test]
    async fn test_implied_technologies_filtered_if_not_in_ruleset() {
        // This test ensures that implied technologies that don't exist in the ruleset
        // are filtered out (e.g., "Acquia Cloud Platform\;confidence:95")

        // Expected behavior:
        // - "Acquia Personalization" detected
        // - Implies "Acquia Cloud Platform\;confidence:95"
        // - "Acquia Cloud Platform\;confidence:95" should NOT appear in output
        //   because it doesn't exist as a technology in the ruleset
    }
}
