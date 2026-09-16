//! GitHub-specific operations for fetching fingerprint rulesets.
//!
//! This module handles fetching from GitHub directories and getting commit SHAs.

mod commit;
mod directory;

pub(crate) use commit::get_latest_commit_sha;
pub(crate) use directory::fetch_from_github_directory;

/// GitHub API User-Agent (`domain-status/<crate version>`).
pub(crate) const GITHUB_API_USER_AGENT: &str = concat!("domain-status/", env!("CARGO_PKG_VERSION"));
