//! Helpers for redacting sensitive URLs, headers, and filesystem paths.

use std::path::Path;

/// Removes userinfo, query strings, and fragments from a URL before logging or persistence.
pub(crate) fn scrub_url(url: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(url) else {
        return url.to_string();
    };

    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

/// Returns whether a header name routinely carries secrets and should be redacted.
pub(crate) fn is_sensitive_header_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
            | "x-csrf-token"
    )
}

/// Redacts sensitive header values while keeping non-sensitive names available for triage.
pub(crate) fn scrub_headers(headers: Vec<(String, String)>) -> Vec<(String, String)> {
    headers
        .into_iter()
        .map(|(name, value)| {
            if is_sensitive_header_name(&name) {
                (name, "[redacted]".to_string())
            } else {
                (name, value)
            }
        })
        .collect()
}

/// Returns a minimally identifying path fragment for warnings without leaking full filesystem layout.
pub(crate) fn scrub_path(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .map_or_else(|| ".env".to_string(), ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrub_url_removes_credentials_and_query() {
        let scrubbed = scrub_url("https://user:password@example.com/path?token=abc#frag");
        assert_eq!(scrubbed, "https://example.com/path");
    }

    #[test]
    fn test_scrub_headers_redacts_sensitive_values() {
        let headers = scrub_headers(vec![
            ("Authorization".to_string(), "Bearer secret".to_string()),
            ("Content-Type".to_string(), "text/html".to_string()),
        ]);

        assert_eq!(headers[0].1, "[redacted]");
        assert_eq!(headers[1].1, "text/html");
    }
}
