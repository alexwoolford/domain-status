//! Skip fingerprinting challenge / bot-wall HTML (still persist the HTTP row).

/// True when the response is a CDN/WAF interstitial rather than the site's stack.
///
/// Conservative: title markers used by Cloudflare/Akamai, or a small 403 body
/// that still contains challenge-vendor tokens. Real 403 app pages are kept.
///
/// Title/body tokens are closed until a live miss. Do not expand the substring
/// list from speculation.
#[must_use]
pub(crate) fn is_challenge_interstitial(status: u16, title: &str, body: &str) -> bool {
    if challenge_title(title) {
        return true;
    }
    status == 403 && body.len() < 4096 && challenge_body(body)
}

fn challenge_title(title: &str) -> bool {
    let t = title.trim().to_ascii_lowercase();
    t.starts_with("just a moment")
        || t.contains("attention required")
        || t.contains("checking your browser")
        || t.contains("pardon our interruption")
        || t.contains("please wait while we verify")
}

fn challenge_body(body: &str) -> bool {
    let b = body.to_ascii_lowercase();
    b.contains("cf-browser-verification")
        || b.contains("cdn-cgi/challenge")
        || b.contains("_cf_chl")
        || b.contains("checking your browser before accessing")
        || (b.contains("akamai") && b.contains("interruption"))
        || (b.contains("cloudflare") && b.contains("enable javascript"))
}

#[cfg(test)]
mod tests {
    use super::is_challenge_interstitial;

    #[test]
    fn cloudflare_just_a_moment_is_interstitial() {
        assert!(is_challenge_interstitial(
            403,
            "Just a moment...",
            "<html><body>Enable JavaScript and cookies to continue</body></html>"
        ));
        assert!(is_challenge_interstitial(
            200,
            "Just a moment...",
            "<html></html>"
        ));
    }

    #[test]
    fn cloudflare_attention_required_is_interstitial() {
        assert!(is_challenge_interstitial(
            403,
            "Attention Required! | Cloudflare",
            ""
        ));
    }

    #[test]
    fn akamai_pardon_title_is_interstitial() {
        assert!(is_challenge_interstitial(
            403,
            "Pardon Our Interruption",
            ""
        ));
    }

    #[test]
    fn small_403_with_cf_challenge_token_is_interstitial() {
        assert!(is_challenge_interstitial(
            403,
            "Forbidden",
            "<script>window._cf_chl = 1;</script>"
        ));
    }

    #[test]
    fn wordpress_200_is_not_interstitial() {
        assert!(!is_challenge_interstitial(
            200,
            "Blog Tool, Publishing Platform, and CMS – WordPress.org",
            "<link rel=\"stylesheet\" href=\"/wp-content/themes/wporg/style.css\">"
        ));
    }

    #[test]
    fn large_403_app_html_is_not_interstitial() {
        let body = format!(
            "<html><body>{}</body></html>",
            "access denied. ".repeat(400)
        );
        assert!(body.len() >= 4096);
        assert!(!is_challenge_interstitial(403, "Access Denied", &body));
    }

    #[test]
    fn small_403_without_vendor_tokens_is_not_interstitial() {
        assert!(!is_challenge_interstitial(
            403,
            "Forbidden",
            "<html><body>API key required</body></html>"
        ));
    }
}
