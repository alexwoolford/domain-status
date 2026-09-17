//! How a technology was observed (persisted as `url_technologies.detection_source`).

/// Serving-stack signal that produced a fingerprint match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DetectionSource {
    Header,
    Cookie,
    Html,
    ScriptSrc,
    Scripts,
    Url,
    Js,
    Ns,
    Cname,
    Cert,
    Implied,
}

impl DetectionSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Cookie => "cookie",
            Self::Html => "html",
            Self::ScriptSrc => "scriptSrc",
            Self::Scripts => "scripts",
            Self::Url => "url",
            Self::Js => "js",
            Self::Ns => "ns",
            Self::Cname => "cname",
            Self::Cert => "cert",
            Self::Implied => "implied",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DetectionSource;

    #[test]
    fn as_str_matches_persisted_tokens() {
        assert_eq!(DetectionSource::Header.as_str(), "header");
        assert_eq!(DetectionSource::ScriptSrc.as_str(), "scriptSrc");
        assert_eq!(DetectionSource::Implied.as_str(), "implied");
        assert_eq!(DetectionSource::Cert.as_str(), "cert");
    }
}
