//! Shared HTTP body streaming with size caps.
//!
//! Page fetch, external scripts, favicon, and asset downloads all need the same
//! chunk-accumulate loop; only the oversize policy differs.

use futures::StreamExt;

/// What to do when accumulated bytes would exceed `max_size`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnLimit {
    /// Keep a prefix of exactly `max_size` bytes and report [`StreamedBytes::Truncated`].
    Truncate,
    /// Stop and return [`StreamBytesError::LimitExceeded`].
    Abort,
    /// Stop and return [`StreamBytesError::TooLarge`].
    Error,
}

/// Successfully streamed body bytes (possibly truncated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StreamedBytes {
    /// Full body within the size limit.
    Complete(Vec<u8>),
    /// Prefix kept after [`OnLimit::Truncate`].
    Truncated(Vec<u8>),
}

impl StreamedBytes {
    /// Returns the underlying bytes.
    #[must_use]
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Complete(b) | Self::Truncated(b) => b,
        }
    }

    /// Returns `true` if the body was truncated at the size cap.
    #[must_use]
    pub(crate) fn is_truncated(&self) -> bool {
        matches!(self, Self::Truncated(_))
    }
}

/// Failure while streaming a response body under a size limit.
#[derive(Debug)]
pub(crate) enum StreamBytesError {
    /// Chunk read failed.
    Read(reqwest::Error),
    /// [`OnLimit::Abort`] when the next chunk would exceed the cap.
    LimitExceeded,
    /// [`OnLimit::Error`] when the next chunk would exceed the cap.
    TooLarge { got: usize, max: usize },
}

impl std::fmt::Display for StreamBytesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(e) => write!(f, "{e}"),
            Self::LimitExceeded => write!(f, "body exceeded size limit (aborted)"),
            Self::TooLarge { got, max } => {
                write!(f, "body too large: {got} bytes (max: {max} bytes)")
            }
        }
    }
}

impl std::error::Error for StreamBytesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(e) => Some(e),
            Self::LimitExceeded | Self::TooLarge { .. } => None,
        }
    }
}

/// Streams a response body, enforcing `max_size` according to `on_limit`.
pub(crate) async fn stream_bytes_with_limit(
    response: reqwest::Response,
    max_size: usize,
    on_limit: OnLimit,
    log_label: &str,
) -> Result<StreamedBytes, StreamBytesError> {
    let mut stream = response.bytes_stream();
    let mut accumulated = Vec::with_capacity(max_size.min(64 * 1024));

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(StreamBytesError::Read)?;

        if accumulated.len() + chunk.len() > max_size {
            log::debug!(
                "Body size limit for {log_label} at {} bytes (limit: {max_size} bytes)",
                accumulated.len() + chunk.len(),
            );
            return match on_limit {
                OnLimit::Truncate => {
                    let room = max_size - accumulated.len();
                    accumulated.extend_from_slice(&chunk[..room]);
                    Ok(StreamedBytes::Truncated(accumulated))
                }
                OnLimit::Abort => Err(StreamBytesError::LimitExceeded),
                OnLimit::Error => Err(StreamBytesError::TooLarge {
                    got: accumulated.len().saturating_add(chunk.len()),
                    max: max_size,
                }),
            };
        }

        accumulated.extend_from_slice(&chunk);
    }

    Ok(StreamedBytes::Complete(accumulated))
}

/// Returns an error if the response `Content-Length` header exceeds `max_size`.
pub(crate) fn reject_if_content_length_exceeds(
    response: &reqwest::Response,
    max_size: usize,
    label: &str,
) -> Result<(), anyhow::Error> {
    if let Some(content_length) = response.content_length() {
        if content_length > max_size as u64 {
            return Err(anyhow::anyhow!(
                "{label} too large: {content_length} bytes (max: {max_size} bytes)"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn fetch(req_path: &str, body: impl Into<Vec<u8>>) -> reqwest::Response {
        let server = MockServer::start().await;
        let bytes = body.into();
        Mock::given(method("GET"))
            .and(path(req_path))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
            .mount(&server)
            .await;
        reqwest::Client::new()
            .get(format!("{}{}", server.uri(), req_path))
            .send()
            .await
            .expect("send")
    }

    #[tokio::test]
    async fn truncate_keeps_prefix() {
        let resp = fetch("/t", vec![1u8; 50]).await;
        let streamed = stream_bytes_with_limit(resp, 20, OnLimit::Truncate, "test")
            .await
            .expect("ok");
        assert!(streamed.is_truncated());
        assert_eq!(streamed.into_bytes().len(), 20);
    }

    #[tokio::test]
    async fn complete_within_limit() {
        let resp = fetch("/c", vec![2u8; 10]).await;
        let streamed = stream_bytes_with_limit(resp, 20, OnLimit::Truncate, "test")
            .await
            .expect("ok");
        assert!(!streamed.is_truncated());
        assert_eq!(streamed.into_bytes().len(), 10);
    }

    #[tokio::test]
    async fn abort_on_oversize() {
        let resp = fetch("/a", vec![3u8; 50]).await;
        let err = stream_bytes_with_limit(resp, 20, OnLimit::Abort, "test")
            .await
            .expect_err("abort");
        assert!(matches!(err, StreamBytesError::LimitExceeded));
    }

    #[tokio::test]
    async fn error_on_oversize() {
        let resp = fetch("/e", vec![4u8; 50]).await;
        let err = stream_bytes_with_limit(resp, 20, OnLimit::Error, "test")
            .await
            .expect_err("error");
        assert!(matches!(err, StreamBytesError::TooLarge { max: 20, .. }));
    }
}
