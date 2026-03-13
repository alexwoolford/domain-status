//! JWT decoding (header + payload, no signature verification).
//!
//! Decodes the first two segments of a JWT token using base64url.
//! No cryptographic verification is performed — these tokens are
//! already exposed on the public web.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;

/// Decoded JWT claims (header + payload).
#[derive(Debug, Clone)]
pub struct DecodedJwt {
    /// Full decoded JWT header as JSON string.
    pub header_json: String,
    /// Full decoded JWT payload as JSON string.
    pub payload_json: String,
    /// Header `alg` claim (e.g., HS256, RS256, none).
    pub algorithm: Option<String>,
    /// Header `typ` claim (usually "JWT").
    pub token_type: Option<String>,
    /// Payload `iss` claim.
    pub issuer: Option<String>,
    /// Payload `sub` claim.
    pub subject: Option<String>,
    /// Payload `aud` claim (stringified if array).
    pub audience: Option<String>,
    /// Payload `exp` claim (converted to epoch milliseconds).
    pub expiration_ms: Option<i64>,
    /// Payload `iat` claim (converted to epoch milliseconds).
    pub issued_at_ms: Option<i64>,
    /// Payload `nbf` claim (converted to epoch milliseconds).
    pub not_before_ms: Option<i64>,
    /// Payload `jti` claim.
    pub jwt_id: Option<String>,
}

/// Attempt to decode a raw JWT string into header + payload.
///
/// Returns `None` if the token is malformed or cannot be decoded.
/// Does not verify the signature — only decodes and parses.
pub fn decode_jwt(token: &str) -> Option<DecodedJwt> {
    let token = token.trim().trim_end_matches('\\');
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    let header_bytes = base64url_decode(parts[0])?;
    let payload_bytes = base64url_decode(parts[1])?;

    let header_str = String::from_utf8(header_bytes).ok()?;
    let payload_str = String::from_utf8(payload_bytes).ok()?;

    let header: Value = serde_json::from_str(&header_str).ok()?;
    let payload: Value = serde_json::from_str(&payload_str).ok()?;

    let algorithm = header.get("alg").and_then(Value::as_str).map(String::from);
    let token_type = header.get("typ").and_then(Value::as_str).map(String::from);
    let issuer = payload.get("iss").and_then(Value::as_str).map(String::from);
    let subject = payload.get("sub").and_then(Value::as_str).map(String::from);
    let audience = payload.get("aud").map(|v| match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    });
    let expiration_ms = epoch_seconds_to_ms(&payload, "exp");
    let issued_at_ms = epoch_seconds_to_ms(&payload, "iat");
    let not_before_ms = epoch_seconds_to_ms(&payload, "nbf");
    let jwt_id = payload.get("jti").and_then(Value::as_str).map(String::from);

    Some(DecodedJwt {
        header_json: header_str,
        payload_json: payload_str,
        algorithm,
        token_type,
        issuer,
        subject,
        audience,
        expiration_ms,
        issued_at_ms,
        not_before_ms,
        jwt_id,
    })
}

/// Attempt to decode a base64-encoded JWT (`jwt-base64` secret type).
///
/// First base64-decodes the outer wrapper, then decodes the inner JWT.
pub fn decode_jwt_base64(encoded: &str) -> Option<DecodedJwt> {
    let inner_bytes = base64url_decode(encoded.trim())?;
    let inner_str = String::from_utf8(inner_bytes).ok()?;
    decode_jwt(&inner_str)
}

/// Base64url decode with fallback for padding variations.
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    // Try URL_SAFE_NO_PAD first (standard JWT encoding)
    URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| {
            // Some tokens use standard base64 or have padding
            use base64::engine::general_purpose::URL_SAFE;
            URL_SAFE.decode(input)
        })
        .or_else(|_| {
            // Last resort: add padding and retry
            let padded = match input.len() % 4 {
                2 => format!("{input}=="),
                3 => format!("{input}="),
                _ => input.to_string(),
            };
            URL_SAFE_NO_PAD.decode(&padded)
        })
        .ok()
}

/// Extract an epoch-seconds claim and convert to milliseconds.
#[allow(clippy::cast_possible_truncation)] // JWT epoch timestamps (f64 seconds) fit in i64
fn epoch_seconds_to_ms(payload: &Value, key: &str) -> Option<i64> {
    payload
        .get(key)
        .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
        .map(|secs| secs.saturating_mul(1000))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real Netlify JWT (header: {"alg":"HS256","typ":"JWT"}, payload has iss, site_id, etc.)
    const NETLIFY_JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzaXRlX2lkIjoiYTg1ZGYwMDMtZGUyMi00ZTNjLThkODItZDAzMzk5MzVjZTY3IiwiYWNjb3VudF9pZCI6IjYzNDlkYmEzNzI2ODMwMTVhY2Y4ZmI3ZSIsImRlcGxveV9pZCI6IjY5YjJmOWYwMDUzMzgxMDAwODc0NjIyYyIsImlzcyI6Im5ldGxpZnkifQ.7cZdXD18ikgVB87TjYZREggugzGweI0ri0VumAUGDG4";

    #[test]
    fn test_decode_valid_jwt() {
        let result = decode_jwt(NETLIFY_JWT);
        assert!(result.is_some(), "Should decode valid JWT");
        let jwt = result.unwrap();

        assert_eq!(jwt.algorithm.as_deref(), Some("HS256"));
        assert_eq!(jwt.token_type.as_deref(), Some("JWT"));
        assert_eq!(jwt.issuer.as_deref(), Some("netlify"));
        assert!(jwt.header_json.contains("\"alg\""));
        assert!(jwt.payload_json.contains("\"site_id\""));
    }

    #[test]
    fn test_decode_jwt_with_expiration() {
        // header: {"alg":"HS256"}, payload: {"sub":"1234","exp":1700000000,"iat":1699999000}
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0IiwiZXhwIjoxNzAwMDAwMDAwLCJpYXQiOjE2OTk5OTkwMDB9.signature";
        let jwt = decode_jwt(token).unwrap();

        assert_eq!(jwt.subject.as_deref(), Some("1234"));
        assert_eq!(jwt.expiration_ms, Some(1_700_000_000_000));
        assert_eq!(jwt.issued_at_ms, Some(1_699_999_000_000));
    }

    #[test]
    fn test_decode_malformed_jwt() {
        assert!(decode_jwt("not-a-jwt").is_none());
        assert!(decode_jwt("only.two").is_none());
        assert!(decode_jwt("a.b.c.d").is_none());
        assert!(decode_jwt("").is_none());
    }

    #[test]
    fn test_decode_invalid_base64() {
        assert!(decode_jwt("!!!.!!!.!!!").is_none());
    }

    #[test]
    fn test_decode_invalid_json() {
        // Valid base64url but not JSON
        let not_json = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not json");
        let token = format!("{not_json}.{not_json}.sig");
        assert!(decode_jwt(&token).is_none());
    }

    #[test]
    fn test_decode_jwt_with_trailing_backslash() {
        let with_backslash = format!("{NETLIFY_JWT}\\");
        let jwt = decode_jwt(&with_backslash).unwrap();
        assert_eq!(jwt.algorithm.as_deref(), Some("HS256"));
    }

    #[test]
    fn test_decode_jwt_minimal_claims() {
        // header: {"alg":"none"}, payload: {}
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(b"{}");
        let token = format!("{header}.{payload}.sig");
        let jwt = decode_jwt(&token).unwrap();

        assert_eq!(jwt.algorithm.as_deref(), Some("none"));
        assert!(jwt.issuer.is_none());
        assert!(jwt.expiration_ms.is_none());
    }

    #[test]
    fn test_decode_jwt_audience_string() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"aud":"my-app"}"#);
        let token = format!("{header}.{payload}.sig");
        let jwt = decode_jwt(&token).unwrap();
        assert_eq!(jwt.audience.as_deref(), Some("my-app"));
    }

    #[test]
    fn test_decode_jwt_audience_array() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"aud":["app1","app2"]}"#);
        let token = format!("{header}.{payload}.sig");
        let jwt = decode_jwt(&token).unwrap();
        assert_eq!(jwt.audience.as_deref(), Some(r#"["app1","app2"]"#));
    }

    #[test]
    fn test_decode_jwt_base64_returns_none_for_plain_jwt() {
        // decode_jwt_base64 expects a base64-wrapped JWT, not a plain one
        assert!(decode_jwt_base64(NETLIFY_JWT).is_none());
    }
}
