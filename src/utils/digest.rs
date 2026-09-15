//! SHA-256 hex encoding. `sha2` 0.11's digest type no longer implements `LowerHex`.

use sha2::{Digest, Sha256};

/// Lowercase hex SHA-256 of `data`.
pub(crate) fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    hex_encode_lower(Sha256::digest(data.as_ref()).as_slice())
}

fn hex_encode_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hex_empty_is_known_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
