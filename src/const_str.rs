//! Const `&str` helpers for compile-time inventory asserts.
//!
//! Tarpaulin does not observe `const fn` bodies; `const _: () = assert!(...)`
//! already fails the build if these helpers are wrong.

/// Byte-wise equality usable in `const` (no `PartialEq` on slices in const).
pub(crate) const fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether `haystack` contains `needle` (const, string identity).
pub(crate) const fn slice_contains(haystack: &[&str], needle: &str) -> bool {
    let mut i = 0;
    while i < haystack.len() {
        if bytes_eq(haystack[i].as_bytes(), needle.as_bytes()) {
            return true;
        }
        i += 1;
    }
    false
}
