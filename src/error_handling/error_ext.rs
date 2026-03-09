//! Extension trait for formatting error chains (Mullvad-style).
//!
//! Provides a single, consistent string representation of an error and its causes
//! for user-facing output.

use std::error::Error;
use std::fmt::Write;

/// Extension trait for errors that formats the full error chain.
///
/// Use in `main` or CLI code to print a single, consistent "Error: ... Caused by: ..."
/// message to stderr, then optionally call [`log_error_chain`](crate::error_handling::log_error_chain)
/// to write the same chain to the log.
pub trait ErrorExt {
    /// Returns a string representation of the entire error chain.
    fn display_chain(&self) -> String;

    /// Like [`display_chain`](Self::display_chain) but with an extra message at the start.
    fn display_chain_with_msg(&self, msg: &str) -> String;
}

impl<E: Error + ?Sized> ErrorExt for E {
    fn display_chain(&self) -> String {
        let mut s = format!("Error: {self}");
        let mut source = self.source();
        while let Some(err) = source {
            let _ = write!(&mut s, "\nCaused by: {err}");
            source = err.source();
        }
        s
    }

    fn display_chain_with_msg(&self, msg: &str) -> String {
        let mut s = format!("Error: {msg}\nCaused by: {self}");
        let mut source = self.source();
        while let Some(err) = source {
            let _ = write!(&mut s, "\nCaused by: {err}");
            source = err.source();
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_chain_single_error() {
        let e: anyhow::Error = anyhow::anyhow!("root");
        let s = e.display_chain();
        assert!(s.starts_with("Error: root"));
        assert!(!s.contains("Caused by"));
    }

    #[test]
    fn display_chain_with_cause() {
        let e: anyhow::Error = anyhow::anyhow!("outer").context("inner");
        let s = e.display_chain();
        assert!(s.contains("Error:"));
        assert!(s.contains("Caused by:"));
    }

    #[test]
    fn display_chain_with_msg() {
        let e: anyhow::Error = anyhow::anyhow!("fail");
        let s = e.display_chain_with_msg("something went wrong");
        assert!(s.starts_with("Error: something went wrong"));
        assert!(s.contains("Caused by: fail"));
    }
}
