//! IO error context helpers (path or message on file errors).
//!
//! Provides `WrappedIoError` and `IoErrorContext` so file operations can attach
//! a path or short message to `std::io::Error`, giving consistent "what file or
//! operation failed" in error output. Aligns with patterns used by projects like
//! innernet.

use std::fmt;
use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Wraps an `io::Error` with a context string (e.g. path or operation name).
///
/// Display format is `{context}: {io_error}` so logs and stderr show which
/// file or step failed.
#[derive(Debug)]
pub struct WrappedIoError {
    /// The underlying IO error.
    pub io_error: io::Error,
    /// Context (path or message) to show with the error.
    pub context: String,
}

impl fmt::Display for WrappedIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.context, self.io_error)
    }
}

impl std::error::Error for WrappedIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.io_error)
    }
}

/// Extension trait for `Result<T, io::Error>` to attach path or message context.
///
/// Use `.with_path(path)` after file operations so errors include the path:
/// `std::fs::read_to_string(path).with_path(path)?`
pub trait IoErrorContext<T> {
    /// Attaches the path as context; the error message will include it.
    fn with_path<P: AsRef<Path>>(self, path: P) -> Result<T, WrappedIoError>;
    /// Attaches a string as context (e.g. operation name).
    #[allow(dead_code)]
    fn with_str<S: Into<String>>(self, context: S) -> Result<T, WrappedIoError>;
}

impl<T> IoErrorContext<T> for Result<T, io::Error> {
    fn with_path<P: AsRef<Path>>(self, path: P) -> Result<T, WrappedIoError> {
        self.map_err(|e| WrappedIoError {
            io_error: e,
            context: path.as_ref().to_string_lossy().to_string(),
        })
    }

    fn with_str<S: Into<String>>(self, context: S) -> Result<T, WrappedIoError> {
        self.map_err(|e| WrappedIoError {
            io_error: e,
            context: context.into(),
        })
    }
}

/// Ensures the parent directory of `file_path` exists and, on Unix, has mode `0o700`.
///
/// Use before creating a database file, log file, or other sensitive output so the
/// containing directory is owner-only (Mullvad-style). No-op if the parent is `.` or
/// the path has no parent.
///
/// # Errors
/// Returns `Err` if creating the directory or setting permissions fails.
pub fn ensure_parent_dir_secure(file_path: &Path) -> io::Result<()> {
    let Some(parent) = file_path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() || parent == Path::new(".") {
        return Ok(());
    }
    std::fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        let mut perms = std::fs::metadata(parent)?.permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(parent, perms)?;
    }
    Ok(())
}

/// Logs a warning if the file at `path` is world-readable (Unix only).
///
/// Call when reading config or other sensitive files so users are prompted to
/// restrict permissions (e.g. `chmod 600`). No-op on non-Unix or if metadata cannot be read.
pub fn warn_if_world_readable(path: &Path) {
    #[cfg(unix)]
    {
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode();
            // World-readable or world-writable
            if (mode & 0o006) != 0 {
                log::warn!(
                    "Config file {} is world-readable (mode {:o}); consider chmod 600 to protect secrets",
                    path.display(),
                    mode & 0o777
                );
            }
        }
    }
}

/// If the error chain contains an IO or path-related error, prints a short hint to stderr.
///
/// Call this after printing the main error and its causes so users get guidance for
/// permission or path issues (config file, database path, output directories).
pub fn print_io_error_hint_if_applicable(error: &anyhow::Error) {
    let has_io = error.chain().any(|cause| {
        cause.downcast_ref::<WrappedIoError>().is_some()
            || cause.downcast_ref::<io::Error>().is_some()
    });
    if has_io {
        eprintln!(
            "Hint: If this looks like a permission or path error, check that the config file, \
             database path, and output directories are readable/writable."
        );
    }
}
