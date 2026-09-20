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
}

impl<T> IoErrorContext<T> for Result<T, io::Error> {
    fn with_path<P: AsRef<Path>>(self, path: P) -> Result<T, WrappedIoError> {
        self.map_err(|e| WrappedIoError {
            io_error: e,
            context: path.as_ref().to_string_lossy().to_string(),
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
///
/// Only sets permissions on directories this function creates; leaves pre-existing
/// directories (e.g. system temp dirs) untouched to avoid "Operation not permitted".
pub fn ensure_parent_dir_secure(file_path: &Path) -> io::Result<()> {
    let Some(parent) = file_path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() || parent == Path::new(".") {
        return Ok(());
    }
    #[cfg(unix)]
    let already_exists = parent.is_dir();
    std::fs::create_dir_all(parent)?;
    #[cfg(unix)]
    if !already_exists {
        use std::os::unix::fs::PermissionsExt;
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
    #[cfg(not(unix))]
    let _ = path;
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Kills: `ensure_parent_dir_secure` creating a directory for a bare
    /// filename or `./file` (those parents must be no-ops).
    #[test]
    fn test_ensure_parent_dir_secure_noop_for_bare_filename_and_dot() {
        assert!(
            ensure_parent_dir_secure(Path::new("file.db")).is_ok(),
            "bare filename has an empty parent"
        );
        assert!(
            ensure_parent_dir_secure(Path::new("./file.db")).is_ok(),
            "parent `.` must be a no-op"
        );
    }

    /// Kills: creating the parent without setting mode `0o700`.
    #[test]
    #[cfg(unix)]
    fn test_ensure_parent_dir_secure_creates_owner_only_dir() {
        let tmp = TempDir::new().expect("tempdir");
        let dest = tmp.path().join("nested").join("db.sqlite");
        ensure_parent_dir_secure(&dest).expect("create parent");
        let parent = dest.parent().expect("parent");
        assert!(parent.is_dir());
        let mode = std::fs::metadata(parent)
            .expect("meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "newly created parent must be owner-only");
    }

    /// Kills: chmod'ing a pre-existing parent (must leave `0o755`).
    #[test]
    #[cfg(unix)]
    fn test_ensure_parent_dir_secure_leaves_existing_dir_mode() {
        let tmp = TempDir::new().expect("tempdir");
        let parent = tmp.path().join("already");
        std::fs::create_dir(&parent).expect("mkdir");
        let mut perms = std::fs::metadata(&parent).expect("meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&parent, perms).expect("chmod 755");
        ensure_parent_dir_secure(&parent.join("db.sqlite")).expect("existing parent");
        let mode = std::fs::metadata(&parent)
            .expect("meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755, "pre-existing parent must not be chmod'd");
    }

    /// Kills: `ensure_parent_dir_secure` returning `Ok` when a parent path is
    /// a file.
    #[test]
    fn test_ensure_parent_dir_secure_file_as_parent_is_err() {
        let tmp = TempDir::new().expect("tempdir");
        let blocker = tmp.path().join("not_a_directory");
        std::fs::write(&blocker, b"x").expect("write blocker");
        let dest = blocker.join("db.sqlite");
        assert!(
            ensure_parent_dir_secure(&dest).is_err(),
            "file-as-parent must fail"
        );
    }
}
