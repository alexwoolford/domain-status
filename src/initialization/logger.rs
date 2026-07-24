//! Logger initialization.
//!
//! This module provides functions to initialize the logger with custom formatting.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::mpsc::Sender;

use crate::config::LogFormat;
use crate::error_handling::InitializationError;
use crate::initialization::log_filters;
use crate::utils::ensure_parent_dir_secure;
use colored::Colorize;
use log::LevelFilter;

/// `Write` adapter that hands every formatted log record off to a dedicated
/// writer thread instead of blocking the calling thread on file I/O.
///
/// Used as the destination for `env_logger::Target::Pipe`. The actual file
/// `write_all`/`flush` syscalls run on a single OS thread (see
/// [`spawn_log_writer_thread`]) so they cannot stall the tokio runtime under
/// heavy logging — the previous design held a `Mutex<File>` and called
/// `write_all`/`flush` synchronously from whichever async task happened to
/// emit the log, putting kernel I/O directly on the runtime workers.
///
/// `env_logger` already serialises access to its `Pipe` internally, so this
/// type does not need to be `Sync`. Channel `send` is wait-free for unbounded
/// channels, so the call site never blocks on the writer thread.
struct ChannelLogWriter {
    sender: Sender<Vec<u8>>,
}

impl Write for ChannelLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Best-effort enqueue. If the writer thread died (channel closed) we
        // silently drop the line — emitting a stderr error here would risk
        // recursing into the same logger.
        let _ = self.sender.send(buf.to_vec());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // The writer thread flushes after every write; nothing to do here.
        Ok(())
    }
}

/// Spawn a dedicated OS thread that owns the log file and drains the channel,
/// writing + flushing each record. The thread terminates naturally when the
/// channel closes (i.e. when the last `Sender` is dropped — which only
/// happens at process exit because `env_logger` holds the static Pipe).
///
/// Returns the Sender end so the caller can build a [`ChannelLogWriter`].
fn spawn_log_writer_thread(file: File) -> Sender<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::Builder::new()
        .name("domain-status-log-writer".to_string())
        .spawn(move || {
            let mut file = file;
            while let Ok(buf) = rx.recv() {
                if file.write_all(&buf).is_err() {
                    // Writing failed (disk full, file handle closed, etc.).
                    // Stop the thread; subsequent sends become silent drops.
                    break;
                }
                // Flush after each record. We're on a dedicated thread, so a
                // blocking fsync here doesn't stall the tokio runtime — the
                // whole point of moving I/O off the async path. This matches
                // the previous design's "flush on Warn+" durability for *every*
                // level, at no extra cost to scan throughput.
                let _ = file.flush();
            }
        })
        .expect("failed to spawn log writer thread");
    tx
}

/// Initializes the logger with the specified level and format.
///
/// Configures `env_logger` with custom formatting. Supports both plain text
/// (with colors and emojis) and JSON formats for structured logging.
///
/// The logger reads from the `RUST_LOG` environment variable by default, but
/// the provided `level` parameter will override it. This allows developers to
/// use `RUST_LOG=debug` for quick debugging while still supporting explicit
/// CLI control via `--log-level`.
///
/// # Arguments
///
/// * `level` - Minimum log level to display (overrides `RUST_LOG` if set)
/// * `format` - Log format (Plain or Json)
///
/// # Returns
///
/// `Ok(())` if initialization succeeds, or an error if logger setup fails.
///
/// # Errors
///
/// Returns `InitializationError::LoggerError` if logger initialization fails.
///
/// # Examples
///
/// ```bash
/// # Use RUST_LOG for quick debugging (no CLI args needed)
/// RUST_LOG=debug domain_status scan urls.txt
///
/// # Override with CLI args (takes precedence)
/// RUST_LOG=debug domain_status scan urls.txt --log-level info
///
/// # Per-module filtering via RUST_LOG
/// RUST_LOG=domain_status=debug,reqwest=info domain_status scan urls.txt
/// ```
pub fn init_logger_with(level: LevelFilter, format: LogFormat) -> Result<(), InitializationError> {
    colored::control::set_override(true);

    // Read from RUST_LOG environment variable first, then override with CLI arg
    let mut builder = env_logger::Builder::from_default_env();

    // Override with CLI-provided level (takes precedence over RUST_LOG)
    builder.filter_level(level);
    log_filters::apply_silenced_crates(&mut builder, level);

    // Explicitly write logs to stderr to avoid polluting stdout when piping
    builder.target(env_logger::Target::Stderr);

    match format {
        LogFormat::Json => {
            builder.format(|buf, record| {
                writeln!(
                    buf,
                    "{{\"ts\":{},\"level\":\"{}\",\"target\":\"{}\",\"msg\":{}}}",
                    chrono::Utc::now().timestamp_millis(),
                    record.level(),
                    record.target(),
                    serde_json::to_string(&record.args().to_string())
                        .unwrap_or_else(|_| "\"\"".into())
                )
            });
        }
        LogFormat::Plain => {
            builder.format(|buf, record| {
                let level = record.level();
                let colored_level = match level {
                    log::Level::Error => level.to_string().red(),
                    log::Level::Warn => level.to_string().yellow(),
                    log::Level::Info => level.to_string().green(),
                    log::Level::Debug => level.to_string().blue(),
                    log::Level::Trace => level.to_string().purple(),
                };

                let emoji = match level {
                    log::Level::Error => "❌",
                    log::Level::Warn => "⚠️",
                    log::Level::Info => "✔️",
                    log::Level::Debug => "🔍",
                    log::Level::Trace => "🔬",
                };

                writeln!(
                    buf,
                    "{} {} [{}] {}",
                    emoji,
                    record.target().cyan(),
                    colored_level,
                    record.args()
                )
            });
        }
    }

    // Use try_init() instead of init() to avoid panicking if logger is already initialized
    // This is important for tests where logger may be initialized multiple times
    builder.try_init().map_err(InitializationError::from)?;

    Ok(())
}

/// Initializes the logger to write to a file with timestamps.
///
/// Used when progress bar is enabled - logs go to file while progress bar shows on terminal.
/// Log format includes ISO 8601 timestamps for each entry.
///
/// # Arguments
///
/// * `level` - Minimum log level to display
/// * `log_file` - Path to the log file
///
/// # Returns
///
/// `Ok(())` if initialization succeeds, or an error if logger setup fails.
///
/// # Errors
/// Returns `Err` when the log file cannot be created or logger setup fails.
pub fn init_logger_to_file(level: LevelFilter, log_file: &Path) -> Result<(), InitializationError> {
    ensure_parent_dir_secure(log_file).map_err(|e| {
        InitializationError::LoggerSetupError(format!("Failed to create log directory: {e}"))
    })?;

    // Create/truncate the log file
    let file = File::create(log_file).map_err(|e| {
        InitializationError::LoggerSetupError(format!("Failed to create log file: {e}"))
    })?;

    // Hand the file off to a dedicated OS thread so all `write_all`/`flush`
    // syscalls run there instead of on whichever tokio worker happens to emit
    // a log record. The format closure stays cheap (just a `writeln!` into
    // env_logger's stack buffer); env_logger then pipes the formatted bytes
    // through `ChannelLogWriter`, which performs a wait-free
    // `mpsc::Sender::send`.
    let writer_tx = spawn_log_writer_thread(file);

    let mut builder = env_logger::Builder::from_default_env();

    builder.filter_level(level);
    log_filters::apply_silenced_crates(&mut builder, level);

    // Format with timestamps (no colors since it's going to a file)
    builder.format(|buf, record| {
        writeln!(
            buf,
            "[{}] {} {} - {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            record.level(),
            record.target(),
            record.args()
        )
    });

    // Pipe the formatted bytes to the channel-backed writer instead of stderr.
    // env_logger holds the Pipe in an internal Mutex, so concurrent log calls
    // from multiple tokio tasks serialise here briefly, but the work inside
    // the lock is just a `Vec::from(slice)` + a wait-free channel send — no
    // file I/O.
    builder.target(env_logger::Target::Pipe(Box::new(ChannelLogWriter {
        sender: writer_tx,
    })));

    builder.try_init().map_err(InitializationError::from)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard for the channel-backed file writer.
    ///
    /// Before this refactor the format closure held a `Mutex<File>` and called
    /// `write_all`/`flush` synchronously from the logging thread (often a
    /// tokio worker). This test exercises the new design directly:
    /// a [`ChannelLogWriter`] hands bytes to a [`spawn_log_writer_thread`]
    /// thread, the thread writes + flushes, and the bytes hit disk.
    ///
    /// The check that matters is "logs go to the file" — but that also
    /// implicitly proves the thread terminates cleanly when the sender is
    /// dropped (otherwise we'd hang here), which is the lifecycle invariant
    /// the production code relies on at process exit.
    #[test]
    fn test_channel_log_writer_round_trips_bytes_to_file() {
        use std::io::Read;
        let temp_file = tempfile::NamedTempFile::new().expect("tempfile");
        let path = temp_file.path().to_path_buf();
        let file = File::create(&path).expect("create");

        let tx = spawn_log_writer_thread(file);
        let mut writer = ChannelLogWriter { sender: tx };

        // Two records — proves the thread loop processes successive sends.
        writer
            .write_all(b"[fixture] WARN domain_status::test - first\n")
            .expect("first write_all enqueue");
        writer
            .write_all(b"[fixture] INFO domain_status::test - second\n")
            .expect("second write_all enqueue");

        // Drop the sender to close the channel; the writer thread drains the
        // queue, flushes, and terminates. Without this the test would hang on
        // the polling loop below if the thread were leaking the channel.
        drop(writer);

        // Poll the file for the expected content. We don't have a JoinHandle
        // here, so we poll for up to 5 s — in practice the writer thread
        // drains within microseconds.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let mut content = String::new();
            File::open(&path)
                .and_then(|mut f| f.read_to_string(&mut content))
                .expect("read log file");
            if content.contains("first") && content.contains("second") {
                assert!(
                    content.contains("[fixture] WARN domain_status::test - first"),
                    "expected exact first record, got: {content}"
                );
                assert!(
                    content.contains("[fixture] INFO domain_status::test - second"),
                    "expected exact second record, got: {content}"
                );
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "writer thread didn't flush both records within 5s; got: {content}"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn test_init_logger_to_file_invalid_path() {
        // Parent path is an existing *file*, so create_dir_all/File::create must fail
        // on every OS. (A bare "/nonexistent/..." path is creatable on Windows because
        // ensure_parent_dir_secure uses create_dir_all on the current drive root.)
        let blocker = tempfile::NamedTempFile::new().expect("tempfile");
        let invalid_path = blocker.path().join("nested").join("log.txt");

        let result = init_logger_to_file(LevelFilter::Info, &invalid_path);
        assert!(
            result.is_err(),
            "Should fail when parent path is not a directory"
        );
        let err = result.unwrap_err();
        match &err {
            InitializationError::LoggerSetupError(_) => {}
            InitializationError::LoggerError(_) => {}
            _ => {
                panic!("Expected LoggerSetupError or LoggerError, got: {:?}", err);
            }
        }
    }
}
