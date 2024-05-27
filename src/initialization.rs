use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use reqwest::ClientBuilder;
use tldextract::{TldExtractor, TldOption};
use tokio::sync::Semaphore;

use colored::*;

use crate::error_handling::InitializationError;

/// Initializes the logger for the application with the provided configuration.
pub fn init_logger() -> Result<(), InitializationError> {
    colored::control::set_override(true);

    let mut builder = env_logger::Builder::new();

    builder.filter_level(log::LevelFilter::Info);
    builder.filter_module("html5ever", log::LevelFilter::Error);

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

    builder.init();

    Ok(())
}

/// Initializes a semaphore with the specified count.
pub fn init_semaphore(count: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(count))
}

/// Initializes the HTTP client with default settings.
pub async fn init_client() -> Result<Arc<reqwest::Client>, reqwest::Error> {
    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(10))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
        .build()?;
    Ok(Arc::new(client))
}

/// Initializes the TLD extractor.
pub fn init_extractor() -> Arc<TldExtractor> {
    Arc::new(TldExtractor::new(TldOption::default()))
}
