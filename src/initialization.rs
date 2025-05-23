use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use reqwest::ClientBuilder;
use tldextract::{TldExtractor, TldOption};
use tokio::sync::Semaphore;

use colored::*;
use log::LevelFilter;
use crate::error_handling::InitializationError;
use rustls::crypto::{CryptoProvider, ring::default_provider};

/// Initializes the logger for the application with the provided configuration.
pub fn init_logger() -> Result<(), InitializationError> {
    colored::control::set_override(true);

    let mut builder = env_logger::Builder::new();

    // Set the log level for your crate to Debug and for other crates to a higher level to reduce verbosity
    builder.filter_level(LevelFilter::Debug);
    builder.filter_module("html5ever", LevelFilter::Error);
    builder.filter_module("sqlx", LevelFilter::Debug);
    builder.filter_module("reqwest", LevelFilter::Debug);
    builder.filter_module("hyper", LevelFilter::Debug);
    builder.filter_module("selectors", LevelFilter::Warn);
    builder.filter_module("domain_status", LevelFilter::Debug);

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

/// Installs the default CryptoProvider required by rustls.
pub fn init_crypto_provider() {
    // The return value is ignored because reinstalling the provider is harmless
    let _ = CryptoProvider::install_default(default_provider());
}
