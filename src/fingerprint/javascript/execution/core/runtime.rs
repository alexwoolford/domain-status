//! QuickJS runtime and context management.

use anyhow::Result;
use rquickjs::{Context, Runtime};

/// Creates a QuickJS runtime with memory limit.
pub fn create_runtime() -> Result<Runtime> {
    let runtime =
        Runtime::new().map_err(|e| anyhow::anyhow!("Failed to create QuickJS runtime: {e}"))?;
    runtime.set_memory_limit(crate::config::MAX_JS_MEMORY_LIMIT);
    Ok(runtime)
}

/// Creates a QuickJS context within a runtime.
pub fn create_context(runtime: &Runtime) -> Result<Context> {
    Context::full(runtime).map_err(|e| anyhow::anyhow!("Failed to create QuickJS context: {e}"))
}
