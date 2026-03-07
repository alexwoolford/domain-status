//! Time abstraction for deterministic tests.

use std::time::SystemTime;

/// Abstraction over wall-clock time for cache TTL and other time-dependent logic.
pub trait Clock: Send + Sync + 'static {
    /// Returns the current wall-clock time.
    fn now(&self) -> SystemTime;
}

/// Production clock that delegates to `SystemTime::now()`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}
