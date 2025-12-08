//! Complete record data structure.
//!
//! This module defines the BatchRecord type, which is a complete record
//! containing all data needed for database insertion. Records are written
//! directly to the database immediately (no batching - SQLite WAL mode handles
//! concurrency efficiently).

mod types;

pub use types::BatchRecord;
