//! Batch record data structure.
//!
//! This module defines the BatchRecord type, which is a complete record
//! containing all data needed for database insertion. Records are now
//! written directly to the database without batching.

mod types;

pub use types::BatchRecord;
