//! Record building for database insertion.
//!
//! This module builds URL persistence records from extracted data.

mod builder;
mod detection;
mod preparation;

pub(crate) use detection::detect_technologies_safely;
pub use preparation::{prepare_record_for_insertion, RecordPreparationParams};
