//! Record building for database insertion.
//!
//! This module handles building URL records and batch records from extracted data.

mod builder;
mod detection;
mod preparation;

pub(crate) use detection::detect_technologies_safely;
pub use preparation::prepare_record_for_insertion;
