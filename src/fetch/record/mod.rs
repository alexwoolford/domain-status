//! Record building and queuing for database insertion.
//!
//! This module handles building URL records and batch records from extracted data,
//! and queuing them for database insertion.

mod builder;
mod detection;
mod preparation;
mod queue;

pub use preparation::prepare_record_for_insertion;
pub use queue::queue_batch_record;
