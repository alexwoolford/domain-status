//! Shared export bootstrap: open DB pool, run filtered query, build rows.

use anyhow::{Context, Result};
use futures::TryStreamExt;

use crate::storage::init_db_pool_with_path;

use super::queries::build_export_query;
use super::row::{build_export_row, extract_main_row_data, ExportRow};
use super::ExportOptions;

/// Invoke `on_row` for every export row matching `opts` filters.
///
/// Shared by CSV / JSONL / Parquet so pool + query setup cannot drift.
///
/// # Errors
/// Returns `Err` when the database pool cannot be created, the query fails, or
/// `on_row` returns an error.
pub(crate) async fn for_each_export_row<F>(opts: &ExportOptions, mut on_row: F) -> Result<usize>
where
    F: FnMut(ExportRow) -> Result<()>,
{
    let pool = init_db_pool_with_path(&opts.db_path, 5)
        .await
        .context("Failed to initialize database pool")?;

    let mut query_builder = build_export_query(
        opts.run_id.as_deref(),
        opts.domain.as_deref(),
        opts.status,
        opts.since,
    );

    let query = query_builder.build();
    let mut rows = query.fetch(pool.as_ref());

    let mut record_count = 0usize;
    while let Some(row) = rows.try_next().await? {
        let main = extract_main_row_data(&row);
        let export_row = build_export_row(&pool, main, opts.include_implied_tech).await?;
        on_row(export_row)?;
        record_count += 1;
    }
    Ok(record_count)
}
