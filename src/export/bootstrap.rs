//! Shared export bootstrap: open DB pool, run filtered query, build rows.

use anyhow::{Context, Result};
use futures::TryStreamExt;

use crate::storage::{init_existing_db_pool, DbPool};

use super::queries::build_export_query;
use super::row::{build_export_row, extract_main_row_data, ExportRow};
use super::ExportOptions;

/// Opens the export database.
///
/// Callers create the output file only after this succeeds, so a missing
/// database does not leave a header-only CSV or an empty JSONL/Parquet file.
///
/// # Errors
/// Returns `Err` when the database file does not exist or the pool cannot be opened.
pub(crate) async fn open_export_pool(opts: &ExportOptions) -> Result<DbPool> {
    init_existing_db_pool(&opts.db_path, 5)
        .await
        .context("Failed to initialize database pool")
}

/// Invoke `on_row` for every export row matching `opts` filters.
///
/// `pool` comes from [`open_export_pool`]. Shared by CSV / JSONL / Parquet so
/// the filtered query cannot drift.
///
/// # Errors
/// Returns `Err` when the query fails, or `on_row` returns an error.
pub(crate) async fn for_each_export_row<F>(
    pool: &DbPool,
    opts: &ExportOptions,
    mut on_row: F,
) -> Result<usize>
where
    F: FnMut(ExportRow) -> Result<()>,
{
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
        let export_row = build_export_row(pool, main, opts.include_implied_tech).await?;
        on_row(export_row)?;
        record_count += 1;
    }
    Ok(record_count)
}
