//! Post-scan summary over an existing `SQLite` database.
//!
//! Pure SQL over the current schema — no new tables. Used by `domain_status summary`
//! so users can inspect the last (or a selected) run without opening sqlite3.

use anyhow::{bail, Context, Result};
use sqlx::{Row, SqlitePool};

use crate::storage::{query_run_history, RunSummary};

/// Options for [`query_scan_summary`].
#[derive(Debug, Clone)]
pub struct SummaryOptions {
    /// Restrict to this run id. When `None`, uses the most recent completed run.
    pub run_id: Option<String>,
    /// How many technology rows to include (default 15).
    pub top_technologies: usize,
}

/// Aggregate view of one completed scan run.
#[derive(Debug, Clone)]
pub struct ScanSummary {
    /// Run metadata (counts, timing).
    pub run: RunSummary,
    /// `(http_status, count)` ordered by count descending.
    pub status_counts: Vec<(i64, i64)>,
    /// `(technology_name, count)` for observed (non-implied) techs, top N.
    pub top_technologies: Vec<(String, i64)>,
    /// Total exposed-secret findings for URLs in this run.
    pub secret_count: i64,
    /// Distinct domains with at least one exposed secret.
    pub urls_with_secrets: i64,
}

impl Default for SummaryOptions {
    fn default() -> Self {
        Self {
            run_id: None,
            top_technologies: 15,
        }
    }
}

/// Resolve which run to summarize and collect status / tech / secret aggregates.
///
/// # Errors
/// Returns an error when the database cannot be queried, no completed runs exist,
/// or the requested `run_id` is missing.
pub async fn query_scan_summary(
    pool: &SqlitePool,
    options: &SummaryOptions,
) -> Result<ScanSummary> {
    let run = resolve_run(pool, options.run_id.as_deref()).await?;
    let top_n = if options.top_technologies == 0 {
        15
    } else {
        options.top_technologies
    };

    let status_counts = query_status_counts(pool, &run.run_id).await?;
    let top_technologies = query_top_technologies(pool, &run.run_id, top_n).await?;
    let (secret_count, urls_with_secrets) = query_secret_stats(pool, &run.run_id).await?;

    Ok(ScanSummary {
        run,
        status_counts,
        top_technologies,
        secret_count,
        urls_with_secrets,
    })
}

/// Format a summary as plain text for stdout.
#[must_use]
pub fn format_scan_summary(summary: &ScanSummary) -> String {
    let mut out = String::new();
    let run = &summary.run;

    out.push_str(&format!("Run: {}\n", run.run_id));
    if let Some(ref version) = run.version {
        out.push_str(&format!("Version: {version}\n"));
    }
    if let Some(elapsed) = run.elapsed_seconds {
        out.push_str(&format!("Elapsed: {elapsed:.1}s\n"));
    }
    out.push_str(&format!(
        "URLs: {} total — {} succeeded, {} failed, {} skipped\n",
        run.total_urls, run.successful_urls, run.failed_urls, run.skipped_urls
    ));

    out.push_str("\nHTTP status:\n");
    if summary.status_counts.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for (status, count) in &summary.status_counts {
            out.push_str(&format!("  {status:>3}: {count}\n"));
        }
    }

    out.push_str("\nTop technologies (observed, is_implied=0):\n");
    if summary.top_technologies.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for (name, count) in &summary.top_technologies {
            out.push_str(&format!("  {count:>4}  {name}\n"));
        }
    }

    out.push_str(&format!(
        "\nExposed secrets: {} finding(s) across {} URL(s)\n",
        summary.secret_count, summary.urls_with_secrets
    ));

    out
}

async fn resolve_run(pool: &SqlitePool, run_id: Option<&str>) -> Result<RunSummary> {
    if let Some(run_id) = run_id {
        let row = sqlx::query(
            "SELECT run_id, version, start_time_ms, end_time_ms, total_urls, successful_urls, \
             failed_urls, skipped_urls, elapsed_seconds \
             FROM runs WHERE run_id = ?",
        )
        .bind(run_id)
        .fetch_optional(pool)
        .await
        .context("Failed to look up run")?;

        let Some(row) = row else {
            bail!("No run found with run_id '{run_id}'");
        };

        return Ok(RunSummary {
            run_id: row.get("run_id"),
            version: row.get("version"),
            start_time_ms: row.get("start_time_ms"),
            end_time_ms: row.get("end_time_ms"),
            total_urls: row.get("total_urls"),
            successful_urls: row.get("successful_urls"),
            failed_urls: row.get("failed_urls"),
            skipped_urls: row.get("skipped_urls"),
            elapsed_seconds: row.get("elapsed_seconds"),
        });
    }

    let mut history = query_run_history(pool, Some(1))
        .await
        .context("Failed to query run history")?;
    history.pop().context(
        "No completed runs found in the database. Run `domain_status scan` first, \
         or pass --run-id for an in-progress run.",
    )
}

async fn query_status_counts(pool: &SqlitePool, run_id: &str) -> Result<Vec<(i64, i64)>> {
    let rows = sqlx::query(
        "SELECT http_status AS status, COUNT(*) AS cnt \
         FROM url_status WHERE run_id = ? \
         GROUP BY http_status ORDER BY cnt DESC, status ASC",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await
    .context("Failed to query HTTP status counts")?;

    Ok(rows
        .into_iter()
        .map(|row| {
            let status: i64 = row.get("status");
            let cnt: i64 = row.get("cnt");
            (status, cnt)
        })
        .collect())
}

async fn query_top_technologies(
    pool: &SqlitePool,
    run_id: &str,
    limit: usize,
) -> Result<Vec<(String, i64)>> {
    // is_implied exists from migration 0010; filter to observed-only evidence.
    let rows = sqlx::query(
        "SELECT t.technology_name AS name, COUNT(*) AS cnt \
         FROM url_technologies t \
         INNER JOIN url_status u ON u.id = t.url_status_id \
         WHERE u.run_id = ? AND COALESCE(t.is_implied, 0) = 0 \
         GROUP BY t.technology_name \
         ORDER BY cnt DESC, name ASC \
         LIMIT ?",
    )
    .bind(run_id)
    .bind(i64::try_from(limit).unwrap_or(15))
    .fetch_all(pool)
    .await
    .context("Failed to query top technologies")?;

    Ok(rows
        .into_iter()
        .map(|row| {
            let name: String = row.get("name");
            let cnt: i64 = row.get("cnt");
            (name, cnt)
        })
        .collect())
}

async fn query_secret_stats(pool: &SqlitePool, run_id: &str) -> Result<(i64, i64)> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS secret_count, \
                COUNT(DISTINCT s.url_status_id) AS urls_with_secrets \
         FROM url_exposed_secrets s \
         INNER JOIN url_status u ON u.id = s.url_status_id \
         WHERE u.run_id = ?",
    )
    .bind(run_id)
    .fetch_one(pool)
    .await
    .context("Failed to query exposed secret counts")?;

    Ok((row.get("secret_count"), row.get("urls_with_secrets")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_scan_summary_includes_sections() {
        let summary = ScanSummary {
            run: RunSummary {
                run_id: "run_1".to_string(),
                version: Some("0.1.0".to_string()),
                start_time_ms: 0,
                end_time_ms: Some(1000),
                total_urls: 3,
                successful_urls: 2,
                failed_urls: 1,
                skipped_urls: 0,
                elapsed_seconds: Some(1.5),
            },
            status_counts: vec![(200, 2), (404, 1)],
            top_technologies: vec![("Nginx".to_string(), 2)],
            secret_count: 0,
            urls_with_secrets: 0,
        };
        let text = format_scan_summary(&summary);
        assert!(text.contains("Run: run_1"));
        assert!(text.contains("HTTP status:"));
        assert!(text.contains("200: 2"));
        assert!(text.contains("Nginx"));
        assert!(text.contains("Exposed secrets: 0"));
    }
}
