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
    use crate::storage::{
        insert_run_metadata, run_migrations, update_run_stats, RunMetadata, RunStats,
    };

    async fn create_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create in-memory test database");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");
        pool
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_url_status_row(
        pool: &SqlitePool,
        domain: &str,
        http_status: i64,
        run_id: &str,
        observed_at_ms: i64,
    ) -> i64 {
        sqlx::query(
            "INSERT INTO url_status (
                initial_domain, final_domain, ip_address, http_status, http_status_text,
                response_time_seconds, title, observed_at_ms, run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id",
        )
        .bind(domain)
        .bind(domain)
        .bind("192.0.2.1")
        .bind(http_status)
        .bind("status text")
        .bind(0.5f64)
        .bind("Test Page")
        .bind(observed_at_ms)
        .bind(run_id)
        .fetch_one(pool)
        .await
        .expect("insert url_status row")
        .get::<i64, _>("id")
    }

    /// Seeds a fully "completed" run (with `end_time_ms` set) carrying:
    /// - two `url_status` rows with different HTTP statuses,
    /// - one observed (`is_implied=0`) and one implied (`is_implied=1`) technology,
    /// - one `url_exposed_secrets` row.
    ///
    /// Returns the run id.
    async fn seed_completed_run(pool: &SqlitePool, run_id: &str, start_time_ms: i64) -> String {
        insert_run_metadata(
            pool,
            &RunMetadata {
                run_id,
                start_time_ms,
                version: "0.1.0-test",
                fingerprints_source: None,
                fingerprints_version: None,
                geoip_version: None,
            },
        )
        .await
        .expect("insert run metadata");

        let url_id_1 = insert_url_status_row(pool, "ok.example", 200, run_id, start_time_ms).await;
        let _url_id_2 =
            insert_url_status_row(pool, "missing.example", 404, run_id, start_time_ms).await;

        sqlx::query(
            "INSERT INTO url_technologies (url_status_id, technology_name, is_implied) VALUES (?, ?, 0)",
        )
        .bind(url_id_1)
        .bind("Nginx")
        .execute(pool)
        .await
        .expect("insert observed technology");

        sqlx::query(
            "INSERT INTO url_technologies (url_status_id, technology_name, is_implied) VALUES (?, ?, 1)",
        )
        .bind(url_id_1)
        .bind("OpenSSL")
        .execute(pool)
        .await
        .expect("insert implied technology");

        sqlx::query(
            "INSERT INTO url_exposed_secrets (url_status_id, secret_type, matched_value, severity, location) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(url_id_1)
        .bind("aws_access_key")
        .bind("AKIAABCDEFGHIJKLMNOP")
        .bind("critical")
        .bind("inline_script")
        .execute(pool)
        .await
        .expect("insert exposed secret");

        update_run_stats(
            pool,
            &RunStats {
                run_id,
                total_urls: 2,
                successful_urls: 2,
                failed_urls: 0,
                skipped_urls: 0,
                elapsed_seconds: 1.23,
            },
        )
        .await
        .expect("update run stats (sets end_time_ms)");

        run_id.to_string()
    }

    /// Seeds a run that has started but not finished (`end_time_ms` stays NULL).
    async fn seed_incomplete_run(pool: &SqlitePool, run_id: &str, start_time_ms: i64) {
        insert_run_metadata(
            pool,
            &RunMetadata {
                run_id,
                start_time_ms,
                version: "0.1.0-test",
                fingerprints_source: None,
                fingerprints_version: None,
                geoip_version: None,
            },
        )
        .await
        .expect("insert incomplete run metadata");
    }

    #[tokio::test]
    async fn test_query_scan_summary_resolves_latest_completed_run_by_default() {
        let pool = create_pool().await;

        seed_completed_run(&pool, "run_completed", 1_704_067_200_000).await;
        // Incomplete run starts *later* than the completed one; it must never be picked
        // as the default "latest completed" run despite the more recent start time.
        seed_incomplete_run(&pool, "run_incomplete", 1_704_067_300_000).await;

        let summary = query_scan_summary(&pool, &SummaryOptions::default())
            .await
            .expect("query_scan_summary should resolve the completed run");

        assert_eq!(summary.run.run_id, "run_completed");
        assert!(
            summary.run.end_time_ms.is_some(),
            "resolved run must be completed (end_time_ms set)"
        );

        let mut status_counts = summary.status_counts.clone();
        status_counts.sort_unstable();
        assert_eq!(status_counts, vec![(200, 1), (404, 1)]);

        assert!(
            summary
                .top_technologies
                .iter()
                .any(|(name, count)| name == "Nginx" && *count == 1),
            "observed Nginx must appear in top_technologies: {:?}",
            summary.top_technologies
        );
        assert!(
            summary
                .top_technologies
                .iter()
                .all(|(name, _)| name != "OpenSSL"),
            "implied-only OpenSSL must be excluded from top_technologies: {:?}",
            summary.top_technologies
        );

        assert_eq!(summary.secret_count, 1);
        assert_eq!(summary.urls_with_secrets, 1);
    }

    #[tokio::test]
    async fn test_query_scan_summary_explicit_run_id_can_target_incomplete_run() {
        let pool = create_pool().await;

        seed_completed_run(&pool, "run_completed", 1_704_067_200_000).await;
        seed_incomplete_run(&pool, "run_incomplete", 1_704_067_300_000).await;

        let summary = query_scan_summary(
            &pool,
            &SummaryOptions {
                run_id: Some("run_incomplete".to_string()),
                top_technologies: 15,
            },
        )
        .await
        .expect("explicit run_id should resolve even for an incomplete run");

        assert_eq!(summary.run.run_id, "run_incomplete");
        assert!(
            summary.run.end_time_ms.is_none(),
            "incomplete run fetched by explicit run_id must still show end_time_ms = NULL"
        );
        assert!(summary.status_counts.is_empty());
        assert!(summary.top_technologies.is_empty());
        assert_eq!(summary.secret_count, 0);
        assert_eq!(summary.urls_with_secrets, 0);
    }

    #[tokio::test]
    async fn test_query_scan_summary_no_completed_runs_errors() {
        let pool = create_pool().await;
        seed_incomplete_run(&pool, "run_incomplete", 1_704_067_200_000).await;

        let result = query_scan_summary(&pool, &SummaryOptions::default()).await;
        assert!(
            result.is_err(),
            "with zero completed runs, run_id: None must error rather than pick an in-progress run"
        );
    }

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
