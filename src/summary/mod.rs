//! Post-scan summary over an existing `SQLite` database.
//!
//! Pure SQL over the current schema — no new tables. Used by `domain-status summary`
//! so users can inspect the last (or a selected) run without opening sqlite3.

use std::fmt::Write as _;

use anyhow::{Context, Result};
use sqlx::{Row, SqlitePool};

use crate::storage::{query_run_by_id, query_run_history, RunSummary};

/// Options for [`query_scan_summary`].
#[derive(Debug, Clone)]
pub struct SummaryOptions {
    /// Restrict to this run id. When `None`, uses the most recent completed run.
    pub run_id: Option<String>,
    /// How many technology rows to include (default 15).
    ///
    /// `0` is treated as 15 (same as the CLI `--top` default).
    pub top_technologies: usize,
}

/// Aggregate view of one selected scan run.
///
/// [`query_scan_summary`] defaults to the latest **completed** run. An explicit
/// `run_id` may target an in-progress run (aggregates can be empty).
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
    /// Distinct `url_status` rows with at least one exposed secret.
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
    // Library callers that pass 0 get the same default as the CLI (`--top` 15).
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

fn write_line(out: &mut String, args: std::fmt::Arguments<'_>) {
    writeln!(out, "{args}").expect("writing to String cannot fail");
}

/// Format a summary as plain text for stdout.
#[must_use]
pub fn format_scan_summary(summary: &ScanSummary) -> String {
    let mut out = String::new();
    let run = &summary.run;

    write_line(&mut out, format_args!("Run: {}", run.run_id));
    if let Some(ref version) = run.version {
        write_line(&mut out, format_args!("Version: {version}"));
    }
    if let Some(elapsed) = run.elapsed_seconds {
        write_line(&mut out, format_args!("Elapsed: {elapsed:.1}s"));
    }
    write_line(
        &mut out,
        format_args!(
            "URLs: {} total — {} succeeded, {} failed, {} skipped",
            run.total_urls, run.successful_urls, run.failed_urls, run.skipped_urls
        ),
    );

    write_line(&mut out, format_args!(""));
    write_line(&mut out, format_args!("HTTP status:"));
    if summary.status_counts.is_empty() {
        write_line(&mut out, format_args!("  (none)"));
    } else {
        for (status, count) in &summary.status_counts {
            write_line(&mut out, format_args!("  {status:>3}: {count}"));
        }
    }

    write_line(&mut out, format_args!(""));
    write_line(
        &mut out,
        format_args!("Top technologies (observed, is_implied=0):"),
    );
    if summary.top_technologies.is_empty() {
        write_line(&mut out, format_args!("  (none)"));
    } else {
        for (name, count) in &summary.top_technologies {
            write_line(&mut out, format_args!("  {count:>4}  {name}"));
        }
    }

    write_line(&mut out, format_args!(""));
    write_line(
        &mut out,
        format_args!(
            "Exposed secrets: {} finding(s) across {} URL(s)",
            summary.secret_count, summary.urls_with_secrets
        ),
    );

    out
}

async fn resolve_run(pool: &SqlitePool, run_id: Option<&str>) -> Result<RunSummary> {
    if let Some(run_id) = run_id {
        return query_run_by_id(pool, run_id)
            .await
            .context("Failed to look up run")?
            .ok_or_else(|| anyhow::anyhow!("No run found with run_id '{run_id}'"));
    }

    let mut history = query_run_history(pool, Some(1))
        .await
        .context("Failed to query run history")?;
    history.pop().context(
        "No completed runs found in the database. Run `domain-status scan` first, \
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
        insert_run_metadata, test_helpers::create_test_pool, update_run_stats, RunMetadata,
        RunStats,
    };

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

    /// Seeds a completed run (`end_time_ms` set) with two 200s + one 404, one observed
    /// tech, one implied tech, and one secret row (severity/location are NOT NULL dummies).
    async fn seed_completed_run(pool: &SqlitePool, run_id: &str, start_time_ms: i64) -> i64 {
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
            insert_url_status_row(pool, "also-ok.example", 200, run_id, start_time_ms).await;
        let _url_id_3 =
            insert_url_status_row(pool, "missing.example", 404, run_id, start_time_ms).await;

        sqlx::query(
            "INSERT INTO url_technologies (url_status_id, technology_name, is_implied) \
             VALUES (?, ?, 0)",
        )
        .bind(url_id_1)
        .bind("Nginx")
        .execute(pool)
        .await
        .expect("insert observed technology");

        sqlx::query(
            "INSERT INTO url_technologies (url_status_id, technology_name, is_implied) \
             VALUES (?, ?, 1)",
        )
        .bind(url_id_1)
        .bind("OpenSSL")
        .execute(pool)
        .await
        .expect("insert implied technology");

        sqlx::query(
            "INSERT INTO url_exposed_secrets \
             (url_status_id, secret_type, matched_value, severity, location) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(url_id_1)
        .bind("fixture_secret_type")
        .bind("fixture-secret-value-001")
        .bind("n/a")
        .bind("n/a")
        .execute(pool)
        .await
        .expect("insert exposed secret");

        update_run_stats(
            pool,
            &RunStats {
                run_id,
                total_urls: 3,
                successful_urls: 3,
                failed_urls: 0,
                skipped_urls: 0,
                elapsed_seconds: 1.23,
            },
        )
        .await
        .expect("update run stats (sets end_time_ms)");

        url_id_1
    }

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
        let pool = create_test_pool().await;

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
        assert_eq!(
            summary.status_counts,
            vec![(200, 2), (404, 1)],
            "histogram must be COUNT DESC, then status ASC (do not sort in the test)"
        );
        assert_eq!(summary.top_technologies, vec![("Nginx".to_string(), 1)]);
        assert_eq!(summary.secret_count, 1);
        assert_eq!(summary.urls_with_secrets, 1);
    }

    #[tokio::test]
    async fn test_query_scan_summary_explicit_run_id_can_target_incomplete_run() {
        let pool = create_test_pool().await;

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
        let pool = create_test_pool().await;
        seed_incomplete_run(&pool, "run_incomplete", 1_704_067_200_000).await;

        let err = query_scan_summary(&pool, &SummaryOptions::default())
            .await
            .expect_err("with zero completed runs, run_id: None must error");
        let msg = err.to_string();
        assert!(
            msg.contains("completed") && msg.contains("--run-id"),
            "error must mention completed runs and --run-id, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_query_scan_summary_unknown_run_id_errors() {
        let pool = create_test_pool().await;
        seed_completed_run(&pool, "run_completed", 1_704_067_200_000).await;

        let err = query_scan_summary(
            &pool,
            &SummaryOptions {
                run_id: Some("run_missing".to_string()),
                top_technologies: 15,
            },
        )
        .await
        .expect_err("unknown run_id must error");
        let msg = err.to_string();
        assert!(
            msg.contains("run_missing"),
            "error must include the requested run id, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_query_scan_summary_top_zero_remaps_to_fifteen() {
        let pool = create_test_pool().await;
        let url_id = seed_completed_run(&pool, "run_completed", 1_704_067_200_000).await;

        for i in 0..16 {
            sqlx::query(
                "INSERT INTO url_technologies (url_status_id, technology_name, is_implied) \
                 VALUES (?, ?, 0)",
            )
            .bind(url_id)
            .bind(format!("T{i:02}"))
            .execute(&pool)
            .await
            .expect("insert extra technology");
        }

        let summary = query_scan_summary(
            &pool,
            &SummaryOptions {
                run_id: Some("run_completed".to_string()),
                top_technologies: 0,
            },
        )
        .await
        .expect("top 0 must query, not omit techs");

        assert_eq!(
            summary.top_technologies.len(),
            15,
            "top_technologies=0 remaps to LIMIT 15, got {:?}",
            summary.top_technologies
        );
        assert!(
            summary
                .top_technologies
                .iter()
                .all(|(name, _)| name != "T15"),
            "16th name T15 must be outside the remapped top 15: {:?}",
            summary.top_technologies
        );
    }

    #[test]
    fn format_scan_summary_gold_output() {
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
        assert_eq!(
            format_scan_summary(&summary),
            "\
Run: run_1
Version: 0.1.0
Elapsed: 1.5s
URLs: 3 total — 2 succeeded, 1 failed, 0 skipped

HTTP status:
  200: 2
  404: 1

Top technologies (observed, is_implied=0):
     2  Nginx

Exposed secrets: 0 finding(s) across 0 URL(s)
"
        );
    }

    #[test]
    fn format_scan_summary_empty_aggregates_print_none() {
        let summary = ScanSummary {
            run: RunSummary {
                run_id: "run_empty".to_string(),
                version: None,
                start_time_ms: 0,
                end_time_ms: None,
                total_urls: 0,
                successful_urls: 0,
                failed_urls: 0,
                skipped_urls: 0,
                elapsed_seconds: None,
            },
            status_counts: vec![],
            top_technologies: vec![],
            secret_count: 0,
            urls_with_secrets: 0,
        };
        assert_eq!(
            format_scan_summary(&summary),
            "\
Run: run_empty
URLs: 0 total — 0 succeeded, 0 failed, 0 skipped

HTTP status:
  (none)

Top technologies (observed, is_implied=0):
  (none)

Exposed secrets: 0 finding(s) across 0 URL(s)
"
        );
    }
}
