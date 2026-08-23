//! Execute cookbook SQL fences against a freshly migrated empty `SQLite` DB.
//!
//! Covers `QUERIES.md`, `DATABASE.md`, and `README.md`. Empty result sets are OK;
//! the goal is syntax + schema alignment (not semantic fixtures).

use domain_status::run_migrations;
use sqlx::sqlite::SqlitePoolOptions;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn extract_sql_fences(markdown: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = markdown;
    while let Some(start) = rest.find("```sql") {
        let after_fence = &rest[start + 6..];
        // Allow optional language modifiers / newline after ```sql
        let body_start = after_fence.find('\n').map(|i| i + 1).unwrap_or(0);
        let body = &after_fence[body_start..];
        let Some(end) = body.find("```") else {
            break;
        };
        let sql = body[..end].trim().to_string();
        if !sql.is_empty() {
            out.push(sql);
        }
        rest = &body[end + 3..];
    }
    out
}

fn is_executable_query(sql: &str) -> bool {
    let stripped: String = sql
        .lines()
        .filter(|line| {
            let t = line.trim_start();
            !(t.is_empty() || t.starts_with("--"))
        })
        .collect::<Vec<_>>()
        .join("\n");
    let head = stripped.trim_start().to_ascii_uppercase();
    head.starts_with("SELECT") || head.starts_with("WITH")
}

#[tokio::test]
async fn cookbook_sql_fences_execute_on_migrated_empty_db() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory sqlite");
    run_migrations(&pool)
        .await
        .expect("migrations must succeed");

    let root = workspace_root();
    let files = ["QUERIES.md", "DATABASE.md", "README.md"];
    let mut failures = Vec::new();
    let mut executed = 0usize;

    for rel in files {
        let path = root.join(rel);
        let markdown = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        for (idx, sql) in extract_sql_fences(&markdown).into_iter().enumerate() {
            if !is_executable_query(&sql) {
                continue;
            }
            executed += 1;
            if let Err(e) = sqlx::query(&sql).fetch_all(&pool).await {
                failures.push(format!(
                    "{rel} fence #{idx}: {e}\n--- SQL ---\n{sql}\n-----------"
                ));
            }
        }
    }

    assert!(
        executed > 0,
        "expected to execute at least one SELECT/WITH fence from docs"
    );
    assert!(
        failures.is_empty(),
        "{} cookbook SQL fence(s) failed against migrated empty DB:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}
