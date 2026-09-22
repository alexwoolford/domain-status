//! Synthetic page and ruleset fixtures for component-cost measurement.
//!
//! The vendored catalog is about 15 technologies, which hides the cost of a
//! full scan. These fixtures keep the same shape of work as that catalog:
//! thousands of `scriptSrc` patterns and hundreds of `html` / `scripts`
//! patterns, against a fixed page.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, OnceLock};
#[cfg(test)]
use std::time::Instant;
use std::time::SystemTime;

use crate::error_handling::ProcessingStats;
use crate::fingerprint::{
    check_body_with_ruleset, check_scripts_with_ruleset, DetectedTechnology, FingerprintMetadata,
    FingerprintRuleset, Technology,
};
use crate::parse::detect_exposed_secrets;
use crate::storage::insert::insert_persisted_url_record;
use crate::storage::{
    init_db_pool_with_path, run_migrations, CookieInfo, DbPool, PersistedUrlRecord, UrlRecord,
};
#[cfg(test)]
use crate::utils::duration_to_us;

const HTML_BYTES: usize = 100 * 1024;
const INLINE_SCRIPT_BYTES: usize = 200 * 1024;
const SCRIPT_BLOB_BYTES: usize = 500 * 1024;
const SCRIPT_SRC_COUNT: usize = 40;

pub(crate) struct CostFixture {
    ruleset: FingerprintRuleset,
    html: String,
    script_sources: Vec<String>,
    inline_script: String,
    #[cfg_attr(not(feature = "bench-utils"), allow(dead_code))]
    page_html: String,
    script_blob: String,
    meta: HashMap<String, Vec<String>>,
}

/// # Panics
///
/// Panics if `tech_count` is not 15, 500, or 6000.
#[must_use]
pub(crate) fn fixture(tech_count: usize) -> &'static CostFixture {
    match tech_count {
        15 => &FIXTURE_15,
        500 => &FIXTURE_500,
        6_000 => &FIXTURE_6000,
        other => panic!("cost fixture size {other} is not built; use 15, 500, or 6000"),
    }
}

static FIXTURE_15: LazyLock<CostFixture> = LazyLock::new(|| CostFixture::generate(15));
static FIXTURE_500: LazyLock<CostFixture> = LazyLock::new(|| CostFixture::generate(500));
static FIXTURE_6000: LazyLock<CostFixture> = LazyLock::new(|| CostFixture::generate(6_000));

impl CostFixture {
    fn generate(tech_count: usize) -> Self {
        let html = html_haystack();
        let script_sources = script_sources();
        let inline_script = repeated("function init(){return 1;}", INLINE_SCRIPT_BYTES);
        let script_blob = repeated("var value = 0;", SCRIPT_BLOB_BYTES);
        let page_html = page_document(&html, &script_sources, &inline_script);
        Self {
            ruleset: synthetic_ruleset(tech_count),
            html,
            script_sources,
            inline_script,
            page_html,
            script_blob,
            meta: HashMap::new(),
        }
    }

    #[cfg_attr(not(feature = "bench-utils"), allow(dead_code))]
    #[must_use]
    pub(crate) fn page_html(&self) -> &str {
        &self.page_html
    }

    #[cfg_attr(not(feature = "bench-utils"), allow(dead_code))]
    #[must_use]
    pub(crate) fn script_blob(&self) -> &str {
        &self.script_blob
    }
}

fn repeated(unit: &str, min_bytes: usize) -> String {
    let mut out = String::with_capacity(min_bytes);
    while out.len() < min_bytes {
        out.push_str(unit);
    }
    out
}

fn html_haystack() -> String {
    let mut html = String::with_capacity(HTML_BYTES + 64);
    html.push_str("<div id=\"cost-fixture-marker\">");
    while html.len() < HTML_BYTES {
        html.push_str("lorem ipsum dolor sit amet ");
    }
    html.push_str("</div>");
    html
}

fn script_sources() -> Vec<String> {
    (0..SCRIPT_SRC_COUNT)
        .map(|i| format!("/static/app-{i}.js"))
        .collect()
}

fn page_document(html: &str, sources: &[String], inline: &str) -> String {
    let mut page = String::with_capacity(html.len() + inline.len() + 4_096);
    page.push_str("<!DOCTYPE html><html><head><title>Cost fixture</title></head><body>");
    page.push_str(html);
    for src in sources {
        page.push_str("<script src=\"");
        page.push_str(src);
        page.push_str("\"></script>");
    }
    page.push_str("<script>");
    page.push_str(inline);
    page.push_str("</script></body></html>");
    page
}

/// About 10% `html`, 10% `scripts`, and the rest `scriptSrc`, matching the
/// full catalog's emphasis on script-source patterns.
fn synthetic_ruleset(tech_count: usize) -> FingerprintRuleset {
    let mut technologies = HashMap::with_capacity(tech_count);
    for i in 0..tech_count {
        let mut tech = Technology::default();
        if i == 0 {
            tech.html = vec!["cost-fixture-marker".to_string()];
        } else {
            match i % 10 {
                0 => tech.html = vec![format!("html-marker-{i}-zz")],
                1 => tech.scripts = vec![format!("scripts-marker-{i}-zz")],
                _ => tech.script = vec![format!("scriptsrc-marker-{i}-zz")],
            }
        }
        technologies.insert(format!("Tech{i}"), tech);
    }
    FingerprintRuleset {
        technologies,
        categories: HashMap::new(),
        metadata: FingerprintMetadata {
            source: "synthetic-cost".to_string(),
            version: tech_count.to_string(),
            last_updated: SystemTime::UNIX_EPOCH,
        },
    }
}

#[must_use]
pub(crate) fn match_body(fix: &CostFixture) -> usize {
    std::hint::black_box(
        check_body_with_ruleset(
            std::hint::black_box(&fix.ruleset),
            std::hint::black_box(fix.html.as_str()),
            std::hint::black_box(fix.script_sources.as_slice()),
            std::hint::black_box(&fix.meta),
            std::hint::black_box("https://example.com/"),
            std::hint::black_box(fix.inline_script.as_str()),
        )
        .len(),
    )
}

#[cfg_attr(not(feature = "bench-utils"), allow(dead_code))]
#[must_use]
pub(crate) fn match_scripts(fix: &CostFixture) -> usize {
    std::hint::black_box(
        check_scripts_with_ruleset(
            std::hint::black_box(&fix.ruleset),
            std::hint::black_box(fix.script_blob.as_str()),
        )
        .len(),
    )
}

#[must_use]
pub(crate) fn scan_secrets(text: &str) -> usize {
    std::hint::black_box(detect_exposed_secrets(std::hint::black_box(text)).len())
}

#[cfg_attr(not(feature = "bench-utils"), allow(dead_code))]
#[must_use]
pub(crate) fn parse_page(fix: &CostFixture) -> usize {
    let stats = ProcessingStats::new();
    let data = crate::fetch::parse_html_content(
        std::hint::black_box(fix.page_html.as_str()),
        "example.com",
        &stats,
    );
    std::hint::black_box(data.title.len() + data.script_sources.len())
}

#[cfg(test)]
fn elapsed_us(work: impl FnOnce()) -> u64 {
    let started = Instant::now();
    work();
    duration_to_us(started.elapsed())
}

#[cfg_attr(not(feature = "bench-utils"), allow(dead_code))]
pub(crate) struct SqliteBench {
    runtime: tokio::runtime::Runtime,
    pool: DbPool,
}

#[cfg_attr(not(feature = "bench-utils"), allow(dead_code))]
impl SqliteBench {
    #[must_use]
    pub(crate) fn get() -> &'static Self {
        static CTX: OnceLock<SqliteBench> = OnceLock::new();
        CTX.get_or_init(Self::open)
    }

    fn open() -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("cost-bench runtime");
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("domain-status-cost-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("cost-bench db directory");
        let pool = runtime
            .block_on(init_db_pool_with_path(&dir.join("scan.db"), 2))
            .expect("cost-bench database");
        runtime
            .block_on(run_migrations(pool.as_ref()))
            .expect("cost-bench migrations");
        runtime
            .block_on(insert_bench_run(&pool))
            .expect("cost-bench run row");
        Self { runtime, pool }
    }

    #[cfg_attr(not(feature = "bench-utils"), allow(dead_code))]
    #[must_use]
    pub(crate) fn upsert_once(&self) -> i64 {
        let record = realistic_record();
        self.runtime
            .block_on(insert_persisted_url_record(&self.pool, record))
            .expect("cost-bench upsert")
            .id
    }
}

#[cfg_attr(not(feature = "bench-utils"), allow(dead_code))]
async fn insert_bench_run(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO runs (run_id, start_time_ms) VALUES (?, ?)
         ON CONFLICT(run_id) DO NOTHING",
    )
    .bind("cost-bench")
    .bind(1_704_067_200_000_i64)
    .execute(pool.as_ref())
    .await?;
    Ok(())
}

#[cfg_attr(not(feature = "bench-utils"), allow(dead_code))]
fn realistic_record() -> PersistedUrlRecord {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let domain = format!("cost-{id}.example.com");
    let url = format!("https://{domain}/");
    let mut url_record = UrlRecord::test_default();
    url_record.initial_domain = domain.clone();
    url_record.final_domain = domain;
    url_record.initial_url = Some(url.clone());
    url_record.final_url = Some(url);
    url_record.title = "Cost fixture".to_string();
    url_record.run_id = Some("cost-bench".to_string());
    url_record.response_time = 0.2;

    let mut http_headers = HashMap::new();
    http_headers.insert("server".to_string(), "cost-bench".to_string());

    PersistedUrlRecord {
        url_record,
        security_headers: HashMap::new(),
        http_headers,
        oids: std::collections::HashSet::new(),
        redirect_chain: vec![("https://example.com/".to_string(), 301)],
        technologies: vec![DetectedTechnology {
            name: "CostFixture".to_string(),
            version: None,
            category: Some("misc".to_string()),
            is_implied: false,
            detection_source: Some("html".to_string()),
        }],
        subject_alternative_names: vec!["example.com".to_string()],
        analytics_ids: vec![],
        geoip: None,
        structured_data: None,
        social_media_links: vec![],
        contact_links: vec![],
        exposed_secrets: vec![],
        whois: None,
        partial_failures: vec![],
        favicon: None,
        cname_records: None,
        aaaa_records: None,
        caa_records: None,
        csp_domains: Vec::new(),
        cookies: vec![CookieInfo {
            name: "session".to_string(),
            secure: true,
            http_only: true,
            same_site: Some("Lax".to_string()),
            domain: Some("example.com".to_string()),
            path: Some("/".to_string()),
        }],
        resource_hints: vec![("preconnect".to_string(), "example.com".to_string())],
        script_hosts: vec![],
        security_txt: None,
        robots_txt: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{elapsed_us, fixture, match_body, scan_secrets};

    /// Wide headroom over a debug run of the 6000-tech fixture.
    ///
    /// A warm body match was about 2.2s on a developer machine, and the script
    /// secret scan about 14ms. Shared runners are slower, and debug builds are
    /// slower than `cargo bench`. These limits are several times that cost so a
    /// noisy swing stays green and a stage that becomes wildly more expensive
    /// does not. `just bench` prints the optimized numbers.
    const BODY_MATCH_CEILING_US: u64 = 20_000_000;
    const SECRET_SCAN_CEILING_US: u64 = 1_000_000;

    #[test]
    #[ignore = "coarse CPU ceiling; run with `just bench`"]
    fn component_cost_ceiling() {
        let fix = fixture(6_000);
        let _ = match_body(fix);
        let _ = scan_secrets(&fix.script_blob);
        let body_us = elapsed_us(|| {
            let _ = match_body(fix);
        });
        let secret_us = elapsed_us(|| {
            let _ = scan_secrets(&fix.script_blob);
        });
        let per_1k = body_us.saturating_mul(1_000) / 6_000;
        eprintln!(
            "component_cost body_match_6000_us={body_us} us_per_1k_techs={per_1k} secret_scan_script_us={secret_us}"
        );
        assert!(
            body_us < BODY_MATCH_CEILING_US,
            "6000-tech body match took {body_us}us; ceiling is {BODY_MATCH_CEILING_US}us"
        );
        assert!(
            secret_us < SECRET_SCAN_CEILING_US,
            "script secret scan took {secret_us}us; ceiling is {SECRET_SCAN_CEILING_US}us"
        );
    }
}
