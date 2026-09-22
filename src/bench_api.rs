//! Entry points for `cargo bench --features bench-utils`.
//!
//! Not a stable API. The functions call the same matchers the scan uses,
//! against synthetic rulesets of 15, 500, and 6000 technologies.

use crate::cost::{self, SqliteBench};

/// Technology counts the fingerprint benches are built for.
pub const TECH_COUNTS: [usize; 3] = [15, 500, 6_000];

/// Match `html`, `scriptSrc`, and inline `scripts` patterns for `tech_count`.
///
/// The returned closure closes over a process-lifetime fixture, so build it
/// outside the timed section.
///
/// # Panics
///
/// Panics if `tech_count` is not 15, 500, or 6000.
#[must_use = "the closure performs the measured work"]
pub fn body_matcher(tech_count: usize) -> Box<dyn Fn() -> usize> {
    let fix = cost::fixture(tech_count);
    Box::new(move || cost::match_body(fix))
}

/// Match `scripts` patterns against the 500 KiB script blob.
///
/// # Panics
///
/// Panics if `tech_count` is not 15, 500, or 6000.
#[must_use = "the closure performs the measured work"]
pub fn scripts_matcher(tech_count: usize) -> Box<dyn Fn() -> usize> {
    let fix = cost::fixture(tech_count);
    Box::new(move || cost::match_scripts(fix))
}

/// Run the HTML-body secret scan on the page fixture.
#[must_use = "the closure performs the measured work"]
pub fn html_secret_scan() -> Box<dyn Fn() -> usize> {
    let fix = cost::fixture(6_000);
    Box::new(move || cost::scan_secrets(fix.page_html()))
}

/// Run the secret scan on the 500 KiB script blob.
#[must_use = "the closure performs the measured work"]
pub fn script_secret_scan() -> Box<dyn Fn() -> usize> {
    let fix = cost::fixture(6_000);
    Box::new(move || cost::scan_secrets(fix.script_blob()))
}

/// Parse the page fixture with the production HTML parser.
#[must_use = "the closure performs the measured work"]
pub fn parse_page() -> Box<dyn Fn() -> usize> {
    let fix = cost::fixture(15);
    Box::new(move || cost::parse_page(fix))
}

/// Insert one realistic URL row, including a header, cookie, redirect, and technology.
///
/// # Panics
///
/// Panics if the temporary database cannot be created.
#[must_use = "the closure performs the measured work"]
pub fn sqlite_upsert() -> Box<dyn Fn() -> i64> {
    let bench = SqliteBench::get();
    Box::new(move || bench.upsert_once())
}
