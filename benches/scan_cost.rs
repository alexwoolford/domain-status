//! Component-cost benches.
//!
//! `cargo test --all-targets` builds this binary in the test profile. Measuring
//! there would skew `just test`, so the suite runs only under `cargo bench`
//! (bench profile, debug assertions off).

use domain_status::bench_api;

fn main() {
    if cfg!(debug_assertions) {
        return;
    }
    divan::main();
}

#[divan::bench(args = bench_api::TECH_COUNTS, sample_count = 5, sample_size = 1)]
fn fingerprint_body(bencher: divan::Bencher, techs: usize) {
    let run = bench_api::body_matcher(techs);
    bencher.bench_local(run);
}

#[divan::bench(args = bench_api::TECH_COUNTS, sample_count = 5, sample_size = 1)]
fn fingerprint_scripts(bencher: divan::Bencher, techs: usize) {
    let run = bench_api::scripts_matcher(techs);
    bencher.bench_local(run);
}

#[divan::bench(sample_count = 10, sample_size = 1)]
fn secret_scan_html(bencher: divan::Bencher) {
    let run = bench_api::html_secret_scan();
    bencher.bench_local(run);
}

#[divan::bench(sample_count = 10, sample_size = 1)]
fn secret_scan_script(bencher: divan::Bencher) {
    let run = bench_api::script_secret_scan();
    bencher.bench_local(run);
}

#[divan::bench(sample_count = 10, sample_size = 1)]
fn html_parse(bencher: divan::Bencher) {
    let run = bench_api::parse_page();
    bencher.bench_local(run);
}

#[divan::bench(sample_count = 20, sample_size = 1)]
fn sqlite_upsert(bencher: divan::Bencher) {
    let run = bench_api::sqlite_upsert();
    bencher.bench_local(run);
}
