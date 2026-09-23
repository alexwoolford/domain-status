//! Every field of `/health`, `/status`, and `/metrics` from one known state.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::State;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::super::types::{
    test_status_state, ErrorCounts, InfoCounts, ScanPhase, StatusResponse, StatusState,
    TimingMetrics, TimingSummary, WarningCounts,
};
use super::health::health_handler;
use super::metrics::{metrics_handler, render_metrics};
use super::status::{build_status_response, status_handler};
use crate::error_handling::{ErrorType, InfoType, ProcessingStats, WarningType};
use crate::initialization::init_rate_limiter;
use crate::runtime_metrics::RuntimeMetrics;
use crate::utils::{TimingStats, UrlTimingMetrics};

const ELAPSED: f64 = 10.0;
const RUN_ID: &str = "sentinel-run";

const SERIES: &[&str] = &[
    "domain_status_run_info",
    "domain_status_elapsed_seconds",
    "domain_status_start_time_seconds",
    "domain_status_total_urls",
    "domain_status_successful_urls",
    "domain_status_failed_urls",
    "domain_status_skipped_urls",
    "domain_status_partial_failures",
    "domain_status_satellite_insert_errors",
    "domain_status_attempted_urls",
    "domain_status_active_urls",
    "domain_status_percentage_complete",
    "domain_status_percentage_dispatched",
    "domain_status_rate_per_second",
    "domain_status_windowed_rate_per_second",
    "domain_status_eta_seconds",
    "domain_status_phase",
    "domain_status_concurrency_limit",
    "domain_status_concurrency_in_use",
    "domain_status_errors_total",
    "domain_status_warnings_total",
    "domain_status_info_total",
    "domain_status_runtime_retries_total",
    "domain_status_runtime_non_retriable_failures_total",
    "domain_status_current_rps",
    "domain_status_timing_http_request_ms",
    "domain_status_timing_dns_forward_ms",
    "domain_status_timing_dns_reverse_ms",
    "domain_status_timing_dns_additional_ms",
    "domain_status_timing_tls_handshake_ms",
    "domain_status_timing_html_parsing_ms",
    "domain_status_timing_body_read_ms",
    "domain_status_timing_html_parse_ms",
    "domain_status_timing_secret_scan_ms",
    "domain_status_timing_tech_detection_ms",
    "domain_status_timing_late_tech_ms",
    "domain_status_timing_external_script_fetch_ms",
    "domain_status_timing_external_script_analysis_ms",
    "domain_status_timing_sqlite_write_ms",
    "domain_status_timing_geoip_lookup_ms",
    "domain_status_timing_whois_lookup_ms",
    "domain_status_timing_total_ms",
];

fn fill_errors(stats: &ProcessingStats) {
    for error in [
        ErrorType::ProcessUrlTimeout,
        ErrorType::HttpRequestTimeoutError,
        ErrorType::HttpRequestConnectError,
        ErrorType::HttpRequestStatusError,
        ErrorType::HttpRequestTooManyRequests,
        ErrorType::HttpRequestBadRequest,
        ErrorType::HttpRequestUnauthorized,
        ErrorType::HttpRequestNotFound,
        ErrorType::HttpRequestInternalServerError,
        ErrorType::HttpRequestBadGateway,
        ErrorType::HttpRequestServiceUnavailable,
        ErrorType::HttpRequestGatewayTimeout,
        ErrorType::HttpRequestBotDetectionError,
        ErrorType::DnsForwardLookupError,
        ErrorType::DnsNsLookupError,
        ErrorType::DnsTxtLookupError,
        ErrorType::DnsMxLookupError,
        ErrorType::DnsCnameLookupError,
        ErrorType::DnsAaaaLookupError,
        ErrorType::DnsCaaLookupError,
        ErrorType::TlsCertificateError,
        ErrorType::HttpRequestDecodeError,
        ErrorType::HttpRequestOtherError,
        ErrorType::HttpRequestBuilderError,
        ErrorType::HttpRequestRedirectError,
        ErrorType::HttpRequestRequestError,
        ErrorType::HttpRequestBodyError,
        ErrorType::TechnologyDetectionError,
    ] {
        stats.increment_error(error);
    }
    stats.increment_warning(WarningType::MissingMetaDescription);
    stats.increment_warning(WarningType::MissingTitle);
    stats.increment_info(InfoType::HttpRedirect);
    stats.increment_info(InfoType::HttpsRedirect);
    stats.increment_info(InfoType::BotDetection403);
    stats.increment_info(InfoType::MultipleRedirects);
}

fn sample_timing() -> UrlTimingMetrics {
    UrlTimingMetrics {
        http_request_us: 2500,
        dns_forward_us: 2500,
        dns_reverse_us: 2500,
        dns_additional_us: 2500,
        tls_handshake_us: 2500,
        html_parsing_us: 2500,
        body_read_us: 2500,
        html_parse_us: 2500,
        secret_scan_us: 2500,
        tech_detection_us: 2500,
        late_tech_us: 2500,
        external_script_fetch_us: 2500,
        external_script_analysis_us: 2500,
        sqlite_write_us: 2500,
        geoip_lookup_us: 2500,
        whois_lookup_us: 2500,
        total_us: 2500,
    }
}

fn timing_ms(ms: u64) -> TimingMetrics {
    TimingMetrics {
        http_request_ms: ms,
        dns_forward_ms: ms,
        dns_reverse_ms: ms,
        dns_additional_ms: ms,
        tls_handshake_ms: ms,
        html_parsing_ms: ms,
        body_read_ms: ms,
        html_parse_ms: ms,
        secret_scan_ms: ms,
        tech_detection_ms: ms,
        late_tech_ms: ms,
        external_script_fetch_ms: ms,
        external_script_analysis_ms: ms,
        sqlite_write_ms: ms,
        geoip_lookup_ms: ms,
        whois_lookup_ms: ms,
        total_ms: ms,
    }
}

async fn known_state() -> (
    StatusState,
    tokio_util::sync::CancellationToken,
    OwnedSemaphorePermit,
) {
    let stats = Arc::new(ProcessingStats::new());
    fill_errors(&stats);
    let timing = Arc::new(TimingStats::new());
    timing.record(&sample_timing());
    let runtime = Arc::new(RuntimeMetrics::default());
    runtime.record_retry();
    runtime.record_retry();
    runtime.record_non_retriable_failure();
    runtime.record_partial_failures(4, 1);
    let (limiter, shutdown) = init_rate_limiter(3, 6).expect("limiter");
    let semaphore = Arc::new(Semaphore::new(8));
    let permit = semaphore.clone().acquire_owned().await.expect("permit");
    let mut state = test_status_state(100, 70, 40, 10, 5);
    state.error_stats = stats;
    state.timing_stats = Some(timing);
    state.request_limiter = Some(limiter);
    state.runtime_metrics = runtime;
    state.run_id = Some(RUN_ID.to_string());
    state.run_start_time_unix_secs = Some(1_700_000_000.0);
    state.phase.set(ScanPhase::Draining);
    state.max_concurrency = Some(8);
    state.semaphore = Some(semaphore);
    (state, shutdown, permit)
}

fn expected_status() -> StatusResponse {
    StatusResponse {
        total_urls: 100,
        total_urls_attempted: 70,
        successful_urls: 40,
        failed_urls: 10,
        skipped_urls: 5,
        active_urls: 15,
        pending_urls: Some(30),
        percentage_complete: (55.0 / 100.0) * 100.0,
        percentage_dispatched: 70.0,
        elapsed_seconds: ELAPSED,
        rate_per_second: 5.5,
        windowed_rate_per_second: 0.0,
        eta_seconds: Some(45.0 / 5.5),
        phase: "draining".to_string(),
        current_rps: Some(3),
        concurrency_limit: Some(8),
        concurrency_in_use: Some(1),
        retried_requests: 2,
        non_retriable_failures: 1,
        partial_failures: 4,
        satellite_insert_errors: 1,
        errors: ErrorCounts {
            total: 28,
            timeout: 2,
            connection_error: 1,
            http_error: 10,
            dns_error: 7,
            tls_error: 1,
            parse_error: 1,
            other_error: 6,
        },
        warnings: WarningCounts {
            total: 2,
            missing_meta_description: 1,
            missing_title: 1,
        },
        info: InfoCounts {
            total: 4,
            http_redirect: 1,
            https_redirect: 1,
            bot_detection_403: 1,
            multiple_redirects: 1,
        },
        timing: Some(TimingSummary {
            count: 1,
            averages: timing_ms(3),
        }),
    }
}

fn samples(body: &str) -> BTreeMap<String, (String, String)> {
    let mut out = BTreeMap::new();
    for line in body.lines() {
        if !line.starts_with("domain_status_") {
            continue;
        }
        let (left, value) = line.rsplit_once(' ').expect("sample");
        let (name, labels) = left.split_once('{').map_or((left, ""), |(name, rest)| {
            (name, rest.trim_end_matches('}'))
        });
        out.insert(name.to_string(), (labels.to_string(), value.to_string()));
    }
    out
}

fn sample<'a>(parsed: &'a BTreeMap<String, (String, String)>, name: &str) -> &'a (String, String) {
    parsed.get(name).unwrap_or_else(|| panic!("missing {name}"))
}

fn assert_counter_series(parsed: &BTreeMap<String, (String, String)>) {
    for (name, expected) in [
        ("domain_status_total_urls", "100"),
        ("domain_status_successful_urls", "40"),
        ("domain_status_failed_urls", "10"),
        ("domain_status_skipped_urls", "5"),
        ("domain_status_attempted_urls", "70"),
        ("domain_status_active_urls", "15"),
        ("domain_status_partial_failures", "4"),
        ("domain_status_satellite_insert_errors", "1"),
        ("domain_status_errors_total", "28"),
        ("domain_status_warnings_total", "2"),
        ("domain_status_info_total", "4"),
        ("domain_status_runtime_retries_total", "2"),
        ("domain_status_runtime_non_retriable_failures_total", "1"),
        ("domain_status_current_rps", "3"),
        ("domain_status_concurrency_limit", "8"),
        ("domain_status_concurrency_in_use", "1"),
        ("domain_status_phase", "2"),
        ("domain_status_run_info", "1"),
    ] {
        assert_eq!(sample(parsed, name).1, expected, "{name}");
    }
    assert_eq!(
        sample(parsed, "domain_status_phase").0,
        "phase=\"draining\""
    );
    assert_eq!(
        sample(parsed, "domain_status_run_info").0,
        "run_id=\"sentinel-run\""
    );
}

fn assert_gauge_series(parsed: &BTreeMap<String, (String, String)>) {
    for (name, expected) in [
        ("domain_status_elapsed_seconds", format!("{ELAPSED}")),
        (
            "domain_status_start_time_seconds",
            format!("{}", 1_700_000_000.0),
        ),
        (
            "domain_status_percentage_complete",
            format!("{}", (55.0 / 100.0) * 100.0),
        ),
        ("domain_status_percentage_dispatched", format!("{}", 70.0)),
        ("domain_status_rate_per_second", format!("{}", 5.5)),
        ("domain_status_windowed_rate_per_second", format!("{}", 0.0)),
        ("domain_status_eta_seconds", format!("{}", 45.0 / 5.5)),
    ] {
        assert_eq!(sample(parsed, name).1, expected, "{name}");
    }
    for name in SERIES {
        if name.contains("_timing_") {
            assert_eq!(sample(parsed, name).1, "3", "{name}");
        }
    }
}

fn assert_series(body: &str) {
    let parsed = samples(body);
    let got: BTreeSet<_> = parsed.keys().cloned().collect();
    let want: BTreeSet<_> = SERIES.iter().copied().map(str::to_string).collect();
    assert_eq!(got, want, "metric series");
    assert_counter_series(&parsed);
    assert_gauge_series(&parsed);
}

async fn assert_handlers(state: StatusState) {
    let health = health_handler().await;
    assert_eq!(health.status(), 200);
    let health_body = axum::body::to_bytes(health.into_body(), 16)
        .await
        .expect("health");
    assert_eq!(health_body.as_ref(), b"ok");

    let status = status_handler(State(state.clone())).await;
    assert_eq!(status.status(), 200);
    let status_body = axum::body::to_bytes(status.into_body(), usize::MAX)
        .await
        .expect("status");
    let parsed: StatusResponse = serde_json::from_slice(&status_body).expect("status json");
    assert_eq!(parsed.total_urls, 100);
    assert_eq!(parsed.phase, "draining");
    assert_eq!(parsed.errors.total, 28);
    assert_eq!(parsed.warnings.total, 2);
    assert_eq!(parsed.info.total, 4);
    assert_eq!(parsed.timing.expect("timing").count, 1);
    assert_eq!(parsed.current_rps, Some(3));
    assert_eq!(parsed.concurrency_in_use, Some(1));

    let metrics = metrics_handler(State(state)).await;
    assert_eq!(metrics.status(), 200);
    let content_type = metrics
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .expect("content-type");
    assert_eq!(content_type, "text/plain; version=0.0.4; charset=utf-8");
    let body = axum::body::to_bytes(metrics.into_body(), usize::MAX)
        .await
        .expect("metrics");
    let text = String::from_utf8(body.to_vec()).expect("utf8");
    let names: BTreeMap<_, _> = samples(&text).into_keys().map(|name| (name, ())).collect();
    let want: BTreeMap<_, _> = SERIES
        .iter()
        .map(|name| ((*name).to_string(), ()))
        .collect();
    assert_eq!(names, want);
}

#[tokio::test]
async fn status_endpoints_cover_every_field() {
    let (state, shutdown, _permit) = known_state().await;
    let built = build_status_response(&state, ELAPSED);
    assert_eq!(built, expected_status());
    assert_series(&render_metrics(&state, ELAPSED));
    assert_handlers(state).await;
    shutdown.cancel();
}
