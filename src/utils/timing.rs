//! Timing metrics for performance analysis.
//!
//! This module provides timing instrumentation to identify bottlenecks in URL processing.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Timing metrics for a single URL processing operation.
#[derive(Debug, Clone, Default)]
pub struct UrlTimingMetrics {
    /// HTTP request time (including redirects)
    pub http_request_ms: u64,
    /// DNS forward lookup time (hostname to IP)
    pub dns_forward_ms: u64,
    /// DNS reverse lookup time (IP to hostname)
    pub dns_reverse_ms: u64,
    /// DNS additional records time (NS, TXT, MX lookups)
    pub dns_additional_ms: u64,
    /// TLS handshake time
    pub tls_handshake_ms: u64,
    /// HTML parsing time
    pub html_parsing_ms: u64,
    /// Technology detection time
    pub tech_detection_ms: u64,
    /// GeoIP lookup time
    pub geoip_lookup_ms: u64,
    /// WHOIS lookup time
    pub whois_lookup_ms: u64,
    /// Security analysis time
    pub security_analysis_ms: u64,
    /// Total processing time (from start to finish)
    pub total_ms: u64,
}

/// Aggregated timing statistics across all processed URLs.
#[derive(Debug, Default)]
pub struct TimingStats {
    /// Total number of URLs processed
    pub count: Arc<AtomicU64>,
    /// Sum of HTTP request times (for average calculation)
    pub http_request_sum_ms: Arc<AtomicU64>,
    /// Sum of DNS forward lookup times
    pub dns_forward_sum_ms: Arc<AtomicU64>,
    /// Sum of DNS reverse lookup times
    pub dns_reverse_sum_ms: Arc<AtomicU64>,
    /// Sum of DNS additional records times
    pub dns_additional_sum_ms: Arc<AtomicU64>,
    /// Sum of TLS handshake times
    pub tls_handshake_sum_ms: Arc<AtomicU64>,
    /// Sum of HTML parsing times
    pub html_parsing_sum_ms: Arc<AtomicU64>,
    /// Sum of technology detection times
    pub tech_detection_sum_ms: Arc<AtomicU64>,
    /// Sum of GeoIP lookup times
    pub geoip_lookup_sum_ms: Arc<AtomicU64>,
    /// Sum of WHOIS lookup times
    pub whois_lookup_sum_ms: Arc<AtomicU64>,
    /// Sum of security analysis times
    pub security_analysis_sum_ms: Arc<AtomicU64>,
    /// Sum of total processing times
    pub total_sum_ms: Arc<AtomicU64>,
}

impl TimingStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records timing metrics for a single URL.
    pub fn record(&self, metrics: &UrlTimingMetrics) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.http_request_sum_ms
            .fetch_add(metrics.http_request_ms, Ordering::Relaxed);
        self.dns_forward_sum_ms
            .fetch_add(metrics.dns_forward_ms, Ordering::Relaxed);
        self.dns_reverse_sum_ms
            .fetch_add(metrics.dns_reverse_ms, Ordering::Relaxed);
        self.dns_additional_sum_ms
            .fetch_add(metrics.dns_additional_ms, Ordering::Relaxed);
        self.tls_handshake_sum_ms
            .fetch_add(metrics.tls_handshake_ms, Ordering::Relaxed);
        self.html_parsing_sum_ms
            .fetch_add(metrics.html_parsing_ms, Ordering::Relaxed);
        self.tech_detection_sum_ms
            .fetch_add(metrics.tech_detection_ms, Ordering::Relaxed);
        self.geoip_lookup_sum_ms
            .fetch_add(metrics.geoip_lookup_ms, Ordering::Relaxed);
        self.whois_lookup_sum_ms
            .fetch_add(metrics.whois_lookup_ms, Ordering::Relaxed);
        self.security_analysis_sum_ms
            .fetch_add(metrics.security_analysis_ms, Ordering::Relaxed);
        self.total_sum_ms
            .fetch_add(metrics.total_ms, Ordering::Relaxed);
    }

    /// Calculates and returns average times for each operation.
    pub fn averages(&self) -> UrlTimingMetrics {
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 {
            return UrlTimingMetrics::default();
        }

        UrlTimingMetrics {
            http_request_ms: self.http_request_sum_ms.load(Ordering::Relaxed) / count,
            dns_forward_ms: self.dns_forward_sum_ms.load(Ordering::Relaxed) / count,
            dns_reverse_ms: self.dns_reverse_sum_ms.load(Ordering::Relaxed) / count,
            dns_additional_ms: self.dns_additional_sum_ms.load(Ordering::Relaxed) / count,
            tls_handshake_ms: self.tls_handshake_sum_ms.load(Ordering::Relaxed) / count,
            html_parsing_ms: self.html_parsing_sum_ms.load(Ordering::Relaxed) / count,
            tech_detection_ms: self.tech_detection_sum_ms.load(Ordering::Relaxed) / count,
            geoip_lookup_ms: self.geoip_lookup_sum_ms.load(Ordering::Relaxed) / count,
            whois_lookup_ms: self.whois_lookup_sum_ms.load(Ordering::Relaxed) / count,
            security_analysis_ms: self.security_analysis_sum_ms.load(Ordering::Relaxed) / count,
            total_ms: self.total_sum_ms.load(Ordering::Relaxed) / count,
        }
    }

    /// Logs a summary of timing statistics.
    pub fn log_summary(&self) {
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 {
            log::info!("No timing data collected");
            return;
        }

        let avg = self.averages();
        let total_sum = self.total_sum_ms.load(Ordering::Relaxed);

        log::info!("=== Timing Metrics Summary ({} URLs) ===", count);
        log::info!("Average times per URL:");
        let percentage = |part: u64, total: u64| -> f64 {
            if total == 0 {
                0.0
            } else {
                part as f64 / total as f64 * 100.0
            }
        };
        log::info!(
            "  HTTP Request:        {:>6} ms ({:.1}%)",
            avg.http_request_ms,
            percentage(avg.http_request_ms, avg.total_ms)
        );
        log::info!(
            "  DNS Forward:         {:>6} ms ({:.1}%)",
            avg.dns_forward_ms,
            percentage(avg.dns_forward_ms, avg.total_ms)
        );
        log::info!(
            "  DNS Reverse:         {:>6} ms ({:.1}%)",
            avg.dns_reverse_ms,
            percentage(avg.dns_reverse_ms, avg.total_ms)
        );
        log::info!(
            "  DNS Additional:      {:>6} ms ({:.1}%)",
            avg.dns_additional_ms,
            percentage(avg.dns_additional_ms, avg.total_ms)
        );
        log::info!(
            "  TLS Handshake:       {:>6} ms ({:.1}%)",
            avg.tls_handshake_ms,
            percentage(avg.tls_handshake_ms, avg.total_ms)
        );
        log::info!(
            "  HTML Parsing:        {:>6} ms ({:.1}%)",
            avg.html_parsing_ms,
            percentage(avg.html_parsing_ms, avg.total_ms)
        );
        log::info!(
            "  Tech Detection:      {:>6} ms ({:.1}%)",
            avg.tech_detection_ms,
            percentage(avg.tech_detection_ms, avg.total_ms)
        );
        log::info!(
            "  GeoIP Lookup:        {:>6} ms ({:.1}%)",
            avg.geoip_lookup_ms,
            percentage(avg.geoip_lookup_ms, avg.total_ms)
        );
        log::info!(
            "  WHOIS Lookup:        {:>6} ms ({:.1}%)",
            avg.whois_lookup_ms,
            percentage(avg.whois_lookup_ms, avg.total_ms)
        );
        log::info!(
            "  Security Analysis:   {:>6} ms ({:.1}%)",
            avg.security_analysis_ms,
            percentage(avg.security_analysis_ms, avg.total_ms)
        );
        let other_ms = avg.total_ms.saturating_sub(
            avg.http_request_ms
                + avg.dns_forward_ms
                + avg.dns_reverse_ms
                + avg.dns_additional_ms
                + avg.tls_handshake_ms
                + avg.html_parsing_ms
                + avg.tech_detection_ms
                + avg.geoip_lookup_ms
                + avg.whois_lookup_ms
                + avg.security_analysis_ms,
        );
        log::info!(
            "  Other/Overhead:      {:>6} ms ({:.1}%)",
            other_ms,
            percentage(other_ms, avg.total_ms)
        );
        log::info!("  Total:               {:>6} ms", avg.total_ms);
        log::info!(
            "Total time across all URLs: {} ms ({:.2} seconds)",
            total_sum,
            total_sum as f64 / 1000.0
        );
    }
}

/// Helper function to convert a Duration to milliseconds.
pub fn duration_to_ms(duration: Duration) -> u64 {
    duration.as_millis() as u64
}
