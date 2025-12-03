//! Timing metrics for performance analysis.
//!
//! This module provides timing instrumentation to identify bottlenecks in URL processing.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Timing metrics for a single URL processing operation.
///
/// All times are stored in microseconds for precision, then converted to milliseconds
/// only when displaying to users.
#[derive(Debug, Clone, Default)]
pub struct UrlTimingMetrics {
    /// HTTP request time (including redirects) in microseconds
    pub http_request_ms: u64,
    /// DNS forward lookup time (hostname to IP) in microseconds
    pub dns_forward_ms: u64,
    /// DNS reverse lookup time (IP to hostname) in microseconds
    pub dns_reverse_ms: u64,
    /// DNS additional records time (NS, TXT, MX lookups) in microseconds
    pub dns_additional_ms: u64,
    /// TLS handshake time in microseconds
    pub tls_handshake_ms: u64,
    /// HTML parsing time in microseconds
    pub html_parsing_ms: u64,
    /// Technology detection time in microseconds
    pub tech_detection_ms: u64,
    /// GeoIP lookup time in microseconds
    pub geoip_lookup_ms: u64,
    /// WHOIS lookup time in microseconds
    pub whois_lookup_ms: u64,
    /// Security analysis time in microseconds
    pub security_analysis_ms: u64,
    /// Total processing time (from start to finish) in microseconds
    pub total_ms: u64,
}

/// Aggregated timing statistics across all processed URLs.
///
/// All times are stored in microseconds for precision, then converted to milliseconds
/// only when displaying to users.
#[derive(Debug, Default)]
pub struct TimingStats {
    /// Total number of URLs processed
    pub count: Arc<AtomicU64>,
    /// Sum of HTTP request times in microseconds (for average calculation)
    pub http_request_sum_ms: Arc<AtomicU64>,
    /// Sum of DNS forward lookup times in microseconds
    pub dns_forward_sum_ms: Arc<AtomicU64>,
    /// Sum of DNS reverse lookup times in microseconds
    pub dns_reverse_sum_ms: Arc<AtomicU64>,
    /// Sum of DNS additional records times in microseconds
    pub dns_additional_sum_ms: Arc<AtomicU64>,
    /// Sum of TLS handshake times in microseconds
    pub tls_handshake_sum_ms: Arc<AtomicU64>,
    /// Sum of HTML parsing times in microseconds
    pub html_parsing_sum_ms: Arc<AtomicU64>,
    /// Sum of technology detection times in microseconds
    pub tech_detection_sum_ms: Arc<AtomicU64>,
    /// Sum of GeoIP lookup times in microseconds
    pub geoip_lookup_sum_ms: Arc<AtomicU64>,
    /// Sum of WHOIS lookup times in microseconds
    pub whois_lookup_sum_ms: Arc<AtomicU64>,
    /// Sum of security analysis times in microseconds
    pub security_analysis_sum_ms: Arc<AtomicU64>,
    /// Sum of total processing times in microseconds
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

    /// Calculates and returns average times for each operation (in microseconds).
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

    /// Converts microseconds to milliseconds for display (rounds to nearest).
    fn micros_to_ms(micros: u64) -> u64 {
        (micros + 500) / 1000 // Round to nearest millisecond
    }

    /// Formats a timing value, showing microseconds if the average rounds to 0ms but total is non-zero.
    fn format_timing_with_micros(
        sum_micros: u64,
        avg_ms: u64,
        name: &str,
        percentage: f64,
    ) -> String {
        if avg_ms == 0 && sum_micros > 0 {
            // Average rounds to 0ms but total is non-zero - show in microseconds
            format!(
                "  {:20} {:>6} ms ({:.1}%) (< 1ms avg, {}μs total)",
                name, avg_ms, percentage, sum_micros
            )
        } else {
            // Normal display in milliseconds
            format!("  {:20} {:>6} ms ({:.1}%)", name, avg_ms, percentage)
        }
    }

    /// Logs a summary of timing statistics.
    ///
    /// Optionally accepts flags to indicate whether GeoIP and WHOIS are enabled,
    /// which will be displayed in the output when these features are disabled.
    pub fn log_summary(&self, geoip_enabled: Option<bool>, whois_enabled: Option<bool>) {
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 {
            log::info!("No timing data collected");
            return;
        }

        let avg = self.averages(); // Returns values in microseconds
        let total_sum_micros = self.total_sum_ms.load(Ordering::Relaxed);

        // Convert to milliseconds for display
        let avg_ms = UrlTimingMetrics {
            http_request_ms: Self::micros_to_ms(avg.http_request_ms),
            dns_forward_ms: Self::micros_to_ms(avg.dns_forward_ms),
            dns_reverse_ms: Self::micros_to_ms(avg.dns_reverse_ms),
            dns_additional_ms: Self::micros_to_ms(avg.dns_additional_ms),
            tls_handshake_ms: Self::micros_to_ms(avg.tls_handshake_ms),
            html_parsing_ms: Self::micros_to_ms(avg.html_parsing_ms),
            tech_detection_ms: Self::micros_to_ms(avg.tech_detection_ms),
            geoip_lookup_ms: Self::micros_to_ms(avg.geoip_lookup_ms),
            whois_lookup_ms: Self::micros_to_ms(avg.whois_lookup_ms),
            security_analysis_ms: Self::micros_to_ms(avg.security_analysis_ms),
            total_ms: Self::micros_to_ms(avg.total_ms),
        };
        let total_sum_ms = Self::micros_to_ms(total_sum_micros);

        log::info!("=== Timing Metrics Summary ({} URLs) ===", count);
        log::info!("Average times per URL:");
        let percentage = |part: u64, total: u64| -> f64 {
            if total == 0 {
                0.0
            } else {
                part as f64 / total as f64 * 100.0
            }
        };

        // Helper to get sum in microseconds for each metric
        let http_sum_micros = self.http_request_sum_ms.load(Ordering::Relaxed);
        log::info!(
            "{}",
            Self::format_timing_with_micros(
                http_sum_micros,
                avg_ms.http_request_ms,
                "HTTP Request:",
                percentage(avg_ms.http_request_ms, avg_ms.total_ms),
            )
        );

        let dns_forward_sum_micros = self.dns_forward_sum_ms.load(Ordering::Relaxed);
        log::info!(
            "{}",
            Self::format_timing_with_micros(
                dns_forward_sum_micros,
                avg_ms.dns_forward_ms,
                "DNS Forward:",
                percentage(avg_ms.dns_forward_ms, avg_ms.total_ms),
            )
        );

        let dns_reverse_sum_micros = self.dns_reverse_sum_ms.load(Ordering::Relaxed);
        log::info!(
            "{}",
            Self::format_timing_with_micros(
                dns_reverse_sum_micros,
                avg_ms.dns_reverse_ms,
                "DNS Reverse:",
                percentage(avg_ms.dns_reverse_ms, avg_ms.total_ms),
            )
        );

        let dns_additional_sum_micros = self.dns_additional_sum_ms.load(Ordering::Relaxed);
        log::info!(
            "{}",
            Self::format_timing_with_micros(
                dns_additional_sum_micros,
                avg_ms.dns_additional_ms,
                "DNS Additional:",
                percentage(avg_ms.dns_additional_ms, avg_ms.total_ms),
            )
        );

        let tls_sum_micros = self.tls_handshake_sum_ms.load(Ordering::Relaxed);
        log::info!(
            "{}",
            Self::format_timing_with_micros(
                tls_sum_micros,
                avg_ms.tls_handshake_ms,
                "TLS Handshake:",
                percentage(avg_ms.tls_handshake_ms, avg_ms.total_ms),
            )
        );

        let html_sum_micros = self.html_parsing_sum_ms.load(Ordering::Relaxed);
        log::info!(
            "{}",
            Self::format_timing_with_micros(
                html_sum_micros,
                avg_ms.html_parsing_ms,
                "HTML Parsing:",
                percentage(avg_ms.html_parsing_ms, avg_ms.total_ms),
            )
        );

        let tech_sum_micros = self.tech_detection_sum_ms.load(Ordering::Relaxed);
        log::info!(
            "{}",
            Self::format_timing_with_micros(
                tech_sum_micros,
                avg_ms.tech_detection_ms,
                "Tech Detection:",
                percentage(avg_ms.tech_detection_ms, avg_ms.total_ms),
            )
        );
        // GeoIP Lookup - show "(disabled)" if GeoIP is not enabled, or show total in microseconds if very fast
        let geoip_sum_micros = self.geoip_lookup_sum_ms.load(Ordering::Relaxed);
        if let Some(false) = geoip_enabled {
            log::info!(
                "  GeoIP Lookup:        {:>6} ms ({:.1}%) (disabled)",
                avg_ms.geoip_lookup_ms,
                percentage(avg_ms.geoip_lookup_ms, avg_ms.total_ms)
            );
        } else {
            log::info!(
                "{}",
                Self::format_timing_with_micros(
                    geoip_sum_micros,
                    avg_ms.geoip_lookup_ms,
                    "GeoIP Lookup:",
                    percentage(avg_ms.geoip_lookup_ms, avg_ms.total_ms),
                )
            );
        }

        // WHOIS Lookup - show "(disabled)" if WHOIS is not enabled
        let whois_sum_micros = self.whois_lookup_sum_ms.load(Ordering::Relaxed);
        if let Some(false) = whois_enabled {
            log::info!(
                "  WHOIS Lookup:        {:>6} ms ({:.1}%) (disabled)",
                avg_ms.whois_lookup_ms,
                percentage(avg_ms.whois_lookup_ms, avg_ms.total_ms)
            );
        } else {
            log::info!(
                "{}",
                Self::format_timing_with_micros(
                    whois_sum_micros,
                    avg_ms.whois_lookup_ms,
                    "WHOIS Lookup:",
                    percentage(avg_ms.whois_lookup_ms, avg_ms.total_ms),
                )
            );
        }

        // Security Analysis - always enabled, but very fast (just checking conditions)
        let security_sum_micros = self.security_analysis_sum_ms.load(Ordering::Relaxed);
        log::info!(
            "{}",
            Self::format_timing_with_micros(
                security_sum_micros,
                avg_ms.security_analysis_ms,
                "Security Analysis:",
                percentage(avg_ms.security_analysis_ms, avg_ms.total_ms),
            )
        );
        let other_ms = avg_ms.total_ms.saturating_sub(
            avg_ms.http_request_ms
                + avg_ms.dns_forward_ms
                + avg_ms.dns_reverse_ms
                + avg_ms.dns_additional_ms
                + avg_ms.tls_handshake_ms
                + avg_ms.html_parsing_ms
                + avg_ms.tech_detection_ms
                + avg_ms.geoip_lookup_ms
                + avg_ms.whois_lookup_ms
                + avg_ms.security_analysis_ms,
        );
        log::info!(
            "  Other/Overhead:      {:>6} ms ({:.1}%)",
            other_ms,
            percentage(other_ms, avg_ms.total_ms)
        );
        log::info!("  Total:               {:>6} ms", avg_ms.total_ms);
        log::info!(
            "Total time across all URLs: {} ms ({:.2} seconds)",
            total_sum_ms,
            total_sum_micros as f64 / 1_000_000.0
        );
    }
}

/// Helper function to convert a Duration to microseconds.
///
/// All timing measurements are stored in microseconds internally for precision,
/// then converted to milliseconds only when displaying to users.
pub fn duration_to_ms(duration: Duration) -> u64 {
    // Return microseconds (despite the function name for API compatibility)
    // The name is kept as `duration_to_ms` to avoid breaking existing code,
    // but it actually returns microseconds which are stored internally
    duration.as_micros() as u64
}
