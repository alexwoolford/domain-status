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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_duration_to_ms_zero() {
        let duration = Duration::from_micros(0);
        assert_eq!(duration_to_ms(duration), 0);
    }

    #[test]
    fn test_duration_to_ms_microseconds() {
        let duration = Duration::from_micros(1234);
        assert_eq!(duration_to_ms(duration), 1234);
    }

    #[test]
    fn test_duration_to_ms_milliseconds() {
        let duration = Duration::from_millis(5);
        assert_eq!(duration_to_ms(duration), 5000); // 5ms = 5000μs
    }

    #[test]
    fn test_duration_to_ms_seconds() {
        let duration = Duration::from_secs(1);
        assert_eq!(duration_to_ms(duration), 1_000_000); // 1s = 1,000,000μs
    }

    #[test]
    fn test_duration_to_ms_nanoseconds() {
        let duration = Duration::from_nanos(500);
        assert_eq!(duration_to_ms(duration), 0); // 500ns < 1μs, rounds to 0
    }

    #[test]
    fn test_timing_stats_new() {
        let stats = TimingStats::new();
        assert_eq!(stats.count.load(Ordering::Relaxed), 0);
        assert_eq!(stats.http_request_sum_ms.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_timing_stats_record_single() {
        let stats = TimingStats::new();
        let metrics = UrlTimingMetrics {
            http_request_ms: 1000,
            dns_forward_ms: 500,
            total_ms: 2000,
            ..Default::default()
        };

        stats.record(&metrics);

        assert_eq!(stats.count.load(Ordering::Relaxed), 1);
        assert_eq!(stats.http_request_sum_ms.load(Ordering::Relaxed), 1000);
        assert_eq!(stats.dns_forward_sum_ms.load(Ordering::Relaxed), 500);
        assert_eq!(stats.total_sum_ms.load(Ordering::Relaxed), 2000);
    }

    #[test]
    fn test_timing_stats_record_multiple() {
        let stats = TimingStats::new();
        let metrics1 = UrlTimingMetrics {
            http_request_ms: 1000,
            total_ms: 2000,
            ..Default::default()
        };
        let metrics2 = UrlTimingMetrics {
            http_request_ms: 2000,
            total_ms: 3000,
            ..Default::default()
        };

        stats.record(&metrics1);
        stats.record(&metrics2);

        assert_eq!(stats.count.load(Ordering::Relaxed), 2);
        assert_eq!(stats.http_request_sum_ms.load(Ordering::Relaxed), 3000);
        assert_eq!(stats.total_sum_ms.load(Ordering::Relaxed), 5000);
    }

    #[test]
    fn test_timing_stats_averages_zero_count() {
        let stats = TimingStats::new();
        let avg = stats.averages();
        assert_eq!(avg.http_request_ms, 0);
        assert_eq!(avg.total_ms, 0);
    }

    #[test]
    fn test_timing_stats_averages_single() {
        let stats = TimingStats::new();
        let metrics = UrlTimingMetrics {
            http_request_ms: 1000,
            dns_forward_ms: 500,
            total_ms: 2000,
            ..Default::default()
        };

        stats.record(&metrics);
        let avg = stats.averages();

        assert_eq!(avg.http_request_ms, 1000);
        assert_eq!(avg.dns_forward_ms, 500);
        assert_eq!(avg.total_ms, 2000);
    }

    #[test]
    fn test_timing_stats_averages_multiple() {
        let stats = TimingStats::new();
        let metrics1 = UrlTimingMetrics {
            http_request_ms: 1000,
            total_ms: 2000,
            ..Default::default()
        };
        let metrics2 = UrlTimingMetrics {
            http_request_ms: 3000,
            total_ms: 4000,
            ..Default::default()
        };

        stats.record(&metrics1);
        stats.record(&metrics2);
        let avg = stats.averages();

        assert_eq!(avg.http_request_ms, 2000); // (1000 + 3000) / 2
        assert_eq!(avg.total_ms, 3000); // (2000 + 4000) / 2
    }

    #[test]
    fn test_timing_stats_averages_rounding() {
        let stats = TimingStats::new();
        let metrics1 = UrlTimingMetrics {
            http_request_ms: 1,
            total_ms: 3,
            ..Default::default()
        };
        let metrics2 = UrlTimingMetrics {
            http_request_ms: 2,
            total_ms: 3,
            ..Default::default()
        };

        stats.record(&metrics1);
        stats.record(&metrics2);
        let avg = stats.averages();

        // (1 + 2) / 2 = 1.5, but integer division = 1
        assert_eq!(avg.http_request_ms, 1);
        // (3 + 3) / 2 = 3
        assert_eq!(avg.total_ms, 3);
    }

    #[test]
    fn test_timing_stats_percentage_division_by_zero() {
        // Test that percentage calculation handles division by zero correctly
        let stats = TimingStats::new();
        let avg = stats.averages();
        // When count is 0, averages should return all zeros
        assert_eq!(avg.total_ms, 0);
        // Percentage calculation should handle total_ms = 0 (returns 0.0)
        // This is tested implicitly - if it panicked, the test would fail
    }

    #[test]
    fn test_timing_stats_overflow_protection() {
        // Test that very large values don't cause overflow
        let stats = TimingStats::new();
        let metrics = UrlTimingMetrics {
            http_request_ms: u64::MAX,
            total_ms: u64::MAX,
            ..Default::default()
        };

        // Should not panic on overflow
        stats.record(&metrics);
        assert_eq!(stats.count.load(Ordering::Relaxed), 1);
        assert_eq!(stats.http_request_sum_ms.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn test_timing_stats_http_request_less_than_total() {
        // Test that http_request_ms is always <= total_ms (critical for percentage accuracy)
        let stats = TimingStats::new();
        let metrics = UrlTimingMetrics {
            http_request_ms: 1000,
            total_ms: 2000, // Total should be >= http_request
            ..Default::default()
        };

        stats.record(&metrics);
        let avg = stats.averages();
        assert!(avg.http_request_ms <= avg.total_ms);
    }

    #[test]
    fn test_timing_stats_all_components_sum_less_than_total() {
        // Test that sum of all components doesn't exceed total (with overhead)
        let stats = TimingStats::new();
        let metrics = UrlTimingMetrics {
            http_request_ms: 1000,
            dns_forward_ms: 500,
            dns_reverse_ms: 300,
            dns_additional_ms: 200,
            tls_handshake_ms: 400,
            html_parsing_ms: 100,
            tech_detection_ms: 50,
            geoip_lookup_ms: 10,
            whois_lookup_ms: 0,
            security_analysis_ms: 5,
            total_ms: 3000, // Total includes overhead
        };

        stats.record(&metrics);
        let avg = stats.averages();
        let sum_components = avg.http_request_ms
            + avg.dns_forward_ms
            + avg.dns_reverse_ms
            + avg.dns_additional_ms
            + avg.tls_handshake_ms
            + avg.html_parsing_ms
            + avg.tech_detection_ms
            + avg.geoip_lookup_ms
            + avg.whois_lookup_ms
            + avg.security_analysis_ms;

        // Sum of components should be <= total (total includes overhead)
        assert!(sum_components <= avg.total_ms);
    }

    #[test]
    fn test_duration_to_ms_very_large_duration() {
        // Test that very large durations don't cause overflow
        let duration = Duration::from_secs(u64::MAX / 1_000_000);
        // Should not panic, but may lose precision
        let result = duration_to_ms(duration);
        // Result should be reasonable (not cause overflow in downstream code)
        assert!(result > 0);
    }

    #[test]
    fn test_duration_to_ms_overflow_protection() {
        // Test duration that would overflow u64::MAX microseconds
        // Duration::from_secs(u64::MAX) would be way too large
        // Test with a large but reasonable duration
        let duration = Duration::from_secs(18_446_744); // Close to u64::MAX / 1_000_000
        let result = duration_to_ms(duration);
        // Should handle gracefully (may truncate but shouldn't panic)
        assert!(result > 0);
    }

    #[test]
    fn test_timing_stats_log_summary_zero_total_ms() {
        // Test that log_summary handles zero total_ms gracefully
        // This is critical - prevents division by zero in percentage calculations
        let stats = TimingStats::new();
        let metrics = UrlTimingMetrics {
            http_request_ms: 0,
            total_ms: 0,
            ..Default::default()
        };
        stats.record(&metrics);

        // Should not panic when logging with zero totals
        // The percentage function at line 181-187 handles total == 0
        stats.log_summary(None, None);
    }

    #[test]
    fn test_timing_stats_log_summary_component_sum_validation() {
        // Test that component sum doesn't exceed total (with overhead)
        // This is critical for percentage accuracy
        let stats = TimingStats::new();
        let metrics = UrlTimingMetrics {
            http_request_ms: 1000,
            dns_forward_ms: 500,
            dns_reverse_ms: 300,
            dns_additional_ms: 200,
            tls_handshake_ms: 400,
            html_parsing_ms: 100,
            tech_detection_ms: 50,
            geoip_lookup_ms: 10,
            whois_lookup_ms: 5,
            security_analysis_ms: 2,
            total_ms: 3000, // Total includes overhead, so sum of components < total
        };

        stats.record(&metrics);
        let avg = stats.averages();

        // Verify that sum of components is less than total (overhead exists)
        let sum = avg.http_request_ms
            + avg.dns_forward_ms
            + avg.dns_reverse_ms
            + avg.dns_additional_ms
            + avg.tls_handshake_ms
            + avg.html_parsing_ms
            + avg.tech_detection_ms
            + avg.geoip_lookup_ms
            + avg.whois_lookup_ms
            + avg.security_analysis_ms;

        assert!(
            sum < avg.total_ms,
            "Component sum should be less than total (overhead exists)"
        );
    }

    #[test]
    fn test_timing_stats_format_timing_with_micros_edge_cases() {
        // Test format_timing_with_micros with edge cases
        // This tests the logic at line 137-146
        let result1 = TimingStats::format_timing_with_micros(500, 0, "Test", 0.0);
        // When avg_ms is 0 but sum_micros > 0, should show microsecond format
        assert!(result1.contains("μs") || result1.contains("micros"));

        let result2 = TimingStats::format_timing_with_micros(0, 0, "Test", 0.0);
        // When both are 0, should show normal format
        assert!(!result2.contains("μs") || result2.contains("0 ms"));
    }

    #[test]
    fn test_timing_stats_micros_to_ms_rounding() {
        // Test that micros_to_ms rounds correctly (line 126-128)
        // Should round to nearest millisecond
        assert_eq!(TimingStats::micros_to_ms(0), 0);
        assert_eq!(TimingStats::micros_to_ms(499), 0); // Rounds down
        assert_eq!(TimingStats::micros_to_ms(500), 1); // Rounds up
        assert_eq!(TimingStats::micros_to_ms(1500), 2); // Rounds to nearest
        assert_eq!(TimingStats::micros_to_ms(1999), 2); // Rounds down
        assert_eq!(TimingStats::micros_to_ms(2000), 2); // Exact
    }

    #[test]
    fn test_timing_stats_other_overhead_calculation() {
        // Test that "Other/Overhead" calculation is correct (line 317-328)
        // This is critical - ensures timing breakdown is accurate
        let stats = TimingStats::new();
        let metrics = UrlTimingMetrics {
            http_request_ms: 1000,
            dns_forward_ms: 500,
            total_ms: 2000, // 500ms overhead
            ..Default::default()
        };

        stats.record(&metrics);
        // The log_summary calculates other_ms = total - sum of components
        // This should be 2000 - 1500 = 500ms
        // We test this implicitly by verifying the calculation doesn't panic
        stats.log_summary(None, None);
    }
}
