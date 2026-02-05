//! Tests for exit code policies (--fail-on flag)

use domain_status::{FailOn, ScanReport};
use std::path::PathBuf;

/// Helper function that mirrors evaluate_exit_code from src/main.rs
fn evaluate_exit_code(fail_on: &FailOn, pct_threshold: u8, report: &ScanReport) -> i32 {
    match fail_on {
        FailOn::Never => 0,
        FailOn::AnyFailure => {
            if report.failed > 0 {
                2
            } else {
                0
            }
        }
        FailOn::PctGreaterThan => {
            if report.total_urls == 0 {
                return 3;
            }
            let failure_pct = (report.failed as f64 / report.total_urls as f64) * 100.0;
            if failure_pct > pct_threshold as f64 {
                2
            } else {
                0
            }
        }
        FailOn::ErrorsOnly => {
            // Future enhancement: distinguish between critical errors and warnings
            // For now, behave like AnyFailure
            if report.failed > 0 {
                2
            } else {
                0
            }
        }
    }
}

#[test]
fn test_fail_on_never_always_returns_zero() {
    // Test that --fail-on never always returns exit code 0
    let report = ScanReport {
        total_urls: 10,
        successful: 5,
        failed: 5,
        db_path: PathBuf::from("./test.db"),
        run_id: "test_run".to_string(),
        elapsed_seconds: 1.0,
    };

    let exit_code = evaluate_exit_code(&FailOn::Never, 10, &report);
    assert_eq!(exit_code, 0, "FailOn::Never should always return 0");
}

#[test]
fn test_fail_on_any_failure_with_failures() {
    let report = ScanReport {
        total_urls: 10,
        successful: 5,
        failed: 5,
        db_path: PathBuf::from("./test.db"),
        run_id: "test_run".to_string(),
        elapsed_seconds: 1.0,
    };

    let exit_code = evaluate_exit_code(&FailOn::AnyFailure, 10, &report);
    assert_eq!(
        exit_code, 2,
        "FailOn::AnyFailure should return 2 when failures > 0"
    );
}

#[test]
fn test_fail_on_any_failure_without_failures() {
    let report = ScanReport {
        total_urls: 10,
        successful: 10,
        failed: 0,
        db_path: PathBuf::from("./test.db"),
        run_id: "test_run".to_string(),
        elapsed_seconds: 1.0,
    };

    let exit_code = evaluate_exit_code(&FailOn::AnyFailure, 10, &report);
    assert_eq!(
        exit_code, 0,
        "FailOn::AnyFailure should return 0 when no failures"
    );
}

#[test]
fn test_fail_on_pct_threshold_below_threshold() {
    use domain_status::ScanReport;

    // 2 failures out of 10 = 20%, threshold is 25%
    let report = ScanReport {
        total_urls: 10,
        successful: 8,
        failed: 2,
        db_path: PathBuf::from("./test.db"),
        run_id: "test_run".to_string(),
        elapsed_seconds: 1.0,
    };

    let exit_code = evaluate_exit_code(&FailOn::PctGreaterThan, 25, &report);
    assert_eq!(
        exit_code, 0,
        "Should return 0 when failure % is below threshold"
    );
}

#[test]
fn test_fail_on_pct_threshold_above_threshold() {
    use domain_status::ScanReport;

    // 3 failures out of 10 = 30%, threshold is 25%
    let report = ScanReport {
        total_urls: 10,
        successful: 7,
        failed: 3,
        db_path: PathBuf::from("./test.db"),
        run_id: "test_run".to_string(),
        elapsed_seconds: 1.0,
    };

    let exit_code = evaluate_exit_code(&FailOn::PctGreaterThan, 25, &report);
    assert_eq!(
        exit_code, 2,
        "Should return 2 when failure % exceeds threshold"
    );
}

#[test]
fn test_fail_on_pct_threshold_exact_threshold() {
    use domain_status::ScanReport;

    // 2 failures out of 10 = 20%, threshold is 20% (should not exceed)
    let report = ScanReport {
        total_urls: 10,
        successful: 8,
        failed: 2,
        db_path: PathBuf::from("./test.db"),
        run_id: "test_run".to_string(),
        elapsed_seconds: 1.0,
    };

    let exit_code = evaluate_exit_code(&FailOn::PctGreaterThan, 20, &report);
    assert_eq!(
        exit_code, 0,
        "Should return 0 when failure % equals threshold (not greater)"
    );
}

#[test]
fn test_fail_on_pct_threshold_zero_urls() {
    use domain_status::ScanReport;

    // Edge case: no URLs processed
    let report = ScanReport {
        total_urls: 0,
        successful: 0,
        failed: 0,
        db_path: PathBuf::from("./test.db"),
        run_id: "test_run".to_string(),
        elapsed_seconds: 1.0,
    };

    let exit_code = evaluate_exit_code(&FailOn::PctGreaterThan, 10, &report);
    assert_eq!(
        exit_code, 3,
        "Should return 3 (partial success) when no URLs processed"
    );
}

#[test]
fn test_fail_on_errors_only() {
    use domain_status::ScanReport;

    // Currently ErrorsOnly behaves like AnyFailure
    let report = ScanReport {
        total_urls: 10,
        successful: 5,
        failed: 5,
        db_path: PathBuf::from("./test.db"),
        run_id: "test_run".to_string(),
        elapsed_seconds: 1.0,
    };

    let exit_code = match &FailOn::ErrorsOnly {
        FailOn::Never => 0,
        FailOn::AnyFailure | FailOn::ErrorsOnly => {
            // Currently ErrorsOnly behaves like AnyFailure
            if report.failed > 0 {
                2
            } else {
                0
            }
        }
        _ => 0,
    };
    assert_eq!(
        exit_code, 2,
        "FailOn::ErrorsOnly should behave like AnyFailure for now"
    );
}
