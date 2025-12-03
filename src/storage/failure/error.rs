//! Error extraction utilities for failure tracking.
//!
//! This module provides functions to extract error types and HTTP status codes
//! from error chains for failure categorization.

use anyhow::Error;
use reqwest::Error as ReqwestError;

use crate::error_handling::{categorize_reqwest_error, ErrorType};

/// Extracts error type from an error chain.
///
/// Uses the shared `categorize_reqwest_error` function for consistency,
/// but also enhances categorization by checking error messages for DNS/TLS patterns.
pub(crate) fn extract_error_type(error: &Error) -> ErrorType {
    // Check error chain for reqwest errors first
    for cause in error.chain() {
        if let Some(reqwest_err) = cause.downcast_ref::<ReqwestError>() {
            // Use shared categorization function for consistency
            let base_type = categorize_reqwest_error(reqwest_err);

            // Enhance categorization by checking error messages for DNS/TLS patterns
            // This provides more specific error types when the underlying cause is DNS/TLS
            let error_msg = reqwest_err.to_string().to_lowercase();

            // Check for DNS errors in message (more specific than generic connect/request errors)
            if error_msg.contains("dns")
                || error_msg.contains("name resolution")
                || error_msg.contains("failed to resolve")
            {
                // Try to determine which DNS lookup failed
                if error_msg.contains("txt") {
                    return ErrorType::DnsTxtLookupError;
                } else if error_msg.contains("mx") || error_msg.contains("mail") {
                    return ErrorType::DnsMxLookupError;
                }
                return ErrorType::DnsNsLookupError;
            }

            // Check for TLS errors in message
            if error_msg.contains("tls")
                || error_msg.contains("ssl")
                || error_msg.contains("certificate")
                || error_msg.contains("handshake")
            {
                return ErrorType::TlsCertificateError;
            }

            // Check for timeout in request/connect errors
            if (base_type == ErrorType::HttpRequestRequestError
                || base_type == ErrorType::HttpRequestConnectError)
                && error_msg.contains("timeout")
            {
                return ErrorType::HttpRequestTimeoutError;
            }

            // Return the base type (from shared categorization)
            return base_type;
        }
    }

    // Check error message for specific patterns (for errors without reqwest::Error)
    let msg = error.to_string().to_lowercase();
    if msg.contains("timeout") {
        return ErrorType::ProcessUrlTimeout;
    }

    // Check for DNS errors in error message
    if msg.contains("dns") || msg.contains("resolve") || msg.contains("lookup failed") {
        // Try to determine which DNS lookup failed
        if msg.contains("ns") || msg.contains("nameserver") {
            return ErrorType::DnsNsLookupError;
        } else if msg.contains("txt") {
            return ErrorType::DnsTxtLookupError;
        } else if msg.contains("mx") || msg.contains("mail") {
            return ErrorType::DnsMxLookupError;
        }
        // Generic DNS error - default to NS lookup error
        return ErrorType::DnsNsLookupError;
    }

    // Check for TLS errors in error message
    if msg.contains("tls")
        || msg.contains("ssl")
        || msg.contains("certificate")
        || msg.contains("handshake")
    {
        return ErrorType::TlsCertificateError;
    }

    // Default to other error
    ErrorType::HttpRequestOtherError
}

/// Extracts HTTP status code from an error chain.
pub(crate) fn extract_http_status(error: &Error) -> Option<u16> {
    for cause in error.chain() {
        if let Some(reqwest_err) = cause.downcast_ref::<ReqwestError>() {
            if let Some(status) = reqwest_err.status() {
                return Some(status.as_u16());
            }
        }
    }
    None
}
