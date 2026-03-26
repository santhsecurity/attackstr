//! Legacy SQL injection (SQLi) rule payloads and validators.
//!
//! This module isolates legacy string-based and static exploitation rules
//! that are not comprehensively handled by the generic grammar engine.

/// Get a list of legacy SQLi payloads that have historically proven effective
/// across various WAF bypass attempts.
#[must_use]
pub fn legacy_sqli_payloads() -> Vec<&'static str> {
    vec![
        "' OR 1=1--",
        "\" OR 1=1--",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "admin' --",
        "admin\" --",
    ]
}
