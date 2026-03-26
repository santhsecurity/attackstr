//! Legacy Command Injection (CMDi) rule payloads.
//!
//! This module isolates legacy static exploitation rules for command injection
//! that are ported directly from older Santh tools.

/// Returns legacy CMDi string payloads that bypass basic filtering.
#[must_use]
pub fn legacy_cmdi_payloads() -> Vec<&'static str> {
    vec!["; id", "| id", "|| id", "&& id", "$(id)", "`id`", "& id &"]
}
