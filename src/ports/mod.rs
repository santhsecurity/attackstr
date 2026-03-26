//! Legacy exploitation rule ports.
//!
//! Exposes payloads and logic ported from older Python tooling within Santh,
//! isolating them from the modern generative grammar engine.

pub mod cmdi;
pub mod sqli;

pub use cmdi::legacy_cmdi_payloads;
pub use sqli::legacy_sqli_payloads;
