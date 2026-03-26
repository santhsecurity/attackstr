//! # attackstr
//!
//! Grammar-based security payload generation for the Santh ecosystem.
//!
//! Every security tool needs attack payloads — `SQLi`, XSS, command injection,
//! SSTI, SSRF, XXE, and more. This crate provides a single, configurable
//! engine that all Santh tools share. Upgrade payloads once, every tool
//! benefits.
//!
//! # Architecture
//!
//! Payloads are defined in TOML grammar files. Each grammar specifies:
//!
//! - **Contexts**: injection points (string break, numeric, attribute, etc.)
//! - **Techniques**: attack patterns with template variables
//! - **Variables**: substitution values (tautologies, commands, etc.)
//! - **Encodings**: transforms applied to final payloads (URL, hex, unicode, etc.)
//!
//! The engine computes the Cartesian product:
//! `contexts × techniques × variable_combos × encodings`
//!
//! # Usage
//!
//! ```rust
//! use attackstr::{PayloadDb, PayloadConfig};
//!
//! let mut db = PayloadDb::with_config(PayloadConfig::default());
//! db.load_toml(r#"
//! [grammar]
//! name = "example"
//! sink_category = "sql-injection"
//!
//! [[techniques]]
//! name = "basic"
//! template = "' OR 1=1 --"
//! "#).unwrap();
//!
//! // Get payloads for a category
//! let sqli = db.payloads("sql-injection");
//! for payload in sqli {
//!     println!("{}", payload.text);
//! }
//!
//! // Get payloads with marker injection for taint tracking
//! let marked = db.payloads_with_marker("xss", "SLN_MARKER_42");
//! ```
//!
//! # Custom Encodings
//!
//! Register custom encoding transforms:
//!
//! ```rust
//! use attackstr::PayloadDb;
//!
//! let mut db = PayloadDb::new();
//! db.register_encoding("rot13", |s| {
//!     s.chars().map(|c| match c {
//!         'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
//!         'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
//!         _ => c,
//!     }).collect()
//! });
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// TOML-configurable settings.
pub mod config;
mod encoding;
mod grammar;
mod loader;
mod mutate;
/// Legacy payloads and custom validators imported from older suites.
pub mod ports;
/// Grammar validation.
pub mod validate;

pub use config::PayloadConfigFile;
pub use encoding::{apply_encoding, BuiltinEncoding, CustomEncoder, Encoder};
pub use grammar::{
    Context, Encoding, Grammar, GrammarMeta, Technique, TemplateExpansionError, Variable,
};
pub use loader::PayloadDb;
pub use mutate::{
    mutate_all, mutate_case, mutate_encoding_mix, mutate_html, mutate_null_bytes,
    mutate_sql_comments, mutate_unicode, mutate_whitespace,
};
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
pub use validate::{validate, GrammarIssue, IssueLevel};

/// A trait for sources that can provide payloads.
///
/// This trait abstracts over different payload storage and generation
/// strategies, allowing users to swap implementations.
///
/// # Example
///
/// ```rust
/// use attackstr::{PayloadSource, PayloadDb};
///
/// fn count_payloads(source: &mut dyn PayloadSource) -> usize {
///     source.payload_count()
/// }
/// ```
pub trait PayloadSource {
    /// Get all payloads for a given category.
    ///
    /// The returned slice is cached on subsequent calls for the same category.
    fn payloads(&mut self, category: &str) -> &[Payload];

    /// Get all available category names.
    fn categories(&self) -> Vec<&str>;

    /// Get the total number of payloads across all categories.
    fn payload_count(&self) -> usize;
}

/// A static payload source that holds payloads directly in memory.
///
/// This is useful for users who generate payloads externally and want
/// to use them with the attackstr ecosystem.
///
/// # Example
///
/// ```rust
/// use attackstr::{StaticPayloads, Payload, PayloadSource};
///
/// let payloads = vec![
///     Payload {
///         text: "test".into(),
///         category: "custom".into(),
///         technique: "manual".into(),
///         context: "default".into(),
///         encoding: "raw".into(),
///         cwe: None,
///         severity: None,
///         confidence: 1.0,
///         expected_pattern: None,
///     },
/// ];
///
/// let mut source = StaticPayloads::new(payloads);
/// assert_eq!(source.payloads("custom").len(), 1);
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StaticPayloads {
    payloads: Vec<Payload>,
}

impl StaticPayloads {
    /// Create a new `StaticPayloads` from a vector of payloads.
    ///
    /// Example:
    /// ```rust
    /// use attackstr::{Payload, StaticPayloads};
    ///
    /// let payloads = vec![Payload {
    ///     text: "alert(1)".into(),
    ///     category: "xss".into(),
    ///     technique: "basic".into(),
    ///     context: "default".into(),
    ///     encoding: "raw".into(),
    ///     cwe: None,
    ///     severity: None,
    ///     confidence: 1.0,
    ///     expected_pattern: None,
    /// }];
    ///
    /// let source = StaticPayloads::new(payloads);
    /// assert_eq!(source.all_payloads().len(), 1);
    /// ```
    #[must_use]
    pub fn new(mut payloads: Vec<Payload>) -> Self {
        sort_payloads_by_category(&mut payloads);
        Self { payloads }
    }

    /// Add a single payload to this source.
    ///
    /// Example:
    /// ```rust
    /// use attackstr::{Payload, StaticPayloads};
    ///
    /// let mut source = StaticPayloads::default();
    /// source.add(Payload {
    ///     text: "test".into(),
    ///     category: "custom".into(),
    ///     technique: "manual".into(),
    ///     context: "default".into(),
    ///     encoding: "raw".into(),
    ///     cwe: None,
    ///     severity: None,
    ///     confidence: 1.0,
    ///     expected_pattern: None,
    /// });
    /// assert_eq!(source.all_payloads().len(), 1);
    /// ```
    pub fn add(&mut self, payload: Payload) {
        self.payloads.push(payload);
        sort_payloads_by_category(&mut self.payloads);
    }

    /// Get all payloads regardless of category.
    ///
    /// Example:
    /// ```rust
    /// use attackstr::StaticPayloads;
    ///
    /// let source = StaticPayloads::default();
    /// assert!(source.all_payloads().is_empty());
    /// ```
    #[must_use]
    pub fn all_payloads(&self) -> &[Payload] {
        &self.payloads
    }

    /// Iterate over all payloads in this source.
    ///
    /// Example:
    /// ```rust
    /// use attackstr::StaticPayloads;
    ///
    /// let source = StaticPayloads::default();
    /// assert_eq!(source.iter().count(), 0);
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = &Payload> {
        self.payloads.iter()
    }

    /// Iterate over payloads for a single category.
    ///
    /// Example:
    /// ```rust
    /// use attackstr::{Payload, StaticPayloads};
    ///
    /// let source = StaticPayloads::new(vec![Payload {
    ///     text: "alert(1)".into(),
    ///     category: "xss".into(),
    ///     technique: "basic".into(),
    ///     context: "default".into(),
    ///     encoding: "raw".into(),
    ///     cwe: None,
    ///     severity: None,
    ///     confidence: 1.0,
    ///     expected_pattern: None,
    /// }]);
    /// assert_eq!(source.iter_category("xss").count(), 1);
    /// ```
    pub fn iter_category<'a>(
        &'a self,
        category: &'a str,
    ) -> impl Iterator<Item = &'a Payload> + 'a {
        self.payloads
            .iter()
            .filter(move |payload| payload.category == category)
    }
}

impl From<Vec<Payload>> for StaticPayloads {
    fn from(payloads: Vec<Payload>) -> Self {
        Self::new(payloads)
    }
}

impl PayloadSource for StaticPayloads {
    fn payloads(&mut self, category: &str) -> &[Payload] {
        let count = self
            .payloads
            .iter()
            .filter(|p| p.category == category)
            .count();
        // Find the range of payloads for this category
        let start = self
            .payloads
            .iter()
            .position(|p| p.category == category)
            .unwrap_or(0);
        let end = start + count;
        if start < self.payloads.len() {
            &self.payloads[start..end.min(self.payloads.len())]
        } else {
            &[]
        }
    }

    fn categories(&self) -> Vec<&str> {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        self.payloads
            .iter()
            .filter_map(|p| {
                if seen.insert(p.category.clone()) {
                    Some(p.category.as_str())
                } else {
                    None
                }
            })
            .collect()
    }

    fn payload_count(&self) -> usize {
        self.payloads.len()
    }
}

/// Configuration for payload generation behavior.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PayloadConfig {
    /// Maximum payloads per category before truncation (0 = unlimited).
    pub max_per_category: usize,
    /// Whether to deduplicate identical payloads within a category.
    pub deduplicate: bool,
    /// Default marker prefix for taint tracking (e.g. "SLN").
    pub marker_prefix: String,
    /// Categories to exclude from generation (e.g. for compliance).
    pub exclude_categories: Vec<String>,
    /// Categories to include exclusively (empty = all).
    pub include_categories: Vec<String>,
    /// Restrict loaded grammars to one or more runtimes (empty = all).
    pub target_runtime: Option<Vec<String>>,
    /// Where to place the taint marker in generated marker payloads.
    pub marker_position: MarkerPosition,
}

impl PayloadConfig {
    /// Create a builder for [`PayloadConfig`].
    ///
    /// Example:
    /// ```rust
    /// use attackstr::PayloadConfig;
    ///
    /// let config = PayloadConfig::builder().marker_prefix("TRACE").build();
    /// assert_eq!(config.marker_prefix, "TRACE");
    /// ```
    #[must_use]
    pub fn builder() -> PayloadConfigBuilder {
        PayloadConfigBuilder::default()
    }

    /// Load a [`PayloadConfig`] from a TOML file.
    ///
    /// Example:
    /// ```rust
    /// use attackstr::PayloadConfig;
    ///
    /// let dir = tempfile::tempdir().unwrap();
    /// let path = dir.path().join("payloads.toml");
    /// std::fs::write(&path, "marker_prefix = \"TRACE\"\n").unwrap();
    ///
    /// let config = PayloadConfig::load(&path).unwrap();
    /// assert_eq!(config.marker_prefix, "TRACE");
    /// ```
    ///
    /// # Errors
    /// Returns a [`PayloadError`] if reading or parsing the file fails.
    pub fn load<P: AsRef<std::path::Path>>(path: P) -> Result<Self, PayloadError> {
        Ok(PayloadConfigFile::load(path)?.into_config())
    }

    /// Parse a [`PayloadConfig`] directly from TOML text.
    ///
    /// Example:
    /// ```rust
    /// use attackstr::{MarkerPosition, PayloadConfig};
    ///
    /// let config = PayloadConfig::from_toml("marker_position = \"suffix\"", "<inline>").unwrap();
    /// assert_eq!(config.marker_position, MarkerPosition::Suffix);
    /// ```
    ///
    /// # Errors
    /// Returns a [`PayloadError`] if parsing the TOML fails.
    pub fn from_toml(toml_str: &str, source: impl Into<String>) -> Result<Self, PayloadError> {
        Ok(PayloadConfigFile::from_toml(toml_str, source.into())?.into_config())
    }
}

impl Default for PayloadConfig {
    fn default() -> Self {
        Self {
            max_per_category: 0,
            deduplicate: true,
            marker_prefix: "SLN".into(),
            exclude_categories: Vec::new(),
            include_categories: Vec::new(),
            target_runtime: None,
            marker_position: MarkerPosition::Prefix,
        }
    }
}

/// Placement strategy for marker-injected payloads.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MarkerPosition {
    /// Prepend the marker to the payload text.
    Prefix,
    /// Append the marker to the payload text.
    Suffix,
    /// Wrap the marker in braces and prepend it inline.
    Inline,
    /// Replace `{MARKER}` placeholders in the payload text.
    Replace(String),
}

impl std::fmt::Display for MarkerPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Prefix => f.write_str("prefix"),
            Self::Suffix => f.write_str("suffix"),
            Self::Inline => f.write_str("inline"),
            Self::Replace(value) => write!(f, "replace:{value}"),
        }
    }
}

/// Builder for [`PayloadConfig`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct PayloadConfigBuilder {
    config: PayloadConfig,
}

impl PayloadConfigBuilder {
    /// Set the maximum payload count per category.
    #[must_use]
    pub fn max_per_category(mut self, max_per_category: usize) -> Self {
        self.config.max_per_category = max_per_category;
        self
    }

    /// Set whether identical payloads should be deduplicated.
    #[must_use]
    pub fn deduplicate(mut self, deduplicate: bool) -> Self {
        self.config.deduplicate = deduplicate;
        self
    }

    /// Set the marker prefix.
    #[must_use]
    pub fn marker_prefix(mut self, marker_prefix: impl Into<String>) -> Self {
        self.config.marker_prefix = marker_prefix.into();
        self
    }

    /// Set the categories to exclude.
    #[must_use]
    pub fn exclude_categories(mut self, exclude_categories: Vec<String>) -> Self {
        self.config.exclude_categories = exclude_categories;
        self
    }

    /// Set the categories to include.
    #[must_use]
    pub fn include_categories(mut self, include_categories: Vec<String>) -> Self {
        self.config.include_categories = include_categories;
        self
    }

    /// Set the allowed target runtimes.
    #[must_use]
    pub fn target_runtime(mut self, target_runtime: Option<Vec<String>>) -> Self {
        self.config.target_runtime = target_runtime;
        self
    }

    /// Set the marker placement strategy.
    #[must_use]
    pub fn marker_position(mut self, marker_position: MarkerPosition) -> Self {
        self.config.marker_position = marker_position;
        self
    }

    /// Build the final [`PayloadConfig`].
    ///
    /// Example:
    /// ```rust
    /// use attackstr::PayloadConfig;
    ///
    /// let config = PayloadConfig::builder().max_per_category(10).build();
    /// assert_eq!(config.max_per_category, 10);
    /// ```
    #[must_use]
    pub fn build(self) -> PayloadConfig {
        self.config
    }
}

fn sort_payloads_by_category(payloads: &mut [Payload]) {
    payloads.sort_by(|left, right| {
        left.category
            .cmp(&right.category)
            .then_with(|| left.technique.cmp(&right.technique))
            .then_with(|| left.context.cmp(&right.context))
            .then_with(|| left.encoding.cmp(&right.encoding))
            .then_with(|| left.text.cmp(&right.text))
    });
}

/// A generated payload with metadata about its origin.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Payload {
    /// The payload string.
    pub text: String,
    /// Which category this payload targets (e.g. "sql-injection").
    pub category: String,
    /// Which technique generated it (e.g. "union-based").
    pub technique: String,
    /// Which context it was generated in (e.g. "string-break").
    pub context: String,
    /// Which encoding was applied (e.g. "`url_encode`").
    pub encoding: String,
    /// Optional CWE identifier inherited from the grammar.
    pub cwe: Option<String>,
    /// Optional severity hint inherited from the grammar.
    pub severity: Option<String>,
    /// Confidence score for this payload variant.
    pub confidence: f64,
    /// Optional regex pattern expected in the observed response.
    pub expected_pattern: Option<String>,
}

impl Default for Payload {
    fn default() -> Self {
        Self {
            text: String::new(),
            category: String::new(),
            technique: String::new(),
            context: String::new(),
            encoding: "raw".to_string(),
            cwe: None,
            severity: None,
            confidence: 1.0,
            expected_pattern: None,
        }
    }
}

impl Eq for Payload {}

impl Hash for Payload {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.text.hash(state);
        self.category.hash(state);
        self.technique.hash(state);
        self.context.hash(state);
        self.encoding.hash(state);
        self.cwe.hash(state);
        self.severity.hash(state);
        self.confidence.to_bits().hash(state);
        self.expected_pattern.hash(state);
    }
}

/// Errors from payload operations.
#[derive(Debug, thiserror::Error)]
pub enum PayloadError {
    /// Failed to read a file.
    #[error("{0}. Fix: verify the file or directory exists and that the current process has permission to read it.")]
    Io(#[from] std::io::Error),
    /// Failed to parse TOML configuration.
    #[error("{message}", message = Self::config_parse_message(file, source))]
    ConfigParse {
        /// Which config file failed.
        file: String,
        /// The parse error.
        source: Box<toml::de::Error>,
    },
    /// Failed to parse TOML grammar.
    #[error("{message}", message = Self::grammar_parse_message(file, source))]
    GrammarParse {
        /// Which file failed.
        file: String,
        /// The parse error.
        source: Box<toml::de::Error>,
    },
    /// Failed to expand template placeholders in a grammar.
    #[error("{message}", message = Self::template_expansion_message(file, source))]
    TemplateExpansion {
        /// Which file failed.
        file: String,
        /// The expansion error.
        source: TemplateExpansionError,
    },
    /// Path is not a directory.
    #[error("path '{0}' is not a directory. Fix: pass a directory that contains `.toml` grammar files or update `grammar_dirs` in your config.")]
    NotADirectory(String),
}

impl Serialize for PayloadError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("kind", self.kind())?;
        map.serialize_entry("message", &self.to_string())?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for PayloadError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct PayloadErrorWire {
            message: String,
        }

        let wire = PayloadErrorWire::deserialize(deserializer)?;
        Ok(Self::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            wire.message,
        )))
    }
}

impl PayloadError {
    fn kind(&self) -> &'static str {
        match self {
            Self::Io(_) => "io",
            Self::ConfigParse { .. } => "config_parse",
            Self::GrammarParse { .. } => "grammar_parse",
            Self::TemplateExpansion { .. } => "template_expansion",
            Self::NotADirectory(_) => "not_a_directory",
        }
    }

    fn config_parse_message(file: &str, source: &toml::de::Error) -> String {
        format!(
            "config parse error in {file}: {source}. Fix: make the file valid TOML and keep payload settings at the top level, for example `max_per_category = 100` and `grammar_dirs = [\"./grammars\"]`."
        )
    }

    fn grammar_parse_message(file: &str, source: &toml::de::Error) -> String {
        let detail = source.to_string();
        let fix = if detail.contains("missing field `grammar`") {
            "Fix: add a `[grammar]` table with at least `name` and `sink_category`."
        } else if detail.contains("missing field `name`")
            || detail.contains("missing field `sink_category`")
        {
            "Fix: every grammar needs a `[grammar]` section with both `name` and `sink_category` fields."
        } else if detail.contains("missing field `template`") {
            "Fix: every `[[techniques]]` entry needs a `name` and `template`."
        } else {
            "Fix: make the file valid TOML and include a `[grammar]` section plus at least one `[[techniques]]` entry."
        };

        format!("grammar parse error in {file}: {detail}. {fix}")
    }

    fn template_expansion_message(file: &str, source: &TemplateExpansionError) -> String {
        let fix = match source {
            TemplateExpansionError::UnclosedBrace { .. } => {
                "Fix: close every `{placeholder}` with a matching `}` and escape literal braces by leaving them outside placeholder syntax."
            }
            TemplateExpansionError::RecursionLimitExceeded { max_depth } => {
                return format!(
                    "template expansion error in {file}: {source}. Fix: remove circular or self-referential variables so expansion stays below the recursion limit of {max_depth}."
                );
            }
            TemplateExpansionError::PayloadLimitExceeded { limit } => {
                return format!(
                    "template expansion error in {file}: {source}. Fix: reduce Cartesian product size (contexts x techniques x variables) to stay below the {limit} limit."
                );
            }
        };

        format!("template expansion error in {file}: {source}. {fix}")
    }
}

#[cfg(test)]
mod adversarial_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_round_trips_with_serde() {
        let payload = Payload {
            text: "alert(1)".into(),
            category: "xss".into(),
            technique: "basic".into(),
            context: "default".into(),
            encoding: "raw".into(),
            cwe: Some("CWE-79".into()),
            severity: Some("high".into()),
            confidence: 0.9,
            expected_pattern: Some("alert".into()),
        };

        let encoded = toml::to_string(&payload).unwrap();
        let decoded: Payload = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn payload_config_builder_overrides_defaults() {
        let config = PayloadConfig::builder()
            .max_per_category(100)
            .deduplicate(false)
            .marker_prefix("TAINT")
            .exclude_categories(vec!["xxe".into()])
            .include_categories(vec!["xss".into()])
            .target_runtime(Some(vec!["php".into()]))
            .marker_position(MarkerPosition::Suffix)
            .build();

        assert_eq!(config.max_per_category, 100);
        assert!(!config.deduplicate);
        assert_eq!(config.marker_prefix, "TAINT");
        assert_eq!(config.exclude_categories, vec!["xxe"]);
        assert_eq!(config.include_categories, vec!["xss"]);
        assert_eq!(config.target_runtime, Some(vec!["php".into()]));
        assert_eq!(config.marker_position, MarkerPosition::Suffix);
    }

    #[test]
    fn payload_config_loads_from_toml() {
        let config = PayloadConfig::from_toml(
            r#"
max_per_category = 25
deduplicate = false
marker_position = "suffix"
"#,
            "<test>",
        )
        .unwrap();

        assert_eq!(config.max_per_category, 25);
        assert!(!config.deduplicate);
        assert_eq!(config.marker_position, MarkerPosition::Suffix);
    }

    #[test]
    fn payload_config_loads_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payloads.toml");
        std::fs::write(&path, "marker_prefix = \"TRACE\"\n").unwrap();

        let config = PayloadConfig::load(&path).unwrap();

        assert_eq!(config.marker_prefix, "TRACE");
    }
}

#[cfg(test)]
mod payload_source_tests {
    use super::*;

    fn create_test_payload(text: &str, category: &str) -> Payload {
        Payload {
            text: text.into(),
            category: category.into(),
            technique: "test".into(),
            context: "default".into(),
            encoding: "raw".into(),
            cwe: None,
            severity: None,
            confidence: 1.0,
            expected_pattern: None,
        }
    }

    #[test]
    fn static_payloads_empty() {
        let source = StaticPayloads::new(vec![]);
        assert_eq!(source.payload_count(), 0);
        assert!(source.categories().is_empty());
    }

    #[test]
    fn static_payloads_single_category() {
        let payloads = vec![
            create_test_payload("payload1", "sqli"),
            create_test_payload("payload2", "sqli"),
        ];
        let source = StaticPayloads::new(payloads);

        assert_eq!(source.payload_count(), 2);
        let cats = source.categories();
        assert_eq!(cats.len(), 1);
        assert_eq!(cats[0], "sqli");
    }

    #[test]
    fn static_payloads_multiple_categories() {
        let payloads = vec![
            create_test_payload("p1", "sqli"),
            create_test_payload("p2", "xss"),
            create_test_payload("p3", "rce"),
        ];
        let source = StaticPayloads::new(payloads);

        assert_eq!(source.payload_count(), 3);
        let mut cats = source.categories();
        cats.sort_unstable();
        assert_eq!(cats, vec!["rce", "sqli", "xss"]);
    }

    #[test]
    fn static_payloads_add() {
        let mut source = StaticPayloads::new(vec![]);
        source.add(create_test_payload("test", "cat"));

        assert_eq!(source.payload_count(), 1);
    }

    #[test]
    fn static_payloads_from_vec() {
        let payloads = vec![create_test_payload("test", "cat")];
        let source: StaticPayloads = payloads.into();

        assert_eq!(source.payload_count(), 1);
    }

    #[test]
    fn static_payloads_default() {
        let source = StaticPayloads::default();
        assert_eq!(source.payload_count(), 0);
    }

    #[test]
    fn static_payloads_all_payloads() {
        let payloads = vec![
            create_test_payload("p1", "sqli"),
            create_test_payload("p2", "xss"),
        ];
        let source = StaticPayloads::new(payloads);

        assert_eq!(source.all_payloads().len(), 2);
    }

    #[test]
    fn static_payloads_group_interleaved_categories() {
        let payloads = vec![
            create_test_payload("p1", "xss"),
            create_test_payload("p2", "sqli"),
            create_test_payload("p3", "xss"),
        ];
        let mut source = StaticPayloads::new(payloads);

        let xss = source.payloads("xss");
        assert_eq!(xss.len(), 2);
        assert!(xss.iter().all(|payload| payload.category == "xss"));
    }

    #[test]
    fn static_payloads_iter_category_filters() {
        let payloads = vec![
            create_test_payload("p1", "xss"),
            create_test_payload("p2", "sqli"),
            create_test_payload("p3", "xss"),
        ];
        let source = StaticPayloads::new(payloads);

        let texts: Vec<_> = source
            .iter_category("xss")
            .map(|payload| payload.text.as_str())
            .collect();

        assert_eq!(texts, vec!["p1", "p3"]);
    }

    #[test]
    fn static_payloads_iter_returns_all_items() {
        let payloads = vec![
            create_test_payload("p1", "xss"),
            create_test_payload("p2", "sqli"),
        ];
        let source = StaticPayloads::new(payloads);

        let texts: Vec<_> = source.iter().map(|payload| payload.text.as_str()).collect();
        assert_eq!(texts, vec!["p2", "p1"]);
    }

    #[test]
    fn payload_db_implements_payload_source() {
        fn use_trait(source: &mut dyn PayloadSource) -> usize {
            source.payload_count()
        }

        let mut db = PayloadDb::new();
        db.load_toml(
            r#"
[grammar]
name = "test"
sink_category = "test-cat"

[[contexts]]
name = "default"
prefix = ""
suffix = ""

[[techniques]]
name = "t1"
template = "hello"
"#,
        )
        .unwrap();

        // Test through the trait interface
        assert_eq!(use_trait(&mut db), 1);

        let cats = db.categories();
        assert_eq!(cats.len(), 1);
        assert_eq!(cats[0], "test-cat");

        let payloads = db.payloads("test-cat");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].text, "hello");
    }

    #[test]
    fn static_payloads_implements_payload_source() {
        fn use_trait(s: &mut dyn PayloadSource) -> usize {
            s.payload_count()
        }

        let payloads = vec![
            create_test_payload("p1", "cat1"),
            create_test_payload("p2", "cat2"),
        ];
        let mut source = StaticPayloads::new(payloads);

        // Test through the trait interface
        assert_eq!(use_trait(&mut source), 2);
    }

    #[test]
    fn payload_source_trait_object_works() {
        let payloads = vec![create_test_payload("test", "cat")];
        let source: Box<dyn PayloadSource> = Box::new(StaticPayloads::new(payloads));

        assert_eq!(source.payload_count(), 1);
        assert_eq!(source.categories(), vec!["cat"]);
    }
}

#[cfg(test)]
mod encoder_tests {
    use super::encoding::{CustomEncoder, Encoder};

    #[test]
    fn custom_encoder_new() {
        let encoder = CustomEncoder::new(|s: &str| s.to_uppercase());
        assert_eq!(encoder.encode("hello"), "HELLO");
    }

    #[test]
    fn custom_encoder_default() {
        let encoder = CustomEncoder::default();
        assert_eq!(encoder.encode("hello"), "hello");
    }

    #[test]
    fn encoder_trait_for_fn() {
        fn upper(s: &str) -> String {
            s.to_uppercase()
        }
        let encoder: &dyn Encoder = &upper;
        assert_eq!(encoder.encode("hello"), "HELLO");
    }

    #[test]
    fn encoder_trait_for_closure() {
        let reverse = |s: &str| s.chars().rev().collect::<String>();
        assert_eq!(reverse.encode("hello"), "olleh");
    }

    #[test]
    fn encoder_trait_for_rot13() {
        let rot13 = |s: &str| {
            s.chars()
                .map(|c| match c {
                    'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
                    'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
                    _ => c,
                })
                .collect::<String>()
        };
        assert_eq!(rot13.encode("hello"), "uryyb");
    }
}

/// Convenience re-exports for common usage.
///
/// ```rust
/// use attackstr::prelude::*;
/// ```
pub mod prelude {
    pub use crate::config::PayloadConfigFile;
    pub use crate::validate::{validate, GrammarIssue};
    pub use crate::{apply_encoding, BuiltinEncoding};
    pub use crate::{mutate_all, mutate_case, mutate_whitespace};
    pub use crate::{Payload, PayloadConfig, PayloadDb, PayloadError};
}
