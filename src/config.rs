//! TOML-configurable PayloadConfig — load settings from file.
//!
//! ```toml
//! # santh-payloads.toml
//! max_per_category = 1000
//! deduplicate = true
//! marker_prefix = "SLN"
//! marker_position = "prefix"   # prefix | suffix | inline | replace:{MARKER}
//! target_runtime = ["php", "node"]
//! exclude_categories = ["xxe"]
//! include_categories = []
//! grammar_dirs = ["./grammars", "/usr/share/santh/grammars"]
//! ```

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::{MarkerPosition, PayloadConfig, PayloadError};

/// TOML-serializable configuration that loads into [`PayloadConfig`].
///
/// # Thread Safety
/// `PayloadConfigFile` is `Send` and `Sync`.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash)]
#[serde(default)]
pub struct PayloadConfigFile {
    /// Maximum payloads per category (0 = unlimited).
    pub max_per_category: usize,
    /// Deduplicate identical payloads.
    pub deduplicate: bool,
    /// Marker prefix for taint tracking.
    pub marker_prefix: String,
    /// Marker position: "prefix", "suffix", "inline", or "replace:{PLACEHOLDER}".
    pub marker_position: String,
    /// Restrict to specific runtimes.
    pub target_runtime: Option<Vec<String>>,
    /// Categories to exclude.
    pub exclude_categories: Vec<String>,
    /// Categories to include (empty = all).
    pub include_categories: Vec<String>,
    /// Directories to load grammars from.
    pub grammar_dirs: Vec<String>,
}

impl Default for PayloadConfigFile {
    fn default() -> Self {
        Self {
            max_per_category: 0,
            deduplicate: true,
            marker_prefix: "SLN".into(),
            marker_position: "prefix".into(),
            target_runtime: None,
            exclude_categories: Vec::new(),
            include_categories: Vec::new(),
            grammar_dirs: Vec::new(),
        }
    }
}

impl PayloadConfigFile {
    /// Load from a TOML file path.
    ///
    /// Example:
    /// ```rust
    /// use attackstr::PayloadConfigFile;
    ///
    /// let dir = tempfile::tempdir().unwrap();
    /// let path = dir.path().join("payloads.toml");
    /// std::fs::write(&path, "max_per_category = 5\n").unwrap();
    ///
    /// let file = PayloadConfigFile::load(&path).unwrap();
    /// assert_eq!(file.max_per_category, 5);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or if the TOML is invalid.
    #[must_use]
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, PayloadError> {
        let content = std::fs::read_to_string(path.as_ref())?;
        Self::from_toml(&content, path.as_ref().display().to_string())
    }

    /// Parse from a TOML string.
    ///
    /// Example:
    /// ```rust
    /// use attackstr::PayloadConfigFile;
    ///
    /// let file = PayloadConfigFile::from_toml("deduplicate = false", "<inline>".into()).unwrap();
    /// assert!(!file.deduplicate);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the TOML string is invalid.
    #[must_use]
    pub fn from_toml(toml_str: &str, source: String) -> Result<Self, PayloadError> {
        toml::from_str(toml_str).map_err(|e| PayloadError::ConfigParse {
            file: source,
            source: Box::new(e),
        })
    }

    /// Convert to a [`PayloadConfig`].
    ///
    /// Example:
    /// ```rust
    /// use attackstr::{MarkerPosition, PayloadConfigFile};
    ///
    /// let config = PayloadConfigFile::from_toml("marker_position = \"suffix\"", "<inline>".into())
    ///     .unwrap()
    ///     .into_config();
    /// assert_eq!(config.marker_position, MarkerPosition::Suffix);
    /// ```
    #[must_use]
    pub fn into_config(self) -> PayloadConfig {
        PayloadConfig {
            max_per_category: self.max_per_category,
            deduplicate: self.deduplicate,
            marker_prefix: self.marker_prefix,
            exclude_categories: self.exclude_categories,
            include_categories: self.include_categories,
            target_runtime: self.target_runtime,
            marker_position: parse_marker_position(&self.marker_position),
        }
    }

    /// Grammar directories to load.
    ///
    /// Example:
    /// ```rust
    /// use attackstr::PayloadConfigFile;
    ///
    /// let file = PayloadConfigFile::from_toml("grammar_dirs = [\"./grammars\"]", "<inline>".into()).unwrap();
    /// assert_eq!(file.grammar_dirs(), ["./grammars"]);
    /// ```
    #[must_use]
    pub fn grammar_dirs(&self) -> &[String] {
        &self.grammar_dirs
    }
}

impl std::fmt::Display for PayloadConfigFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PayloadConfigFile(max_per_category={}, grammar_dirs={})",
            self.max_per_category,
            self.grammar_dirs.len()
        )
    }
}

fn parse_marker_position(s: &str) -> MarkerPosition {
    match s {
        "suffix" => MarkerPosition::Suffix,
        "inline" => MarkerPosition::Inline,
        s if s.starts_with("replace:") => MarkerPosition::Replace(s[8..].to_string()),
        _ => MarkerPosition::Prefix,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_file() {
        let cf = PayloadConfigFile::default();
        assert_eq!(cf.max_per_category, 0);
        assert!(cf.deduplicate);
        assert_eq!(cf.marker_prefix, "SLN");
        assert_eq!(cf.marker_position, "prefix");
        assert!(cf.grammar_dirs.is_empty());
    }

    #[test]
    fn parse_minimal_toml() {
        let cf = PayloadConfigFile::from_toml("", "<test>".into()).unwrap();
        assert!(cf.deduplicate);
    }

    #[test]
    fn parse_full_toml() {
        let cf = PayloadConfigFile::from_toml(
            r#"
max_per_category = 500
deduplicate = false
marker_prefix = "TAINT"
marker_position = "suffix"
target_runtime = ["php"]
exclude_categories = ["xxe"]
include_categories = ["sqli", "xss"]
grammar_dirs = ["./grammars", "/opt/payloads"]
"#,
            "<test>".into(),
        )
        .unwrap();

        assert_eq!(cf.max_per_category, 500);
        assert!(!cf.deduplicate);
        assert_eq!(cf.marker_prefix, "TAINT");
        assert_eq!(cf.target_runtime, Some(vec!["php".into()]));
        assert_eq!(cf.exclude_categories, vec!["xxe"]);
        assert_eq!(cf.grammar_dirs, vec!["./grammars", "/opt/payloads"]);
    }

    #[test]
    fn into_config_converts() {
        let cf = PayloadConfigFile {
            marker_position: "replace:{M}".into(),
            max_per_category: 42,
            ..Default::default()
        };
        let config = cf.into_config();
        assert_eq!(config.max_per_category, 42);
        assert_eq!(
            config.marker_position,
            MarkerPosition::Replace("{M}".into())
        );
    }

    #[test]
    fn marker_position_parsing() {
        assert_eq!(parse_marker_position("prefix"), MarkerPosition::Prefix);
        assert_eq!(parse_marker_position("suffix"), MarkerPosition::Suffix);
        assert_eq!(parse_marker_position("inline"), MarkerPosition::Inline);
        assert_eq!(
            parse_marker_position("replace:{MARKER}"),
            MarkerPosition::Replace("{MARKER}".into())
        );
        assert_eq!(parse_marker_position("unknown"), MarkerPosition::Prefix);
    }

    #[test]
    fn load_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
max_per_category = 100
grammar_dirs = ["./g"]
"#,
        )
        .unwrap();

        let cf = PayloadConfigFile::load(&path).unwrap();
        assert_eq!(cf.max_per_category, 100);
        assert_eq!(cf.grammar_dirs, vec!["./g"]);
    }

    #[test]
    fn load_nonexistent_file_errors() {
        assert!(PayloadConfigFile::load("/nonexistent/config.toml").is_err());
    }

    #[test]
    fn invalid_toml_errors() {
        assert!(PayloadConfigFile::from_toml("{{invalid", "<test>".into()).is_err());
    }
}
