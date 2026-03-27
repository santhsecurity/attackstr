//! Payload database — loads grammars from TOML files, expands payloads, serves them.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::grammar::{self, ExpandedPayload, Grammar, GrammarExpansionIter};
use crate::validate::{validate, IssueLevel};
use crate::{MarkerPosition, Payload, PayloadConfig, PayloadConfigFile, PayloadError};

/// The central payload database. Loads grammars, expands payloads, serves them.
///
/// # Example
///
/// ```rust
/// use attackstr::{PayloadDb, PayloadConfig};
///
/// let mut db = PayloadDb::with_config(PayloadConfig {
///     deduplicate: true,
///     ..PayloadConfig::default()
/// });
///
/// // Load from directory
/// // db.load_dir("./grammars").unwrap();
///
/// // Or load from a TOML string
/// db.load_toml(r#"
/// [grammar]
/// name = "test"
/// sink_category = "test-injection"
///
/// [[contexts]]
/// name = "default"
/// prefix = ""
/// suffix = ""
///
/// [[techniques]]
/// name = "basic"
/// template = "test payload"
///
/// [[encodings]]
/// name = "raw"
/// transform = "identity"
/// "#).unwrap();
///
/// let payloads = db.payloads("test-injection");
/// assert_eq!(payloads.len(), 1);
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayloadDb {
    /// Configuration.
    config: PayloadConfig,
    /// Loaded grammars by category.
    grammars: HashMap<String, Vec<Grammar>>,
    /// Expanded payloads by category (lazily populated).
    cache: HashMap<String, Vec<Payload>>,
    /// Custom encoding functions.
    #[serde(skip, default)]
    custom_encodings: HashMap<String, fn(&str) -> String>,
    /// Guards directory loads so concurrent callers fail explicitly.
    #[serde(skip, default = "default_load_state")]
    load_in_progress: Arc<AtomicBool>,
}

impl PartialEq for PayloadDb {
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config && self.grammars == other.grammars && self.cache == other.cache
    }
}

impl Eq for PayloadDb {}

impl Hash for PayloadDb {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.config.hash(state);
        hash_string_keyed_map(&self.grammars, state);
        hash_string_keyed_map(&self.cache, state);
    }
}

impl PayloadDb {
    /// Create a new empty database with default config.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(PayloadConfig::default())
    }

    /// Create a new database with the given configuration.
    #[must_use]
    pub fn with_config(config: PayloadConfig) -> Self {
        Self {
            config,
            grammars: HashMap::new(),
            cache: HashMap::new(),
            custom_encodings: HashMap::new(),
            load_in_progress: default_load_state(),
        }
    }

    /// Load a config file and then load every grammar directory declared in it.
    ///
    /// Relative `grammar_dirs` entries are resolved relative to the config file's
    /// parent directory so project-local configs work from any current directory.
    ///
    /// Returns the configured database and any per-grammar load errors collected
    /// while scanning the configured grammar directories.
    ///
    /// # Errors
    /// Returns a `PayloadError` if the initial config file fails to load.
    pub fn load_config_and_grammars<P: AsRef<Path>>(
        config_path: P,
    ) -> Result<(Self, Vec<PayloadError>), PayloadError> {
        let config_path = config_path.as_ref();
        let config_file = PayloadConfigFile::load(config_path)?;
        let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));

        let mut db = Self::with_config(config_file.clone().into_config());
        let mut errors = Vec::new();

        for grammar_dir in config_file.grammar_dirs() {
            let resolved_dir = if Path::new(grammar_dir).is_absolute() {
                Path::new(grammar_dir).to_path_buf()
            } else {
                config_dir.join(grammar_dir)
            };

            errors.extend(db.load_dir_lenient(&resolved_dir)?);
        }

        Ok((db, errors))
    }

    /// Register a custom encoding transform.
    ///
    /// Custom encodings take precedence over built-ins with the same name.
    pub fn register_encoding(&mut self, name: &str, func: fn(&str) -> String) {
        self.custom_encodings.insert(name.to_string(), func);
        self.cache.clear(); // Invalidate cache — encodings changed.
    }

    fn runtime_allowed(&self, grammar: &Grammar) -> bool {
        let Some(targets) = &self.config.target_runtime else {
            return true;
        };
        if targets.is_empty() {
            return true;
        }

        let Some(grammar_runtimes) = &grammar.meta.target_runtime else {
            return true;
        };

        grammar_runtimes.iter().any(|runtime| {
            targets
                .iter()
                .any(|target| runtime.eq_ignore_ascii_case(target))
        })
    }

    /// Load all `.toml` grammar files from a directory.
    ///
    /// Non-TOML files are silently skipped. Subdirectories are NOT recursed
    /// (flat layout by design — one category per file or split across files).
    ///
    /// # Errors
    /// Returns a `PayloadError` if the path doesn't exist or isn't a directory.
    pub fn load_dir<P: AsRef<Path>>(&mut self, dir: P) -> Result<Vec<PayloadError>, PayloadError> {
        self.load_dir_lenient(dir)
    }

    /// Load all `.toml` grammar files from a directory and collect per-file errors.
    ///
    /// Successfully parsed grammars remain loaded even if other files fail.
    ///
    /// # Errors
    /// Returns a `PayloadError` if the path doesn't exist or isn't a directory.
    pub fn load_dir_lenient<P: AsRef<Path>>(
        &mut self,
        dir: P,
    ) -> Result<Vec<PayloadError>, PayloadError> {
        let _load_guard = self.begin_load_session()?;
        self.load_dir_lenient_inner(dir.as_ref())
    }

    fn load_dir_lenient_inner(&mut self, path: &Path) -> Result<Vec<PayloadError>, PayloadError> {
        if !path.is_dir() {
            return Err(PayloadError::NotADirectory(path.display().to_string()));
        }

        let mut errors = Vec::new();
        let mut entries = Vec::new();
        match std::fs::read_dir(path) {
            Ok(read_dir) => {
                for entry_result in read_dir {
                    match entry_result {
                        Ok(entry) => {
                            if entry.path().extension().and_then(|s| s.to_str()) == Some("toml") {
                                entries.push(entry);
                            }
                        }
                        Err(err) => {
                            errors.push(PayloadError::Io(err));
                        }
                    }
                }
            }
            Err(err) => return Err(PayloadError::Io(err)),
        }

        // Sort for deterministic ordering.
        entries.sort_by_key(std::fs::DirEntry::path);

        let mut loaded = Vec::new();

        for entry in entries {
            if let Some(grammar) = self.load_single_grammar_file(&entry.path(), &mut errors) {
                let category = grammar.meta.sink_category.clone();
                loaded.push((category, grammar));
            }
        }

        for (category, grammar) in loaded {
            self.grammars.entry(category).or_default().push(grammar);
        }

        self.cache.clear(); // Invalidate cache.
        Ok(errors)
    }

    fn load_single_grammar_file(
        &self,
        file_path: &Path,
        errors: &mut Vec<PayloadError>,
    ) -> Option<Grammar> {
        let content = match std::fs::read_to_string(file_path) {
            Ok(content) => content,
            Err(err) => {
                errors.push(PayloadError::Io(err));
                return None;
            }
        };
        let grammar: Grammar = match toml::from_str(&content) {
            Ok(grammar) => grammar,
            Err(source) => {
                errors.push(PayloadError::GrammarParse {
                    file: file_path.display().to_string(),
                    source: Box::new(source),
                });
                return None;
            }
        };
        if let Err(error) = self.validate_grammar(&grammar, &file_path.display().to_string()) {
            errors.push(error);
            return None;
        }
        if let Err(source) = grammar::expand(&grammar, &self.custom_encodings) {
            errors.push(PayloadError::TemplateExpansion {
                file: file_path.display().to_string(),
                source,
            });
            return None;
        }

        let category = grammar.meta.sink_category.clone();

        // Check include/exclude filters.
        if !self.config.include_categories.is_empty()
            && !self.config.include_categories.contains(&category)
        {
            return None;
        }
        if self.config.exclude_categories.contains(&category) {
            return None;
        }
        if !self.runtime_allowed(&grammar) {
            return None;
        }

        Some(grammar)
    }

    /// Load a grammar from a TOML string.
    ///
    /// # Errors
    /// Returns a `PayloadError` if the TOML is invalid or template variables fail to expand.
    pub fn load_toml(&mut self, toml_str: &str) -> Result<(), PayloadError> {
        self.load_reader(std::io::Cursor::new(toml_str), "<string>")
    }

    /// Load a grammar from any reader containing TOML.
    ///
    /// # Errors
    /// Returns a `PayloadError` if reading, parsing, or template expansion fails.
    pub fn load_reader<R: Read>(&mut self, mut reader: R, source_name: &str) -> Result<(), PayloadError> {
        let mut toml_str = String::new();
        reader
            .read_to_string(&mut toml_str)
            .map_err(PayloadError::Io)?;
        let grammar: Grammar = toml::from_str(&toml_str).map_err(|e| PayloadError::GrammarParse {
            file: source_name.into(),
            source: Box::new(e),
        })?;
        self.validate_grammar(&grammar, source_name)?;
        grammar::expand(&grammar, &self.custom_encodings).map_err(|source| {
            PayloadError::TemplateExpansion {
                file: source_name.into(),
                source,
            }
        })?;

        let category = grammar.meta.sink_category.clone();

        if !self.config.include_categories.is_empty()
            && !self.config.include_categories.contains(&category)
        {
            return Ok(());
        }
        if self.config.exclude_categories.contains(&category) {
            return Ok(());
        }
        if !self.runtime_allowed(&grammar) {
            return Ok(());
        }

        self.grammars.entry(category).or_default().push(grammar);
        self.cache.clear();
        Ok(())
    }

    fn validate_grammar(&self, grammar: &Grammar, source_name: &str) -> Result<(), PayloadError> {
        let issues = validate(grammar);
        let errors: Vec<_> = issues
            .into_iter()
            .filter(|issue| issue.level == IssueLevel::Error)
            .collect();

        if errors.is_empty() {
            Ok(())
        } else {
            Err(PayloadError::GrammarValidation {
                file: source_name.to_string(),
                issues: errors,
            })
        }
    }

    fn begin_load_session(&self) -> Result<LoadSessionGuard, PayloadError> {
        self.load_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| PayloadError::ConcurrentLoad)?;
        Ok(LoadSessionGuard {
            flag: Arc::clone(&self.load_in_progress),
        })
    }

    /// Get all expanded payloads for a category.
    ///
    /// Results are cached after first expansion.
    pub fn payloads(&mut self, category: &str) -> &[Payload] {
        if !self.cache.contains_key(category) {
            let payloads = self.expand_category(category);
            self.cache.insert(category.to_string(), payloads);
        }
        self.cache
            .get(category)
            .map_or(&[], std::vec::Vec::as_slice)
    }

    /// Stream payloads for a category without materializing the full category at once.
    pub fn iter_payloads<'a>(
        &'a self,
        category: &'a str,
    ) -> impl Iterator<Item = Result<Payload, crate::grammar::TemplateExpansionError>> + 'a {
        let grammars = match self.grammars.get(category) {
            Some(v) => v.as_slice(),
            None => Default::default(),
        };
        PayloadIter {
            category,
            grammars,
            grammar_index: 0,
            current_iter: None,
            custom_encodings: &self.custom_encodings,
            deduplicate: self.config.deduplicate,
            max_per_category: self.config.max_per_category,
            emitted: 0,
            seen_payloads: HashSet::new(),
        }
    }

    /// Get payload strings only (no metadata) for a category.
    pub fn payload_strings(&mut self, category: &str) -> Vec<String> {
        self.payloads(category)
            .iter()
            .map(|p| p.text.clone())
            .collect()
    }

    /// Iterate over loaded category names in sorted order.
    pub fn iter_categories(&self) -> impl Iterator<Item = &str> {
        let mut categories: Vec<_> = self.grammars.keys().map(String::as_str).collect();
        categories.sort_unstable();
        categories.into_iter()
    }

    /// Get all payloads with a taint marker injected.
    ///
    /// Marker placement is controlled by [`crate::PayloadConfig::marker_position`].
    pub fn payloads_with_marker(&mut self, category: &str, marker: &str) -> Vec<Payload> {
        let marker_position = self.config.marker_position.clone();
        self.payloads(category)
            .iter()
            .map(|p| Payload {
                text: Self::apply_marker_position(&marker_position, &p.text, marker),
                category: p.category.clone(),
                technique: p.technique.clone(),
                context: p.context.clone(),
                encoding: p.encoding.clone(),
                cwe: p.cwe.clone(),
                severity: p.severity.clone(),
                confidence: p.confidence,
                expected_pattern: p.expected_pattern.clone(),
            })
            .collect()
    }

    /// Get all categories that have been loaded.
    #[must_use]
    pub fn categories(&self) -> Vec<&str> {
        self.iter_categories().collect()
    }

    /// Total number of grammars loaded.
    #[must_use]
    pub fn grammar_count(&self) -> usize {
        self.grammars.values().map(std::vec::Vec::len).sum()
    }

    /// Clear all loaded grammars and cached payloads.
    pub fn clear(&mut self) {
        self.grammars.clear();
        self.cache.clear();
    }

    /// Expand all grammars for a category into payloads.
    fn expand_category(&self, category: &str) -> Vec<Payload> {
        self.iter_payloads(category)
            .filter_map(Result::ok)
            .collect()
    }

    fn apply_marker_position(
        marker_position: &MarkerPosition,
        payload: &str,
        marker: &str,
    ) -> String {
        match marker_position {
            MarkerPosition::Prefix => format!("{marker}{payload}"),
            MarkerPosition::Suffix => format!("{payload}{marker}"),
            MarkerPosition::Inline => format!("{{{marker}}}{payload}"),
            MarkerPosition::Replace(placeholder) => payload.replace(placeholder, marker),
        }
    }
}

impl Default for PayloadDb {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::PayloadSource for PayloadDb {
    fn payloads(&mut self, category: &str) -> &[crate::Payload] {
        self.payloads(category)
    }

    fn categories(&self) -> Vec<&str> {
        self.categories()
    }

    fn payload_count(&self) -> usize {
        // Expand all categories and sum their payloads
        self.grammars
            .keys()
            .map(|cat| self.iter_payloads(cat).filter(|r| r.is_ok()).count())
            .sum()
    }
}

pub struct PayloadIter<'a> {
    category: &'a str,
    grammars: &'a [Grammar],
    grammar_index: usize,
    current_iter: Option<GrammarExpansionIter<'a>>,
    custom_encodings: &'a HashMap<String, fn(&str) -> String>,
    deduplicate: bool,
    max_per_category: usize,
    emitted: usize,
    seen_payloads: HashSet<String>,
}

impl Iterator for PayloadIter<'_> {
    type Item = Result<Payload, crate::grammar::TemplateExpansionError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.max_per_category > 0 && self.emitted >= self.max_per_category {
            return None;
        }

        loop {
            if let Some(iter) = self.current_iter.as_mut() {
                if let Some(res) = iter.next() {
                    match res {
                        Ok(expanded_payload) => {
                            let grammar = &self.grammars[self.grammar_index - 1];
                            if self.deduplicate
                                && !self.seen_payloads.insert(expanded_payload.text.clone())
                            {
                                continue;
                            }

                            self.emitted += 1;
                            return Some(Ok(payload_from_expanded(
                                self.category,
                                grammar,
                                expanded_payload,
                            )));
                        }
                        Err(e) => return Some(Err(e)),
                    }
                }

                self.current_iter = None;
            }

            let grammar = self.grammars.get(self.grammar_index)?;
            self.grammar_index += 1;
            match grammar::iter_expanded(grammar, self.custom_encodings) {
                Ok(iter) => self.current_iter = Some(iter),
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

fn hash_string_keyed_map<T, Hs>(map: &HashMap<String, Vec<T>>, state: &mut Hs)
where
    T: Hash,
    Hs: Hasher,
{
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_by(|(left, _), (right, _)| left.cmp(right));
    for (key, value) in entries {
        key.hash(state);
        value.hash(state);
    }
}

fn default_load_state() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

struct LoadSessionGuard {
    flag: Arc<AtomicBool>,
}

impl Drop for LoadSessionGuard {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

fn payload_from_expanded(
    category: &str,
    grammar: &Grammar,
    expanded_payload: ExpandedPayload,
) -> Payload {
    Payload {
        text: expanded_payload.text,
        category: category.to_string(),
        technique: expanded_payload.technique,
        context: expanded_payload.context,
        encoding: expanded_payload.encoding,
        cwe: grammar.meta.cwe.clone(),
        severity: grammar.meta.severity.clone(),
        confidence: expanded_payload.confidence,
        expected_pattern: expanded_payload.expected_pattern,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_toml_string() {
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
name = "basic"
template = "hello"

[[encodings]]
name = "raw"
transform = "identity"
"#,
        )
        .unwrap();

        let payloads = db.payloads("test-cat");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].text, "hello");
        assert_eq!(payloads[0].technique, "basic");
        assert_eq!(payloads[0].context, "default");
        assert!((payloads[0].confidence - 1.0).abs() < f64::EPSILON);
        assert!(payloads[0].expected_pattern.is_none());
    }

    #[test]
    fn multiple_grammars_same_category() {
        let mut db = PayloadDb::new();
        db.load_toml(
            r#"
[grammar]
name = "a"
sink_category = "cat"
[[techniques]]
name = "t1"
template = "payload-a"
"#,
        )
        .unwrap();
        db.load_toml(
            r#"
[grammar]
name = "b"
sink_category = "cat"
[[techniques]]
name = "t2"
template = "payload-b"
"#,
        )
        .unwrap();

        let payloads = db.payloads("cat");
        assert_eq!(payloads.len(), 2);
        let texts: Vec<&str> = payloads.iter().map(|p| p.text.as_str()).collect();
        assert!(texts.contains(&"payload-a"));
        assert!(texts.contains(&"payload-b"));
    }

    #[test]
    fn deduplication() {
        let mut db = PayloadDb::with_config(PayloadConfig {
            deduplicate: true,
            ..PayloadConfig::default()
        });
        // Two grammars producing same payload.
        for _ in 0..2 {
            db.load_toml(
                r#"
[grammar]
name = "dup"
sink_category = "dup-cat"
[[techniques]]
name = "t"
template = "same"
"#,
            )
            .unwrap();
        }

        let payloads = db.payloads("dup-cat");
        assert_eq!(payloads.len(), 1);
    }

    #[test]
    fn max_per_category() {
        let mut db = PayloadDb::with_config(PayloadConfig {
            max_per_category: 2,
            ..PayloadConfig::default()
        });
        db.load_toml(
            r#"
[grammar]
name = "big"
sink_category = "big-cat"

[[techniques]]
name = "t1"
template = "{var}"

[[vars]]
value = "a"
[[vars]]
value = "b"
[[vars]]
value = "c"
[[vars]]
value = "d"
[[vars]]
value = "e"
"#,
        )
        .unwrap();

        let payloads = db.payloads("big-cat");
        assert_eq!(payloads.len(), 2); // Truncated to 2.
    }

    #[test]
    fn exclude_categories() {
        let mut db = PayloadDb::with_config(PayloadConfig {
            exclude_categories: vec!["blocked".into()],
            ..PayloadConfig::default()
        });
        db.load_toml(
            r#"
[grammar]
name = "blocked"
sink_category = "blocked"
[[techniques]]
name = "t"
template = "evil"
"#,
        )
        .unwrap();

        assert!(db.payloads("blocked").is_empty());
        assert_eq!(db.grammar_count(), 0);
    }

    #[test]
    fn include_categories() {
        let mut db = PayloadDb::with_config(PayloadConfig {
            include_categories: vec!["allowed".into()],
            ..PayloadConfig::default()
        });
        db.load_toml(
            r#"
[grammar]
name = "good"
sink_category = "allowed"
[[techniques]]
name = "t"
template = "ok"
"#,
        )
        .unwrap();
        db.load_toml(
            r#"
[grammar]
name = "bad"
sink_category = "not-allowed"
[[techniques]]
name = "t"
template = "nope"
"#,
        )
        .unwrap();

        assert_eq!(db.payloads("allowed").len(), 1);
        assert!(db.payloads("not-allowed").is_empty());
    }

    #[test]
    fn runtime_filter_includes_matching_grammar() {
        let mut db = PayloadDb::with_config(PayloadConfig {
            target_runtime: Some(vec!["php".into()]),
            ..PayloadConfig::default()
        });
        db.load_toml(
            r#"
[grammar]
name = "php-only"
sink_category = "runtime-cat"
target_runtime = ["php", "node"]

[[techniques]]
name = "t"
template = "payload"
"#,
        )
        .unwrap();

        assert_eq!(db.payloads("runtime-cat").len(), 1);
    }

    #[test]
    fn runtime_filter_excludes_non_matching_grammar() {
        let mut db = PayloadDb::with_config(PayloadConfig {
            target_runtime: Some(vec!["ruby".into()]),
            ..PayloadConfig::default()
        });
        db.load_toml(
            r#"
[grammar]
name = "php-only"
sink_category = "runtime-cat"
target_runtime = ["php", "node"]

[[techniques]]
name = "t"
template = "payload"
"#,
        )
        .unwrap();

        assert!(db.payloads("runtime-cat").is_empty());
        assert_eq!(db.grammar_count(), 0);
    }

    #[test]
    fn runtime_filter_allows_unspecified_grammar_runtime() {
        let mut db = PayloadDb::with_config(PayloadConfig {
            target_runtime: Some(vec!["node".into()]),
            ..PayloadConfig::default()
        });
        db.load_toml(
            r#"
[grammar]
name = "generic"
sink_category = "runtime-generic"

[[techniques]]
name = "t"
template = "payload"
"#,
        )
        .unwrap();

        assert_eq!(db.payloads("runtime-generic").len(), 1);
    }

    #[test]
    fn marker_injection() {
        let mut db = PayloadDb::new();
        db.load_toml(
            r#"
[grammar]
name = "m"
sink_category = "mark"
[[techniques]]
name = "t"
template = "alert(1)"
"#,
        )
        .unwrap();

        let marked = db.payloads_with_marker("mark", "SLN_42_");
        assert_eq!(marked.len(), 1);
        assert_eq!(marked[0].text, "SLN_42_alert(1)");
    }

    #[test]
    fn marker_injection_suffix() {
        let mut db = PayloadDb::with_config(PayloadConfig {
            marker_position: MarkerPosition::Suffix,
            ..PayloadConfig::default()
        });
        db.load_toml(
            r#"
[grammar]
name = "m"
sink_category = "mark-suffix"
[[techniques]]
name = "t"
template = "alert(1)"
"#,
        )
        .unwrap();

        let marked = db.payloads_with_marker("mark-suffix", "SLN_42_");
        assert_eq!(marked[0].text, "alert(1)SLN_42_");
    }

    #[test]
    fn iter_categories_returns_sorted_names() {
        let mut db = PayloadDb::new();
        db.load_toml(
            r#"
[grammar]
name = "zeta"
sink_category = "zeta"
[[techniques]]
name = "t"
template = "a"
"#,
        )
        .unwrap();
        db.load_toml(
            r#"
[grammar]
name = "alpha"
sink_category = "alpha"
[[techniques]]
name = "t"
template = "b"
"#,
        )
        .unwrap();

        let categories: Vec<_> = db.iter_categories().collect();
        assert_eq!(categories, vec!["alpha", "zeta"]);
    }

    #[test]
    fn config_file_round_trip_loads_grammar_dir_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let grammar_dir = dir.path().join("grammars");
        std::fs::create_dir(&grammar_dir).unwrap();

        std::fs::write(
            grammar_dir.join("xss.toml"),
            r#"
[grammar]
name = "example-xss"
sink_category = "xss"

[[contexts]]
name = "quoted"
prefix = "'"
suffix = "'"

[[techniques]]
name = "alert"
template = "{prefix}<script>{payload}</script>{suffix}"

[[payloads]]
value = "alert(1)"

[[encodings]]
name = "raw"
transform = "identity"
"#,
        )
        .unwrap();

        std::fs::write(
            dir.path().join("attackstr.toml"),
            r#"
max_per_category = 5
deduplicate = true
marker_prefix = "TRACE"
marker_position = "replace:{MARKER}"
grammar_dirs = ["./grammars"]
"#,
        )
        .unwrap();

        let (mut db, errors) =
            PayloadDb::load_config_and_grammars(dir.path().join("attackstr.toml")).unwrap();
        assert!(errors.is_empty(), "unexpected load errors: {errors:?}");

        let payloads = db.payloads("xss");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].text, "'<script>alert(1)</script>'");
    }

    #[test]
    fn marker_injection_inline() {
        let mut db = PayloadDb::with_config(PayloadConfig {
            marker_position: MarkerPosition::Inline,
            ..PayloadConfig::default()
        });
        db.load_toml(
            r#"
[grammar]
name = "m"
sink_category = "mark-inline"
[[techniques]]
name = "t"
template = "alert(1)"
"#,
        )
        .unwrap();

        let marked = db.payloads_with_marker("mark-inline", "SLN_42_");
        assert_eq!(marked[0].text, "{SLN_42_}alert(1)");
    }

    #[test]
    fn marker_injection_replace_placeholder() {
        let mut db = PayloadDb::with_config(PayloadConfig {
            marker_position: MarkerPosition::Replace("{MARKER}".into()),
            ..PayloadConfig::default()
        });
        db.load_toml(
            r#"
[grammar]
name = "m"
sink_category = "mark-replace"
[[techniques]]
name = "t"
template = "<!-- {MARKER} -->alert(1)"
"#,
        )
        .unwrap();

        let marked = db.payloads_with_marker("mark-replace", "SLN_42_");
        assert_eq!(marked[0].text, "<!-- SLN_42_ -->alert(1)");
    }

    #[test]
    fn custom_encoding() {
        fn reverse(s: &str) -> String {
            s.chars().rev().collect()
        }

        let mut db = PayloadDb::new();
        db.register_encoding("reverse", reverse);
        db.load_toml(
            r#"
[grammar]
name = "enc"
sink_category = "enc-cat"
[[techniques]]
name = "t"
template = "hello"
[[encodings]]
name = "rev"
transform = "reverse"
"#,
        )
        .unwrap();

        let payloads = db.payloads("enc-cat");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].text, "olleh");
    }

    #[test]
    fn payload_strings_convenience() {
        let mut db = PayloadDb::new();
        db.load_toml(
            r#"
[grammar]
name = "s"
sink_category = "strings"
[[techniques]]
name = "t"
template = "abc"
"#,
        )
        .unwrap();

        let strings = db.payload_strings("strings");
        assert_eq!(strings, vec!["abc"]);
    }

    #[test]
    fn categories_list() {
        let mut db = PayloadDb::new();
        db.load_toml(
            r#"
[grammar]
name = "a"
sink_category = "alpha"
[[techniques]]
name = "t"
template = "x"
"#,
        )
        .unwrap();
        db.load_toml(
            r#"
[grammar]
name = "b"
sink_category = "beta"
[[techniques]]
name = "t"
template = "y"
"#,
        )
        .unwrap();

        let mut cats = db.categories();
        cats.sort_unstable();
        assert_eq!(cats, vec!["alpha", "beta"]);
    }

    #[test]
    fn clear_resets() {
        let mut db = PayloadDb::new();
        db.load_toml(
            r#"
[grammar]
name = "c"
sink_category = "cleared"
[[techniques]]
name = "t"
template = "x"
"#,
        )
        .unwrap();

        assert_eq!(db.grammar_count(), 1);
        db.clear();
        assert_eq!(db.grammar_count(), 0);
        assert!(db.payloads("cleared").is_empty());
    }

    #[test]
    fn missing_category_returns_empty() {
        let mut db = PayloadDb::new();
        assert!(db.payloads("nonexistent").is_empty());
    }

    #[test]
    fn load_dir_with_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("test.toml"),
            r#"
[grammar]
name = "dir-test"
sink_category = "dir-cat"
[[techniques]]
name = "t"
template = "from-dir"
"#,
        )
        .unwrap();

        // Non-TOML file should be skipped.
        std::fs::write(dir.path().join("readme.txt"), "not a grammar").unwrap();

        let mut db = PayloadDb::new();
        let errors = db.load_dir(dir.path()).unwrap();
        assert!(errors.is_empty());

        assert_eq!(db.payloads("dir-cat").len(), 1);
        assert_eq!(db.payloads("dir-cat")[0].text, "from-dir");
    }

    #[test]
    fn load_dir_not_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file.txt");
        std::fs::write(&file, "not a dir").unwrap();

        let mut db = PayloadDb::new();
        assert!(db.load_dir(&file).is_err());
    }

    #[test]
    fn invalid_toml_error() {
        let mut db = PayloadDb::new();
        let result = db.load_toml("this is not valid {{{ toml");
        assert!(result.is_err());
    }

    #[test]
    fn load_dir_collects_errors_and_continues() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("good.toml"),
            r#"
[grammar]
name = "good"
sink_category = "dir-cat"
[[techniques]]
name = "t"
template = "ok"
"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("bad.toml"), "not valid toml {{{").unwrap();

        let mut db = PayloadDb::new();
        let errors = db.load_dir(dir.path()).unwrap();

        assert_eq!(errors.len(), 1);
        assert_eq!(db.payloads("dir-cat").len(), 1);
        assert_eq!(db.payloads("dir-cat")[0].text, "ok");
    }

    #[test]
    fn load_dir_lenient_collects_template_errors() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("bad-template.toml"),
            r#"
[grammar]
name = "bad-template"
sink_category = "dir-cat"
[[techniques]]
name = "t"
template = "{broken"
"#,
        )
        .unwrap();

        let mut db = PayloadDb::new();
        let errors = db.load_dir_lenient(dir.path()).unwrap();

        assert_eq!(errors.len(), 1);
        assert!(matches!(errors[0], PayloadError::GrammarValidation { .. }));
        assert!(db.payloads("dir-cat").is_empty());
    }

    #[test]
    fn load_toml_rejects_empty_technique_templates() {
        let mut db = PayloadDb::new();
        let error = db
            .load_toml(
                r#"
[grammar]
name = "invalid"
sink_category = "dir-cat"

[[techniques]]
name = "blank"
template = "   "
"#,
            )
            .unwrap_err();

        match error {
            PayloadError::GrammarValidation { issues, .. } => {
                assert!(issues.iter().any(|issue| issue.message.contains("empty template")));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn load_dir_reports_concurrent_loads_explicitly() {
        let dir = tempfile::tempdir().unwrap();
        let db = PayloadDb::new();
        let _guard = db.begin_load_session().unwrap();

        let mut db = db;
        let error = db.load_dir_lenient(dir.path()).unwrap_err();
        assert!(matches!(error, PayloadError::ConcurrentLoad));
    }

    #[test]
    fn variable_expansion_with_encodings() {
        let mut db = PayloadDb::new();
        db.load_toml(
            r#"
[grammar]
name = "ve"
sink_category = "ve-cat"

[[contexts]]
name = "c"
prefix = "'"
suffix = ""

[[techniques]]
name = "t"
template = "{prefix}OR {tautology}"

[[tautologies]]
value = "1=1"

[[encodings]]
name = "raw"
transform = "identity"

[[encodings]]
name = "url"
transform = "url_encode"
"#,
        )
        .unwrap();

        let payloads = db.payloads("ve-cat");
        assert_eq!(payloads.len(), 2); // 1 var × 1 technique × 2 encodings
        let texts: Vec<&str> = payloads.iter().map(|p| p.text.as_str()).collect();
        assert!(texts.contains(&"'OR 1=1"));
        assert!(texts.contains(&"%27OR%201%3D1"));
    }

    #[test]
    fn payload_metadata_propagates() {
        let mut db = PayloadDb::new();
        db.load_toml(
            r#"
[grammar]
name = "meta"
sink_category = "meta-cat"
severity = "high"
cwe = "CWE-89"

[[techniques]]
name = "t"
template = "SELECT 1"
confidence = 0.75
expected_pattern = "SELECT"
"#,
        )
        .unwrap();

        let payloads = db.payloads("meta-cat");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].severity.as_deref(), Some("high"));
        assert_eq!(payloads[0].cwe.as_deref(), Some("CWE-89"));
        assert!((payloads[0].confidence - 0.75).abs() < f64::EPSILON);
        assert_eq!(payloads[0].expected_pattern.as_deref(), Some("SELECT"));
    }

    #[test]
    fn iter_payloads_streams_category_payloads() {
        let mut db = PayloadDb::new();
        db.load_toml(
            r#"
[grammar]
name = "stream"
sink_category = "stream-cat"

[[techniques]]
name = "t1"
template = "{var}"

[[vars]]
value = "a"
[[vars]]
value = "b"
"#,
        )
        .unwrap();

        let payloads: Vec<_> = db
            .iter_payloads("stream-cat")
            .filter_map(Result::ok)
            .collect();

        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[0].text, "a");
        assert_eq!(payloads[1].text, "b");
    }

    #[test]
    fn iter_payloads_honors_deduplication_and_limits() {
        let mut db = PayloadDb::with_config(PayloadConfig {
            deduplicate: true,
            max_per_category: 1,
            ..PayloadConfig::default()
        });
        db.load_toml(
            r#"
[grammar]
name = "stream-limit"
sink_category = "stream-limit-cat"

[[techniques]]
name = "a"
template = "same"

[[techniques]]
name = "b"
template = "same"
"#,
        )
        .unwrap();

        let payloads: Vec<_> = db
            .iter_payloads("stream-limit-cat")
            .filter_map(Result::ok)
            .collect();

        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].text, "same");
    }

    #[test]
    fn load_config_and_grammars_loads_relative_grammar_dirs() {
        let root = tempfile::tempdir().unwrap();
        let grammars_dir = root.path().join("grammars");
        std::fs::create_dir(&grammars_dir).unwrap();
        std::fs::write(
            grammars_dir.join("xss.toml"),
            r#"
[grammar]
name = "xss"
sink_category = "xss"

[[techniques]]
name = "basic"
template = "<script>alert(1)</script>"
"#,
        )
        .unwrap();
        let config_path = root.path().join("santh-payloads.toml");
        std::fs::write(
            &config_path,
            r#"
deduplicate = true
grammar_dirs = ["./grammars"]
"#,
        )
        .unwrap();

        let (mut db, errors) = PayloadDb::load_config_and_grammars(&config_path).unwrap();

        assert!(errors.is_empty());
        assert_eq!(db.payloads("xss").len(), 1);
        assert_eq!(db.payloads("xss")[0].text, "<script>alert(1)</script>");
    }

    #[test]
    fn load_config_and_grammars_returns_collected_grammar_errors() {
        let root = tempfile::tempdir().unwrap();
        let grammars_dir = root.path().join("grammars");
        std::fs::create_dir(&grammars_dir).unwrap();
        std::fs::write(
            grammars_dir.join("good.toml"),
            r#"
[grammar]
name = "good"
sink_category = "cat"

[[techniques]]
name = "ok"
template = "payload"
"#,
        )
        .unwrap();
        std::fs::write(grammars_dir.join("bad.toml"), "not valid toml {{{").unwrap();
        let config_path = root.path().join("santh-payloads.toml");
        std::fs::write(&config_path, "grammar_dirs = [\"./grammars\"]").unwrap();

        let (mut db, errors) = PayloadDb::load_config_and_grammars(&config_path).unwrap();

        assert_eq!(errors.len(), 1);
        assert_eq!(db.payloads("cat").len(), 1);
    }
}
