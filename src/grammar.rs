//! Grammar types — the TOML schema for payload definitions.

use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// A fully expanded payload candidate before it is converted into a public [`crate::Payload`].
///
/// # Thread Safety
/// `ExpandedPayload` is `Send` and `Sync`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExpandedPayload {
    /// Final text after template expansion and encoding.
    pub text: String,
    /// Technique name that produced the payload.
    pub technique: String,
    /// Context name used during expansion.
    pub context: String,
    /// Encoding name applied to the payload.
    pub encoding: String,
    /// Confidence score for this technique expansion.
    pub confidence: f64,
    /// Optional expected observer pattern for the response.
    pub expected_pattern: Option<String>,
}

impl Eq for ExpandedPayload {}

impl Hash for ExpandedPayload {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.text.hash(state);
        self.technique.hash(state);
        self.context.hash(state);
        self.encoding.hash(state);
        self.confidence.to_bits().hash(state);
        self.expected_pattern.hash(state);
    }
}

impl std::fmt::Display for ExpandedPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.technique, self.context, self.encoding, self.text
        )
    }
}

/// A complete grammar definition loaded from TOML.
///
/// Grammars define the Cartesian product of contexts × techniques × variables × encodings.
/// The expansion engine iterates all combinations to produce payloads.
///
/// # Thread Safety
/// `Grammar` is `Send` and `Sync`.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Grammar {
    /// Metadata about this grammar.
    #[serde(rename = "grammar")]
    pub meta: GrammarMeta,
    /// Injection contexts (prefix/suffix pairs).
    #[serde(default)]
    pub contexts: Vec<Context>,
    /// Attack techniques (templates with variable placeholders).
    #[serde(default)]
    pub techniques: Vec<Technique>,
    /// Encoding transforms to apply to final payloads.
    #[serde(default)]
    pub encodings: Vec<Encoding>,
    /// Variable definitions — keys are plural names (e.g. "tautologies"),
    /// values are lists of substitution values.
    #[serde(flatten)]
    pub variables: HashMap<String, Vec<Variable>>,
}

impl Hash for Grammar {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.meta.hash(state);
        self.contexts.hash(state);
        self.techniques.hash(state);
        self.encodings.hash(state);

        let mut variables: Vec<_> = self.variables.iter().collect();
        variables.sort_by(|(left, _), (right, _)| left.cmp(right));
        for (key, value) in variables {
            key.hash(state);
            value.hash(state);
        }
    }
}

impl std::fmt::Display for Grammar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.meta.name, self.meta.sink_category)
    }
}

/// Metadata about a grammar.
///
/// # Thread Safety
/// `GrammarMeta` is `Send` and `Sync`.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct GrammarMeta {
    /// Human-readable name (e.g. "sql-injection").
    pub name: String,
    /// Category this grammar targets — used for lookup and filtering.
    pub sink_category: String,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
    /// Optional tags for filtering (e.g. `["owasp-a03", "cwe-89"]`).
    #[serde(default)]
    pub tags: Vec<String>,
    /// Optional severity hint (tools may override).
    #[serde(default)]
    pub severity: Option<String>,
    /// Optional CWE ID (e.g. "CWE-89").
    #[serde(default)]
    pub cwe: Option<String>,
    /// Optional runtimes this grammar applies to (e.g. `["php", "node"]`).
    #[serde(default)]
    pub target_runtime: Option<Vec<String>>,
}

impl std::fmt::Display for GrammarMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name, self.sink_category)
    }
}

/// An injection context — defines prefix/suffix that break out of a data context.
///
/// # Thread Safety
/// `Context` is `Send` and `Sync`.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct Context {
    /// Name of this context (e.g. "string-break", "numeric").
    pub name: String,
    /// String prepended before the technique payload.
    pub prefix: String,
    /// String appended after the technique payload.
    #[serde(default)]
    pub suffix: String,
}

impl std::fmt::Display for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}

/// An attack technique — a template string with variable placeholders.
///
/// Placeholders use `{var_name}` syntax. The special variables `{prefix}` and
/// `{suffix}` are replaced with the current context's prefix/suffix.
///
/// # Thread Safety
/// `Technique` is `Send` and `Sync`.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct Technique {
    /// Name of this technique (e.g. "union-based", "time-based").
    pub name: String,
    /// Template string with `{variable}` placeholders.
    pub template: String,
    /// Optional tags for technique-level filtering.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Confidence score for this technique.
    #[serde(
        default = "default_confidence",
        deserialize_with = "deserialize_confidence"
    )]
    pub confidence: f64,
    /// Regex the observer should look for in the response.
    #[serde(default)]
    pub expected_pattern: Option<String>,
}

impl Eq for Technique {}

impl Hash for Technique {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.template.hash(state);
        self.tags.hash(state);
        self.confidence.to_bits().hash(state);
        self.expected_pattern.hash(state);
    }
}

impl std::fmt::Display for Technique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}

/// An encoding transform applied to the final payload.
///
/// # Thread Safety
/// `Encoding` is `Send` and `Sync`.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct Encoding {
    /// Name of this encoding (e.g. "url-encode", "hex").
    pub name: String,
    /// Transform identifier — maps to a built-in or custom encoding function.
    pub transform: String,
}

impl std::fmt::Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name, self.transform)
    }
}

/// A variable substitution value.
///
/// # Thread Safety
/// `Variable` is `Send` and `Sync`.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct Variable {
    /// The literal value to substitute.
    pub value: String,
}

impl std::fmt::Display for Variable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.value)
    }
}

/// Errors returned while expanding template placeholders.
///
/// # Thread Safety
/// `TemplateExpansionError` is `Send` and `Sync`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
#[non_exhaustive]
pub enum TemplateExpansionError {
    /// A template opened a placeholder but never closed it.
    #[error("unclosed '{{' in template: {template}. Fix: close every '{{' with a matching '}}' and keep braces balanced in all template variables.")]
    UnclosedBrace {
        /// The template fragment that failed.
        template: String,
    },
    /// Recursive variable expansion exceeded the allowed nesting depth.
    #[error("template expansion exceeded recursion depth limit ({max_depth}). Fix: reduce recursive variable references or simplify mutually-nesting templates.")]
    RecursionLimitExceeded {
        /// Maximum supported nesting depth.
        max_depth: usize,
    },
    /// Number of generated payloads exceeded the circuit breaker limit.
    #[error("grammar generated too many payloads (exceeded {limit}). Fix: reduce the size of variable value sets or lower cartesian expansion breadth.")]
    PayloadLimitExceeded {
        /// The limit that was exceeded.
        limit: usize,
    },
}

const MAX_TEMPLATE_RECURSION_DEPTH: usize = 50;

/// Expand a grammar into a list of payload strings.
///
/// The expansion is:
/// `for each context × technique × variable_combination × encoding`
///
/// Returns expanded payload records with generation metadata.
#[must_use]
pub fn expand(
    grammar: &Grammar,
    custom_encodings: &HashMap<String, fn(&str) -> String>,
) -> Result<Vec<ExpandedPayload>, TemplateExpansionError> {
    let mut results = Vec::new();
    for payload in iter_expanded(grammar, custom_encodings)? {
        results.push(payload?);
    }
    Ok(results)
}

pub(crate) fn iter_expanded<'a>(
    grammar: &'a Grammar,
    custom_encodings: &'a HashMap<String, fn(&str) -> String>,
) -> Result<GrammarExpansionIter<'a>, TemplateExpansionError> {
    GrammarExpansionIter::new(grammar, custom_encodings)
}

pub(crate) struct GrammarExpansionIter<'a> {
    grammar: &'a Grammar,
    custom_encodings: &'a HashMap<String, fn(&str) -> String>,
    lookup: Arc<HashMap<String, Vec<String>>>,
    contexts: Vec<Cow<'a, Context>>,
    encodings: Vec<Cow<'a, Encoding>>,
    next_context_index: usize,
    next_technique_index: usize,
    active_context_index: usize,
    active_technique_index: usize,
    active_templates: Option<TemplateExpansionIter>,
    active_template: Option<String>,
    active_encoding_index: usize,
    generated_count: usize,
}

impl<'a> GrammarExpansionIter<'a> {
    fn new(
        grammar: &'a Grammar,
        custom_encodings: &'a HashMap<String, fn(&str) -> String>,
    ) -> Result<Self, TemplateExpansionError> {
        let lookup = Arc::new(build_variable_lookup(grammar));
        let contexts: Vec<Cow<'a, Context>> = if grammar.contexts.is_empty() {
            vec![Cow::Owned(Context {
                name: "default".into(),
                prefix: String::new(),
                suffix: String::new(),
            })]
        } else {
            grammar.contexts.iter().cloned().map(Cow::Owned).collect()
        };
        let encodings: Vec<Cow<'a, Encoding>> = if grammar.encodings.is_empty() {
            vec![Cow::Owned(Encoding {
                name: "raw".into(),
                transform: "identity".into(),
            })]
        } else {
            grammar.encodings.iter().cloned().map(Cow::Owned).collect()
        };

        for ctx in &contexts {
            for tech in &grammar.techniques {
                let base = tech
                    .template
                    .replace("{prefix}", &ctx.prefix)
                    .replace("{suffix}", &ctx.suffix);
                let _ = TemplateExpansionIter::new(base, Arc::clone(&lookup))?;
            }
        }

        Ok(Self {
            grammar,
            custom_encodings,
            lookup,
            contexts,
            encodings,
            next_context_index: 0,
            next_technique_index: 0,
            active_context_index: 0,
            active_technique_index: 0,
            active_templates: None,
            active_template: None,
            active_encoding_index: 0,
            generated_count: 0,
        })
    }

    fn advance_source(&mut self) -> Result<bool, TemplateExpansionError> {
        if self.grammar.techniques.is_empty() {
            return Ok(false);
        }
        if self.next_context_index >= self.contexts.len() {
            return Ok(false);
        }

        let context_index = self.next_context_index;
        let technique_index = self.next_technique_index;
        let context = self.contexts[context_index].as_ref();
        let technique = &self.grammar.techniques[technique_index];
        let base = technique
            .template
            .replace("{prefix}", &context.prefix)
            .replace("{suffix}", &context.suffix);

        self.active_context_index = context_index;
        self.active_technique_index = technique_index;
        self.active_templates = Some(TemplateExpansionIter::new(base, Arc::clone(&self.lookup))?);
        self.active_template = None;
        self.active_encoding_index = 0;

        self.next_technique_index += 1;
        if self.next_technique_index >= self.grammar.techniques.len() {
            self.next_technique_index = 0;
            self.next_context_index += 1;
        }

        Ok(true)
    }
}

impl Iterator for GrammarExpansionIter<'_> {
    type Item = Result<ExpandedPayload, TemplateExpansionError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.generated_count >= 1_000_000 {
                return Some(Err(TemplateExpansionError::PayloadLimitExceeded {
                    limit: 1_000_000,
                }));
            }
            if let Some(template) = self.active_template.as_ref() {
                if self.active_encoding_index < self.encodings.len() {
                    let encoding = self.encodings[self.active_encoding_index].as_ref();
                    self.active_encoding_index += 1;
                    let technique = &self.grammar.techniques[self.active_technique_index];
                    let context = self.contexts[self.active_context_index].as_ref();
                    let encoded = apply_encoding_dispatch(
                        template,
                        &encoding.transform,
                        self.custom_encodings,
                    );
                    self.generated_count += 1;
                    return Some(Ok(ExpandedPayload {
                        text: encoded,
                        technique: technique.name.clone(),
                        context: context.name.clone(),
                        encoding: encoding.name.clone(),
                        confidence: technique.confidence,
                        expected_pattern: technique.expected_pattern.clone(),
                    }));
                }

                self.active_template = None;
                self.active_encoding_index = 0;
            }

            if let Some(templates) = self.active_templates.as_mut() {
                if let Some(template_res) = templates.next() {
                    match template_res {
                        Ok(template) => {
                            self.active_template = Some(template);
                            continue;
                        }
                        Err(e) => return Some(Err(e)),
                    }
                }
                self.active_templates = None;
            }

            match self.advance_source() {
                Ok(true) => (),
                Ok(false) => return None,
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

struct TemplateExpansionIter {
    lookup: Arc<HashMap<String, Vec<String>>>,
    stack: Vec<TemplateFrame>,
}

#[derive(Debug, Clone)]
struct TemplateFrame {
    prefix: String,
    remaining: String,
    depth: usize,
}

impl TemplateExpansionIter {
    fn new(
        template: String,
        lookup: Arc<HashMap<String, Vec<String>>>,
    ) -> Result<Self, TemplateExpansionError> {
        Ok(Self {
            lookup,
            stack: vec![TemplateFrame {
                prefix: String::new(),
                remaining: template,
                depth: 0,
            }],
        })
    }
}

impl Iterator for TemplateExpansionIter {
    type Item = Result<String, TemplateExpansionError>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(frame) = self.stack.pop() {
            if frame.depth > MAX_TEMPLATE_RECURSION_DEPTH {
                return Some(Err(TemplateExpansionError::RecursionLimitExceeded {
                    max_depth: MAX_TEMPLATE_RECURSION_DEPTH,
                }));
            }
            let Some(start) = frame.remaining.find('{') else {
                return Some(Ok(format!("{}{}", frame.prefix, frame.remaining)));
            };
            let Some(rel_end) = frame.remaining[start..].find('}') else {
                return Some(Err(TemplateExpansionError::UnclosedBrace {
                    template: format!("{}{}", frame.prefix, frame.remaining),
                }));
            };
            let end = start + rel_end;
            let var_name = &frame.remaining[start + 1..end];
            let before = &frame.remaining[..start];
            let after = &frame.remaining[end + 1..];
            let prefix = format!("{}{before}", frame.prefix);

            if let Some(values) = self.lookup.get(var_name) {
                for value in values.iter().rev() {
                    self.stack.push(TemplateFrame {
                        prefix: prefix.clone(),
                        remaining: format!("{value}{after}"),
                        depth: frame.depth + 1,
                    });
                }
            } else {
                let literal = format!("{{{var_name}}}");
                self.stack.push(TemplateFrame {
                    prefix: format!("{prefix}{literal}"),
                    remaining: after.to_string(),
                    depth: frame.depth + 1,
                });
            }
        }

        None
    }
}

fn build_variable_lookup(grammar: &Grammar) -> HashMap<String, Vec<String>> {
    let mut lookup = HashMap::new();
    for (k, vars) in &grammar.variables {
        let singular = depluralize(k);
        let values: Vec<String> = vars.iter().map(|v| v.value.clone()).collect();
        lookup.insert(singular.clone(), values.clone());
        lookup.insert(k.clone(), values);
    }
    lookup
}

fn deserialize_confidence<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let val = f64::deserialize(deserializer)?;
    if !(0.0..=1.0).contains(&val) || val.is_nan() {
        return Err(serde::de::Error::custom(
            "confidence must be between 0.0 and 1.0",
        ));
    }
    Ok(val)
}

fn default_confidence() -> f64 {
    1.0
}

/// Apply an encoding by name — checks custom encodings first, then builtins.
fn apply_encoding_dispatch(
    s: &str,
    transform: &str,
    custom: &HashMap<String, fn(&str) -> String>,
) -> String {
    if let Some(func) = custom.get(transform) {
        return func(s);
    }
    crate::encoding::apply_encoding(s, transform)
}

#[cfg(test)]
/// Recursively expand `{variable}` placeholders in a template string.
pub(crate) fn expand_template(
    template: String,
    lookup: &HashMap<String, Vec<String>>,
) -> Result<Vec<String>, TemplateExpansionError> {
    expand_template_with_depth(template, lookup, 0)
}

#[cfg(test)]
fn expand_template_with_depth(
    template: String,
    lookup: &HashMap<String, Vec<String>>,
    depth: usize,
) -> Result<Vec<String>, TemplateExpansionError> {
    if depth > MAX_TEMPLATE_RECURSION_DEPTH {
        return Err(TemplateExpansionError::RecursionLimitExceeded {
            max_depth: MAX_TEMPLATE_RECURSION_DEPTH,
        });
    }

    let Some(start) = template.find('{') else {
        return Ok(vec![template]);
    };
    let Some(rel_end) = template[start..].find('}') else {
        return Err(TemplateExpansionError::UnclosedBrace { template });
    };
    let end = start + rel_end;
    let var_name = &template[start + 1..end];
    let before = &template[..start];
    let after = &template[end + 1..];

    let mut results = Vec::new();
    if let Some(values) = lookup.get(var_name) {
        for val in values {
            let new_template = format!("{before}{val}{after}");
            results.extend(expand_template_with_depth(new_template, lookup, depth + 1)?);
        }
    } else {
        // Unknown variable — preserve placeholder, continue expanding `after`.
        for expanded_after in expand_template_with_depth(after.to_string(), lookup, depth + 1)? {
            results.push(format!("{before}{{{var_name}}}{expanded_after}"));
        }
    }
    Ok(results)
}

/// Simple depluralization for variable name matching.
///
/// "tautologies" → "tautology", "comments" → "comment", "vars" → "var"
pub(crate) fn depluralize(s: &str) -> String {
    if s.ends_with("ies") && s.len() > 3 {
        format!("{}y", &s[..s.len() - 3])
    } else if s.ends_with('s') && s.len() > 1 {
        s[..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_template_basic() {
        let mut lookup = HashMap::new();
        lookup.insert("tautology".to_string(), vec!["1=1".into(), "2>1".into()]);
        lookup.insert("comment".to_string(), vec!["--".into(), "#".into()]);

        let res = expand_template("OR {tautology}{comment}".into(), &lookup).unwrap();
        assert_eq!(res.len(), 4);
        assert!(res.contains(&"OR 1=1--".into()));
        assert!(res.contains(&"OR 2>1#".into()));
    }

    #[test]
    fn expand_template_no_vars() {
        let lookup = HashMap::new();
        let res = expand_template("static content".into(), &lookup).unwrap();
        assert_eq!(res, vec!["static content"]);
    }

    #[test]
    fn expand_template_missing_var() {
        let mut lookup = HashMap::new();
        lookup.insert("a".into(), vec!["X".into()]);

        let res = expand_template("{a}:{missing}".into(), &lookup).unwrap();
        assert_eq!(res, vec!["X:{missing}"]);
    }

    #[test]
    fn expand_template_preserves_marker_placeholder() {
        let lookup = HashMap::new();
        let res = expand_template("<!-- {MARKER} -->".into(), &lookup).unwrap();
        assert_eq!(res, vec!["<!-- {MARKER} -->"]);
    }

    #[test]
    fn expand_template_preserves_unknown_braces() {
        let lookup = HashMap::new();
        let res = expand_template("function() { return 1; }".into(), &lookup).unwrap();
        assert_eq!(res, vec!["function() { return 1; }"]);
    }

    #[test]
    fn expand_template_nested() {
        let mut lookup = HashMap::new();
        lookup.insert("inner".into(), vec!["X".into()]);
        lookup.insert("outer".into(), vec!["{inner}".into()]);

        let res = expand_template("{outer}".into(), &lookup).unwrap();
        assert_eq!(res, vec!["X"]);
    }

    #[test]
    fn expand_template_unclosed_brace_errors() {
        let lookup = HashMap::new();
        let err = expand_template("prefix {broken".into(), &lookup).unwrap_err();
        assert!(matches!(err, TemplateExpansionError::UnclosedBrace { .. }));
    }

    #[test]
    fn expand_template_recursion_limit_errors() {
        let mut lookup = HashMap::new();
        lookup.insert("loop".into(), vec!["{loop}".into()]);

        let err = expand_template("{loop}".into(), &lookup).unwrap_err();
        assert!(matches!(
            err,
            TemplateExpansionError::RecursionLimitExceeded { max_depth: 50 }
        ));
    }

    #[test]
    fn depluralize_cases() {
        assert_eq!(depluralize("tautologies"), "tautology");
        assert_eq!(depluralize("comments"), "comment");
        assert_eq!(depluralize("vars"), "var");
        assert_eq!(depluralize("s"), "s"); // too short
        assert_eq!(depluralize("ssrf_targets"), "ssrf_target");
    }

    #[test]
    fn expand_grammar_cartesian() {
        let mut vars = HashMap::new();
        vars.insert(
            "vars".to_string(),
            vec![
                Variable { value: "A".into() },
                Variable { value: "B".into() },
                Variable { value: "C".into() },
            ],
        );

        let grammar = Grammar {
            meta: GrammarMeta {
                name: "test".into(),
                sink_category: "test".into(),
                description: None,
                tags: vec![],
                severity: None,
                cwe: None,
                target_runtime: None,
            },
            contexts: vec![Context {
                name: "c1".into(),
                prefix: String::new(),
                suffix: String::new(),
            }],
            techniques: vec![
                Technique {
                    name: "t1".into(),
                    template: "{var}".into(),
                    tags: vec![],
                    confidence: 1.0,
                    expected_pattern: None,
                },
                Technique {
                    name: "t2".into(),
                    template: "X{var}Y".into(),
                    tags: vec![],
                    confidence: 1.0,
                    expected_pattern: None,
                },
            ],
            encodings: vec![
                Encoding {
                    name: "raw".into(),
                    transform: "identity".into(),
                },
                Encoding {
                    name: "url".into(),
                    transform: "url_encode".into(),
                },
            ],
            variables: vars,
        };

        let custom = HashMap::new();
        let payloads = expand(&grammar, &custom).unwrap();
        // 3 vars × 2 techniques × 2 encodings = 12
        assert_eq!(payloads.len(), 12);
    }

    #[test]
    fn expand_grammar_defaults() {
        let grammar = Grammar {
            meta: GrammarMeta {
                name: "test".into(),
                sink_category: "test".into(),
                description: None,
                tags: vec![],
                severity: None,
                cwe: None,
                target_runtime: None,
            },
            contexts: vec![], // uses default
            techniques: vec![Technique {
                name: "t1".into(),
                template: "hello".into(),
                tags: vec![],
                confidence: 1.0,
                expected_pattern: None,
            }],
            encodings: vec![], // uses default
            variables: HashMap::new(),
        };

        let custom = HashMap::new();
        let payloads = expand(&grammar, &custom).unwrap();
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].text, "hello");
    }

    #[test]
    fn expand_grammar_empty_techniques() {
        let grammar = Grammar {
            meta: GrammarMeta {
                name: "empty".into(),
                sink_category: "empty".into(),
                description: None,
                tags: vec![],
                severity: None,
                cwe: None,
                target_runtime: None,
            },
            contexts: vec![],
            techniques: vec![],
            encodings: vec![],
            variables: HashMap::new(),
        };

        let custom = HashMap::new();
        let payloads = expand(&grammar, &custom).unwrap();
        assert!(payloads.is_empty());
    }

    #[test]
    fn expand_propagates_technique_metadata() {
        let grammar = Grammar {
            meta: GrammarMeta {
                name: "meta".into(),
                sink_category: "meta".into(),
                description: None,
                tags: vec![],
                severity: Some("high".into()),
                cwe: Some("CWE-79".into()),
                target_runtime: None,
            },
            contexts: vec![],
            techniques: vec![Technique {
                name: "t1".into(),
                template: "alert(1)".into(),
                tags: vec![],
                confidence: 0.42,
                expected_pattern: Some("alert".into()),
            }],
            encodings: vec![],
            variables: HashMap::new(),
        };

        let custom = HashMap::new();
        let payloads = expand(&grammar, &custom).unwrap();
        assert_eq!(payloads.len(), 1);
        assert!((payloads[0].confidence - 0.42).abs() < f64::EPSILON);
        assert_eq!(payloads[0].expected_pattern.as_deref(), Some("alert"));
    }
}
