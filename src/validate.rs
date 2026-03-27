//! Grammar validation — catch errors at load time, not expansion time.

use serde::{Deserialize, Serialize};

use crate::grammar::{Grammar, GrammarMeta};

/// A validation warning or error found in a grammar.
///
/// # Thread Safety
/// `GrammarIssue` is `Send` and `Sync`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GrammarIssue {
    /// The grammar name.
    pub grammar: String,
    /// The issue severity.
    pub level: IssueLevel,
    /// Human-readable description of the issue.
    pub message: String,
}

impl std::fmt::Display for GrammarIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.level, self.message)
    }
}

/// Severity of a grammar validation issue.
///
/// # Thread Safety
/// `IssueLevel` is `Send` and `Sync`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum IssueLevel {
    /// Problem that will cause incorrect behavior.
    Error,
    /// Likely mistake but grammar will still work.
    Warning,
}

impl std::fmt::Display for IssueLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Error => f.write_str("error"),
            Self::Warning => f.write_str("warning"),
        }
    }
}

/// Validate a grammar and return any issues found.
///
/// Example:
/// ```rust
/// use attackstr::{validate, Grammar, GrammarMeta, Technique};
/// use std::collections::HashMap;
///
/// let grammar = Grammar {
///     meta: GrammarMeta {
///         name: "example".into(),
///         sink_category: "xss".into(),
///         description: None,
///         tags: Vec::new(),
///         severity: None,
///         cwe: None,
///         target_runtime: None,
///     },
///     contexts: Vec::new(),
///     techniques: vec![Technique {
///         name: "basic".into(),
///         template: "<script>alert(1)</script>".into(),
///         tags: Vec::new(),
///         confidence: 1.0,
///         expected_pattern: None,
///     }],
///     encodings: Vec::new(),
///     variables: HashMap::new(),
/// };
///
/// assert!(validate(&grammar).is_empty());
/// ```
#[must_use]
pub fn validate(grammar: &Grammar) -> Vec<GrammarIssue> {
    let mut issues = Vec::new();
    let name = &grammar.meta.name;

    validate_meta(&grammar.meta, name, &mut issues);
    validate_techniques(grammar, name, &mut issues);
    validate_encodings(grammar, name, &mut issues);
    validate_variables(grammar, name, &mut issues);

    issues
}

fn validate_meta(meta: &GrammarMeta, name: &str, issues: &mut Vec<GrammarIssue>) {
    if meta.name.is_empty() {
        issues.push(GrammarIssue {
            grammar: name.into(),
            level: IssueLevel::Error,
            message: "grammar name is empty".into(),
        });
    }
    if meta.sink_category.is_empty() {
        issues.push(GrammarIssue {
            grammar: name.into(),
            level: IssueLevel::Error,
            message: "sink_category is empty — payloads won't be retrievable".into(),
        });
    }
}

fn validate_techniques(grammar: &Grammar, name: &str, issues: &mut Vec<GrammarIssue>) {
    if grammar.techniques.is_empty() {
        issues.push(GrammarIssue {
            grammar: name.into(),
            level: IssueLevel::Warning,
            message: "no techniques defined — grammar produces no payloads".into(),
        });
        return;
    }

    for tech in &grammar.techniques {
        if tech.template.trim().is_empty() {
            issues.push(GrammarIssue {
                grammar: name.into(),
                level: IssueLevel::Error,
                message: format!("technique '{}' has empty template", tech.name),
            });
        }

        // Check for unreferenced variables in template.
        check_template_variables(grammar, tech, name, issues);

        if tech.confidence < 0.0 || tech.confidence > 1.0 {
            issues.push(GrammarIssue {
                grammar: name.into(),
                level: IssueLevel::Warning,
                message: format!(
                    "technique '{}' confidence {} is outside [0.0, 1.0]",
                    tech.name, tech.confidence
                ),
            });
        }
    }
}

fn check_template_variables(
    grammar: &Grammar,
    tech: &crate::grammar::Technique,
    name: &str,
    issues: &mut Vec<GrammarIssue>,
) {
    let mut pos = 0;
    while let Some(start) = tech.template[pos..].find('{') {
        let abs_start = pos + start;
        if let Some(end) = tech.template[abs_start..].find('}') {
            let var_name = &tech.template[abs_start + 1..abs_start + end];
            let looks_like_var = var_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
            if looks_like_var
                && var_name != "prefix"
                && var_name != "suffix"
                && !var_name.is_empty()
            {
                // Check if this variable exists (plural or singular).
                let has_var = grammar.variables.contains_key(var_name)
                    || grammar.variables.contains_key(&format!("{var_name}s"))
                    || grammar
                        .variables
                        .keys()
                        .any(|k| crate::grammar::depluralize(k) == var_name);
                if !has_var {
                    issues.push(GrammarIssue {
                        grammar: name.into(),
                        level: IssueLevel::Warning,
                        message: format!(
                            "technique '{}' references undefined variable '{{{}}}'",
                            tech.name, var_name
                        ),
                    });
                }
            }
            pos = abs_start + end + 1;
        } else {
            issues.push(GrammarIssue {
                grammar: name.into(),
                level: IssueLevel::Error,
                message: format!("technique '{}' has unclosed '{{' in template", tech.name),
            });
            break;
        }
    }
}

fn validate_encodings(grammar: &Grammar, name: &str, issues: &mut Vec<GrammarIssue>) {
    let known = crate::encoding::BuiltinEncoding::ALL;
    for enc in &grammar.encodings {
        if !known.contains(&enc.transform.as_str()) {
            issues.push(GrammarIssue {
                grammar: name.into(),
                level: IssueLevel::Warning,
                message: format!(
                    "encoding '{}' uses unknown transform '{}' — will pass through unchanged",
                    enc.name, enc.transform
                ),
            });
        }
    }
}

fn validate_variables(grammar: &Grammar, name: &str, issues: &mut Vec<GrammarIssue>) {
    for (var_name, values) in &grammar.variables {
        // Skip known non-variable keys.
        if ["grammar", "contexts", "techniques", "encodings"].contains(&var_name.as_str()) {
            continue;
        }
        if values.is_empty() {
            issues.push(GrammarIssue {
                grammar: name.into(),
                level: IssueLevel::Warning,
                message: format!("variable '{var_name}' has no values"),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grammar::*;
    use std::collections::HashMap;

    fn meta(name: &str, cat: &str) -> GrammarMeta {
        GrammarMeta {
            name: name.into(),
            sink_category: cat.into(),
            description: None,
            tags: vec![],
            severity: None,
            cwe: None,
            target_runtime: None,
        }
    }

    #[test]
    fn valid_grammar_no_issues() {
        let mut vars = HashMap::new();
        vars.insert("cmds".into(), vec![Variable { value: "id".into() }]);

        let g = Grammar {
            meta: meta("test", "rce"),
            contexts: vec![Context {
                name: "default".into(),
                prefix: String::new(),
                suffix: String::new(),
            }],
            techniques: vec![Technique {
                name: "exec".into(),
                template: "{cmd}".into(),
                tags: vec![],
                confidence: 1.0,
                expected_pattern: None,
            }],
            encodings: vec![Encoding {
                name: "raw".into(),
                transform: "identity".into(),
            }],
            variables: vars,
        };

        let issues = validate(&g);
        assert!(issues.is_empty(), "unexpected issues: {issues:?}");
    }

    #[test]
    fn empty_name_is_error() {
        let g = Grammar {
            meta: meta("", "cat"),
            contexts: vec![],
            techniques: vec![],
            encodings: vec![],
            variables: HashMap::new(),
        };
        let issues = validate(&g);
        assert!(issues
            .iter()
            .any(|i| i.level == IssueLevel::Error && i.message.contains("name is empty")));
    }

    #[test]
    fn empty_category_is_error() {
        let g = Grammar {
            meta: meta("test", ""),
            contexts: vec![],
            techniques: vec![],
            encodings: vec![],
            variables: HashMap::new(),
        };
        let issues = validate(&g);
        assert!(issues
            .iter()
            .any(|i| i.level == IssueLevel::Error && i.message.contains("sink_category")));
    }

    #[test]
    fn no_techniques_warns() {
        let g = Grammar {
            meta: meta("test", "cat"),
            contexts: vec![],
            techniques: vec![],
            encodings: vec![],
            variables: HashMap::new(),
        };
        let issues = validate(&g);
        assert!(issues
            .iter()
            .any(|i| i.level == IssueLevel::Warning && i.message.contains("no techniques")));
    }

    #[test]
    fn empty_template_is_error() {
        let g = Grammar {
            meta: meta("test", "cat"),
            contexts: vec![],
            techniques: vec![Technique {
                name: "blank".into(),
                template: "   ".into(),
                tags: vec![],
                confidence: 1.0,
                expected_pattern: None,
            }],
            encodings: vec![],
            variables: HashMap::new(),
        };

        let issues = validate(&g);
        assert!(issues
            .iter()
            .any(|i| i.level == IssueLevel::Error && i.message.contains("empty template")));
    }

    #[test]
    fn undefined_variable_warns() {
        let g = Grammar {
            meta: meta("test", "cat"),
            contexts: vec![],
            techniques: vec![Technique {
                name: "t".into(),
                template: "{missing_var}".into(),
                tags: vec![],
                confidence: 1.0,
                expected_pattern: None,
            }],
            encodings: vec![],
            variables: HashMap::new(),
        };
        let issues = validate(&g);
        assert!(issues
            .iter()
            .any(|i| i.message.contains("undefined variable")));
    }

    #[test]
    fn unclosed_brace_is_error() {
        let g = Grammar {
            meta: meta("test", "cat"),
            contexts: vec![],
            techniques: vec![Technique {
                name: "t".into(),
                template: "unclosed {brace".into(),
                tags: vec![],
                confidence: 1.0,
                expected_pattern: None,
            }],
            encodings: vec![],
            variables: HashMap::new(),
        };
        let issues = validate(&g);
        assert!(issues
            .iter()
            .any(|i| i.level == IssueLevel::Error && i.message.contains("unclosed")));
    }

    #[test]
    fn unknown_encoding_warns() {
        let g = Grammar {
            meta: meta("test", "cat"),
            contexts: vec![],
            techniques: vec![Technique {
                name: "t".into(),
                template: "x".into(),
                tags: vec![],
                confidence: 1.0,
                expected_pattern: None,
            }],
            encodings: vec![Encoding {
                name: "custom".into(),
                transform: "nonexistent_transform".into(),
            }],
            variables: HashMap::new(),
        };
        let issues = validate(&g);
        assert!(issues
            .iter()
            .any(|i| i.message.contains("unknown transform")));
    }

    #[test]
    fn bad_confidence_warns() {
        let g = Grammar {
            meta: meta("test", "cat"),
            contexts: vec![],
            techniques: vec![Technique {
                name: "t".into(),
                template: "x".into(),
                tags: vec![],
                confidence: 1.5,
                expected_pattern: None,
            }],
            encodings: vec![],
            variables: HashMap::new(),
        };
        let issues = validate(&g);
        assert!(issues.iter().any(|i| i.message.contains("confidence")));
    }

    #[test]
    fn prefix_suffix_not_flagged_as_undefined() {
        let g = Grammar {
            meta: meta("test", "cat"),
            contexts: vec![Context {
                name: "c".into(),
                prefix: "'".into(),
                suffix: "--".into(),
            }],
            techniques: vec![Technique {
                name: "t".into(),
                template: "{prefix}OR 1=1{suffix}".into(),
                tags: vec![],
                confidence: 1.0,
                expected_pattern: None,
            }],
            encodings: vec![],
            variables: HashMap::new(),
        };
        let issues = validate(&g);
        assert!(issues.is_empty(), "unexpected: {issues:?}");
    }

    #[test]
    fn plural_variable_resolves() {
        let mut vars = HashMap::new();
        vars.insert(
            "tautologies".into(),
            vec![Variable {
                value: "1=1".into(),
            }],
        );

        let g = Grammar {
            meta: meta("test", "cat"),
            contexts: vec![],
            techniques: vec![Technique {
                name: "t".into(),
                template: "{tautology}".into(),
                tags: vec![],
                confidence: 1.0,
                expected_pattern: None,
            }],
            encodings: vec![],
            variables: vars,
        };
        let issues = validate(&g);
        assert!(issues.is_empty(), "unexpected: {issues:?}");
    }
}
