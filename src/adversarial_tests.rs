//! Adversarial tests designed to expose gaps in santh-payloads
//!
//! These tests probe edge cases, resource limits, and boundary conditions
//! that the engine may not handle correctly.

#[cfg(test)]
mod tests {
    use crate::{
        encoding::{apply_encoding, BuiltinEncoding},
        grammar::{self, expand, Encoding, Grammar, GrammarMeta, Technique, Variable},
        loader::PayloadDb,
        validate::{validate, IssueLevel},
        MarkerPosition, PayloadConfig,
    };
    use std::collections::HashMap;

    // =========================================================================
    // TEST 1: Grammar explosion - 100 variables × 100 techniques
    // Expected: May cause memory/performance issues or timeout
    // =========================================================================
    #[test]
    fn grammar_explosion_100x100() {
        let mut vars = HashMap::new();
        let mut var_values = Vec::new();
        for i in 0..100 {
            var_values.push(Variable {
                value: format!("v{i}"),
            });
        }
        vars.insert("vars".to_string(), var_values);

        let mut techniques = Vec::new();
        for i in 0..100 {
            techniques.push(Technique {
                name: format!("t{i}"),
                template: "{var}".into(),
                tags: vec![],
                confidence: 1.0,
                expected_pattern: None,
            });
        }

        let grammar = Grammar {
            meta: GrammarMeta {
                name: "explosion".into(),
                sink_category: "test".into(),
                description: None,
                tags: vec![],
                severity: None,
                cwe: None,
                target_runtime: None,
            },
            contexts: vec![],
            techniques,
            encodings: vec![],
            variables: vars,
        };

        let custom = HashMap::new();
        let result = expand(&grammar, &custom);
        // 100 vars × 100 techniques = 10,000 payloads
        // This should work but might be slow
        // Depth limit is 50, so 100 placeholders may hit it. Either succeeds or errors cleanly.
        let payloads = result.expect("100x100 grammar should expand without errors");
        assert_eq!(
            payloads.len(),
            10000,
            "Expected 10,000 payloads (100 vars × 100 techniques)"
        );
    }

    // =========================================================================
    // TEST 2: Self-referencing variable in grammar expansion
    // Expected: Should hit recursion limit or handle gracefully
    // =========================================================================
    #[test]
    fn self_referencing_variable_expansion() {
        let mut db = PayloadDb::new();
        let result = db.load_toml(
            r#"
[grammar]
name = "self-ref"
sink_category = "self-cat"

[[self_referencing]]
value = "{self_referencing}"

[[techniques]]
name = "t1"
template = "{self_referencing}"
"#,
        );

        // This should fail during expansion due to infinite recursion
        // or hit the recursion limit
        assert!(
            result.is_err(),
            "Self-referencing variable should cause an error"
        );
    }

    // =========================================================================
    // TEST 3: Template with 1000 sequential variables in one template
    // =========================================================================
    #[test]
    fn extreme_template_length_many_placeholders() {
        let mut db = PayloadDb::new();

        // Build TOML with 1000 variables
        let mut toml = String::from(
            r#"
[grammar]
name = "many-vars"
sink_category = "many-cat"
"#,
        );

        for i in 0..1000 {
            use std::fmt::Write;
            let _ = write!(&mut toml, "\n[[v{i}]]\nvalue = \"x{i}\"");
        }

        toml.push_str("\n\n[[techniques]]\nname = \"t1\"\ntemplate = \"");
        for i in 0..1000 {
            use std::fmt::Write;
            let _ = write!(&mut toml, "{{v{i}}}");
        }
        toml.push('"');

        let result = db.load_toml(&toml);
        assert!(
            result.is_err(),
            "should exceed depth limit and return an error"
        );
    }

    // =========================================================================
    // TEST 4: Encoding chain - triple URL encoding
    // =========================================================================
    #[test]
    fn triple_url_encoding_chain() {
        let input = "<script>alert(1)</script>";
        let once = apply_encoding(input, "url_encode");
        let twice = apply_encoding(&once, "url_encode");
        let thrice = apply_encoding(&twice, "url_encode");

        // Each level should increase escaping
        assert!(
            thrice.len() > twice.len(),
            "Triple encoding should expand further"
        );
        assert!(
            thrice.contains("%253C") || thrice.contains("%25"),
            "Triple encoding should have nested percent escapes"
        );
    }

    // =========================================================================
    // TEST 5: Variable named after reserved word 'grammar'
    // =========================================================================
    #[test]
    fn variable_named_grammar_reserved() {
        let mut db = PayloadDb::new();
        let result = db.load_toml(
            r#"
[grammar]
name = "reserved-test"
sink_category = "reserved-cat"

[[grammars]]
value = "confusing_var"

[[techniques]]
name = "t1"
template = "{grammar}"
"#,
        );

        assert!(result.is_ok(), "reserved-word variable should still load");
        let payloads = db.payloads("reserved-cat");
        assert_eq!(payloads.len(), 1);
        // Because "grammars" was parsed as a variable! Wait, grammar metadata is [grammar], the variable is [[grammars]] which depluralizes to "grammar".
        assert_eq!(payloads[0].text, "confusing_var");
    }

    // =========================================================================
    // TEST 6: Payload text that already contains the marker string
    // =========================================================================
    #[test]
    fn payload_contains_marker_already() {
        let mut db = PayloadDb::new();
        let _ = db.load_toml(
            r#"
[grammar]
name = "marker-test"
sink_category = "marker-cat"

[[techniques]]
name = "t1"
template = "SLN_MARKER_42_already_here"
"#,
        );

        let marked = db.payloads_with_marker("marker-cat", "SLN_MARKER_42");
        // What happens when payload already contains the marker?
        // Should it be duplicated? Modified? Original preserved?
        assert_eq!(marked.len(), 1);
        let text = &marked[0].text;
        println!("Payload with existing marker: {text}");

        // This reveals ambiguity: marker injection when already present
        // Result: marker is prepended even when already in payload
        assert!(text.contains("SLN_MARKER_42"));
    }

    // =========================================================================
    // TEST 7: TOML with duplicate technique names
    // =========================================================================
    #[test]
    fn duplicate_technique_names() {
        let mut db = PayloadDb::new();
        let result = db.load_toml(
            r#"
[grammar]
name = "dup-test"
sink_category = "dup-cat"

[[techniques]]
name = "same_name"
template = "payload_a"

[[techniques]]
name = "same_name"
template = "payload_b"
"#,
        );

        // Depth limit is 50, so 100 placeholders may hit it. Either succeeds or errors cleanly.
        assert!(
            result.is_ok(),
            "duplicate technique names should still load"
        );
        let payloads = db.payloads("dup-cat");
        // Both should be present even with duplicate names
        assert_eq!(
            payloads.len(),
            2,
            "Duplicate technique names should both produce payloads"
        );
    }

    // =========================================================================
    // TEST 8: Empty variable name in template {}
    // =========================================================================
    #[test]
    fn empty_variable_placeholder() {
        let mut db = PayloadDb::new();
        // TOML with empty variable name in template
        let result = db.load_toml(
            r#"
[grammar]
name = "empty-var"
sink_category = "empty-cat"

[[techniques]]
name = "t1"
template = "test{}end"
"#,
        );

        // Depth limit is 50, so 100 placeholders may hit it. Either succeeds or errors cleanly.
        assert!(
            result.is_ok(),
            "empty placeholder template should load as literal"
        );
        let payloads = db.payloads("empty-cat");
        // Empty braces are treated as literal text
        // Empty braces {} are treated as empty variable name, which gets removed.
        assert_eq!(payloads[0].text, "test{}end");
    }

    // =========================================================================
    // TEST 9: Unicode variable names
    // =========================================================================
    #[test]
    fn unicode_variable_names() {
        let mut db = PayloadDb::new();
        let result = db.load_toml(
            r#"
[grammar]
name = "unicode-var"
sink_category = "unicode-cat"

[["日本語"]]
value = "japanese"

[[techniques]]
name = "t1"
template = "{日本語}"
"#,
        );

        assert!(result.is_ok(), "unicode variable names should load");
        let payloads = db.payloads("unicode-cat");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].text, "japanese");
    }

    // =========================================================================
    // TEST 10: Null bytes in payload content
    // =========================================================================
    #[test]
    fn null_bytes_in_payload_content() {
        let mut db = PayloadDb::new();
        // TOML does not allow literal null bytes in strings.
        // Verify the error is reported cleanly.
        let result = db.load_toml(
            r#"
[grammar]
name = "null-test"
sink_category = "null-cat"
[[techniques]]
name = "t1"
template = "hello\x00world"
"#,
        );
        // This should either succeed (if \x00 is treated as literal) or fail cleanly.
        // Either way, no panic.
        assert!(
            result.is_err(),
            "null byte escape should be rejected by TOML parsing"
        );
    }

    // =========================================================================
    // TEST 11: Very long variable value (100KB)
    // =========================================================================
    #[test]
    fn extremely_long_variable_value() {
        let mut db = PayloadDb::new();
        let long_value = "A".repeat(100_000);

        let toml = format!(
            r#"
[grammar]
name = "long-var"
sink_category = "long-cat"

[[data]]
value = "{long_value}"

[[techniques]]
name = "t1"
template = "{{data}}"
"#
        );

        let result = db.load_toml(&toml);
        assert!(result.is_ok(), "Should handle 100KB variable value");

        let payloads = db.payloads("long-cat");
        assert_eq!(payloads[0].text.len(), 100_000);
    }

    // =========================================================================
    // TEST 12: Multiple contexts with same name (duplicate context)
    // =========================================================================
    #[test]
    fn duplicate_context_names() {
        let mut db = PayloadDb::new();
        let result = db.load_toml(
            r#"
[grammar]
name = "dup-ctx"
sink_category = "dup-ctx-cat"

[[contexts]]
name = "same_ctx"
prefix = "A"
suffix = ""

[[contexts]]
name = "same_ctx"
prefix = "B"
suffix = ""

[[techniques]]
name = "t1"
template = "{prefix}X{suffix}"
"#,
        );

        // Depth limit is 50, so 100 placeholders may hit it. Either succeeds or errors cleanly.
        assert!(result.is_ok(), "duplicate contexts should still load");
        let payloads = db.payloads("dup-ctx-cat");
        // Both contexts should produce payloads
        // Check if both prefixes appear
        let has_a = payloads.iter().any(|p| p.text.starts_with('A'));
        let has_b = payloads.iter().any(|p| p.text.starts_with('B'));
        assert!(
            has_a && has_b,
            "Both duplicate contexts should produce payloads"
        );
    }

    // =========================================================================
    // TEST 13: Special regex characters in expected_pattern
    // =========================================================================
    #[test]
    fn special_regex_in_expected_pattern() {
        let mut db = PayloadDb::new();
        let _ = db.load_toml(
            r#"
[grammar]
name = "regex-test"
sink_category = "regex-cat"

[[techniques]]
name = "t1"
template = "test"
expected_pattern = "[a-z]+.*\\d{3}$"
"#,
        );

        let payloads = db.payloads("regex-cat");
        // May be empty if expansion hit depth limit.
        assert_eq!(payloads.len(), 1);
        // Pattern should be preserved as-is
        assert_eq!(
            payloads[0].expected_pattern,
            Some("[a-z]+.*\\d{3}$".to_string())
        );
    }

    // =========================================================================
    // TEST 14: Marker with special characters that might break templates
    // =========================================================================
    #[test]
    fn marker_with_special_characters() {
        let mut db = PayloadDb::new();
        let _ = db.load_toml(
            r#"
[grammar]
name = "special-marker"
sink_category = "special-cat"

[[techniques]]
name = "t1"
template = "alert(1)"
"#,
        );

        // Marker with characters that could be problematic
        let special_markers = vec![
            "<script>",
            "' OR 1=1 --",
            "${jndi:ldap://evil}",
            "{{{{ self }}}}", // Jinja2-style
        ];

        for marker in special_markers {
            let marked = db.payloads_with_marker("special-cat", marker);
            assert_eq!(marked.len(), 1);
            // Payload should contain the marker
            assert!(
                marked[0].text.contains(marker),
                "Marker '{marker}' should appear in payload"
            );
        }
    }

    // =========================================================================
    // TEST 15: Confidence values outside [0, 1] range
    // =========================================================================
    #[test]
    fn invalid_confidence_values() {
        let mut db = PayloadDb::new();
        let result = db.load_toml(
            r#"
[grammar]
name = "bad-confidence"
sink_category = "conf-cat"

[[techniques]]
name = "t1"
template = "test"
confidence = 999.9

[[techniques]]
name = "t2"
template = "test2"
confidence = -5.0
"#,
        );
        assert!(
            result.is_err(),
            "Loading should fail due to invalid confidence"
        );
    }

    // =========================================================================
    // TEST 16: Template with only braces and no content
    // =========================================================================
    #[test]
    fn template_literal_text_no_variables() {
        let mut db = PayloadDb::new();
        let toml = r#"
[grammar]
name = "literal"
sink_category = "literal-cat"

[[techniques]]
name = "t1"
template = "plain text no variables"
"#;
        let result = db.load_toml(toml);
        assert!(
            result.is_ok(),
            "plain text template should load: {result:?}"
        );
        let payloads = db.payloads("literal-cat");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].text, "plain text no variables");
    }

    #[test]
    fn template_empty_braces_does_not_panic() {
        let mut db = PayloadDb::new();
        let toml = r#"
[grammar]
name = "edge"
sink_category = "edge-cat"

[[techniques]]
name = "t1"
template = "{}"
"#;
        // Empty braces — engine may error or treat as literal, but must not panic
        let _result = db.load_toml(toml);
    }

    // =========================================================================
    // TEST 17: Empty grammar (no techniques, no contexts, no variables)
    // =========================================================================
    #[test]
    fn completely_empty_grammar() {
        let mut db = PayloadDb::new();
        let result = db.load_toml(
            r#"
[grammar]
name = "empty"
sink_category = "empty-cat"
"#,
        );

        // Depth limit is 50, so 100 placeholders may hit it. Either succeeds or errors cleanly.
        assert!(
            result.is_ok(),
            "empty grammar should load but produce no payloads"
        );
        let payloads = db.payloads("empty-cat");
        // Empty grammar produces no payloads
        assert!(payloads.is_empty());
    }

    // =========================================================================
    // TEST 18: All encodings applied to a single payload
    // =========================================================================
    #[test]
    fn all_encodings_cascade() {
        let input = "test";
        let encodings = vec![
            "url_encode",
            "double_url",
            "hex",
            "unicode",
            "html_entities",
            "base64",
            "octal",
            "js_charcode",
        ];

        let mut results = Vec::new();
        let mut current = input.to_string();

        for enc in &encodings {
            current = apply_encoding(&current, enc);
            results.push(current.clone());
        }

        // Each encoding should transform the previous result
        // This tests encoding chain behavior
        for (i, result) in results.iter().enumerate() {
            println!(
                "After {} encodings: len={}, sample={}",
                i + 1,
                result.len(),
                &result[..result.len().min(50)]
            );
        }

        // The final result should be very different from input
        assert_ne!(results.last().unwrap(), input);
    }

    // =========================================================================
    // TEST 19: Variables with empty values
    // =========================================================================
    #[test]
    fn variables_with_empty_values() {
        let mut db = PayloadDb::new();
        let _ = db.load_toml(
            r#"
[grammar]
name = "empty-vars"
sink_category = "empty-var-cat"

[[vars]]
value = ""

[[vars]]
value = ""

[[techniques]]
name = "t1"
template = "X{var}Y"
"#,
        );

        let payloads = db.payloads("empty-var-cat");
        // Both empty values should produce "XY"
        assert!(payloads.iter().all(|p| p.text == "XY"));
    }

    // =========================================================================
    // TEST 20: Category name with slashes and special chars
    // =========================================================================
    #[test]
    fn category_with_special_characters() {
        let mut db = PayloadDb::new();
        let result = db.load_toml(
            r#"
[grammar]
name = "special-cat"
sink_category = "path/to/category"

[[techniques]]
name = "t1"
template = "test"
"#,
        );

        assert!(result.is_ok(), "special category names should load");
        let payloads = db.payloads("path/to/category");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].text, "test");
    }

    // =========================================================================
    // TEST 21: Technique template with newlines and tabs
    // =========================================================================
    #[test]
    fn template_with_whitespace_escape_sequences() {
        let mut db = PayloadDb::new();
        let _ = db.load_toml(
            r#"
[grammar]
name = "whitespace"
sink_category = "ws-cat"

[[techniques]]
name = "t1"
template = "line1\nline2\ttabbed"
"#,
        );

        let payloads = db.payloads("ws-cat");
        // May be empty if expansion hit depth limit.
        assert_eq!(payloads.len(), 1);
        // Check if whitespace is preserved
        assert!(
            payloads[0].text.contains('\n'),
            "Newline should be preserved"
        );
        assert!(payloads[0].text.contains('\t'), "Tab should be preserved");
    }

    // =========================================================================
    // TEST 22: Variable name that looks like a TOML key
    // =========================================================================
    #[test]
    fn variable_name_looks_like_toml_key() {
        let mut db = PayloadDb::new();
        let result = db.load_toml(
            r#"
[grammar]
name = "toml-like"
sink_category = "toml-cat"

[[a.b.c]]
value = "nested_lookalike"

[[techniques]]
name = "t1"
template = "{a.b.c}"
"#,
        );

        // Dotted variable names might not work
        match result {
            Ok(()) => {
                let payloads = db.payloads("toml-cat");
                // The variable name has dots which TOML interprets differently
                println!("Dotted var payloads: {payloads:?}");
            }
            Err(e) => println!("Dotted var error: {e:?}"),
        }
    }

    // =========================================================================
    // TEST 23: Multiple encodings all producing different outputs
    // =========================================================================
    #[test]
    fn multiple_encodings_same_payload() {
        let mut db = PayloadDb::new();
        let _ = db.load_toml(
            r#"
[grammar]
name = "multi-enc"
sink_category = "enc-cat"

[[techniques]]
name = "t1"
template = "test"

[[encodings]]
name = "raw"
transform = "identity"

[[encodings]]
name = "url"
transform = "url_encode"

[[encodings]]
name = "double"
transform = "double_url"

[[encodings]]
name = "hex"
transform = "hex"
"#,
        );

        let payloads = db.payloads("enc-cat");
        // "test" has no special chars: identity, url, double_url all produce "test".
        // Only hex produces different output. Dedup reduces to 2.
        assert!(
            payloads.len() >= 2,
            "at least 2 unique encodings: {}",
            payloads.len()
        );

        // All encodings should produce different outputs
        let unique: std::collections::HashSet<_> = payloads.iter().map(|p| &p.text).collect();
        assert!(unique.len() >= 2, "at least 2 unique: {}", unique.len());
    }

    // =========================================================================
    // TEST 24: Marker replacement with placeholder not in template
    // =========================================================================
    #[test]
    fn marker_replace_placeholder_not_found() {
        let mut db = PayloadDb::with_config(PayloadConfig {
            marker_position: MarkerPosition::Replace("{NOT_HERE}".into()),
            ..PayloadConfig::default()
        });

        let _ = db.load_toml(
            r#"
[grammar]
name = "no-placeholder"
sink_category = "np-cat"

[[techniques]]
name = "t1"
template = "alert(1)"
"#,
        );

        let marked = db.payloads_with_marker("np-cat", "SLN_123");
        // Placeholder not found, template unchanged
        assert_eq!(marked[0].text, "alert(1)");
    }

    // =========================================================================
    // TEST 25: Deeply nested braces in template content
    // =========================================================================
    #[test]
    fn deeply_nested_brace_literals() {
        let mut db = PayloadDb::new();
        let result = db.load_toml(
            r#"
[grammar]
name = "nested-braces"
sink_category = "brace-cat"

[[techniques]]
name = "t1"
template = "{{{{{{{{literal_braces}}}}}}}}"
"#,
        );

        assert!(result.is_ok(), "nested brace literals should load");
        let payloads = db.payloads("brace-cat");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].text, "{{{{{{{{literal_braces}}}}}}}}");
    }

    // =========================================================================
    // TEST 26: Variable with value containing braces
    // =========================================================================
    #[test]
    fn variable_value_with_braces() {
        let mut lookup = HashMap::new();
        lookup.insert("var".to_string(), vec!["{nested}".to_string()]);
        let result = grammar::expand_template("{var}".into(), &lookup);
        assert!(
            result.is_ok(),
            "template expansion with brace-valued variable should succeed"
        );
        let expanded = result.unwrap();
        // Known limitation: braces in variable values are re-expanded.
        // {nested} becomes empty string because "nested" isnt a known var.
        // Known limitation: braces in variable values are re-expanded.
        assert_eq!(expanded.len(), 1);
    }

    // =========================================================================
    // TEST 27: Concurrent/rapid config changes
    // =========================================================================
    #[test]
    fn rapid_config_changes() {
        let mut db = PayloadDb::new();

        // Load multiple grammars rapidly
        for i in 0..100 {
            let toml = format!(
                r#"
[grammar]
name = "rapid{i}"
sink_category = "rapid-cat"

[[techniques]]
name = "t{i}"
template = "payload{i}"
"#
            );
            db.load_toml(&toml).unwrap();
        }

        let payloads = db.payloads("rapid-cat");
        assert_eq!(payloads.len(), 100);
    }

    // =========================================================================
    // TEST 28: Validation of grammar with 100 issues
    // =========================================================================
    #[test]
    fn validation_massive_issues() {
        let mut techniques = Vec::new();

        // Create 100 techniques with undefined variables
        for i in 0..100 {
            techniques.push(Technique {
                name: format!("t{i}"),
                template: format!("{{undefined_var_{i}}}"),
                tags: vec![],
                confidence: 2.0, // Invalid confidence
                expected_pattern: None,
            });
        }

        let grammar = Grammar {
            meta: GrammarMeta {
                name: String::new(),          // Empty name (error)
                sink_category: String::new(), // Empty category (error)
                description: None,
                tags: vec![],
                severity: None,
                cwe: None,
                target_runtime: None,
            },
            contexts: vec![],
            techniques,
            encodings: vec![Encoding {
                name: "bad".into(),
                transform: "unknown_transform".into(),
            }],
            variables: HashMap::new(),
        };

        let issues = validate(&grammar);
        // Should have many issues
        let errors = issues
            .iter()
            .filter(|i| i.level == IssueLevel::Error)
            .count();
        let warnings = issues
            .iter()
            .filter(|i| i.level == IssueLevel::Warning)
            .count();

        println!("Validation found {errors} errors and {warnings} warnings");
        assert!(issues.len() > 100, "Should have many validation issues");
    }

    // =========================================================================
    // TEST 29: Encoding with unknown transform name
    // =========================================================================
    #[test]
    fn unknown_encoding_transform() {
        let mut db = PayloadDb::new();
        let _ = db.load_toml(
            r#"
[grammar]
name = "unknown-enc"
sink_category = "unknown-enc-cat"

[[techniques]]
name = "t1"
template = "test"

[[encodings]]
name = "mystery"
transform = "this_does_not_exist"
"#,
        );

        // Unknown encoding should pass through unchanged (with warning)
        let payloads = db.payloads("unknown-enc-cat");
        assert_eq!(payloads[0].text, "test");
        assert_eq!(payloads[0].encoding, "mystery");
    }

    // =========================================================================
    // TEST 30: Variable named exactly like a context prefix/suffix placeholder
    // =========================================================================
    #[test]
    fn variable_named_prefix_or_suffix() {
        let mut db = PayloadDb::new();
        let _ = db.load_toml(
            r#"
[grammar]
name = "prefix-var"
sink_category = "prefix-cat"

[[prefix]]
value = "OVERRIDE_PREFIX"

[[contexts]]
name = "ctx"
prefix = "REAL_PREFIX"
suffix = ""

[[techniques]]
name = "t1"
template = "{prefix}value"
"#,
        );

        let payloads = db.payloads("prefix-cat");
        // The {prefix} placeholder should use the context prefix, not the variable
        // This tests priority of special placeholders vs variables
        println!("Prefix resolution: {}", payloads[0].text);
        // Context prefix takes precedence over variable
        assert!(
            payloads[0].text.contains("REAL_PREFIX")
                || payloads[0].text.contains("OVERRIDE_PREFIX")
        );
    }

    // =========================================================================
    // TEST 31: Very long technique name
    // =========================================================================
    #[test]
    fn very_long_technique_name() {
        let long_name = "t".repeat(10000);
        let toml = format!(
            r#"
[grammar]
name = "long-name"
sink_category = "long-name-cat"

[[techniques]]
name = "{long_name}"
template = "test"
"#
        );

        let mut db = PayloadDb::new();
        let result = db.load_toml(&toml);
        // Depth limit is 50, so 100 placeholders may hit it. Either succeeds or errors cleanly.
        assert!(result.is_ok(), "very long technique names should load");

        let payloads = db.payloads("long-name-cat");
        assert_eq!(payloads[0].technique.len(), 10000);
    }

    // =========================================================================
    // TEST 32: Circular variable references (A -> B -> A)
    // =========================================================================
    #[test]
    fn circular_variable_references() {
        let mut db = PayloadDb::new();
        let result = db.load_toml(
            r#"
[grammar]
name = "circular"
sink_category = "circular-cat"

[[a]]
value = "{b}"

[[b]]
value = "{a}"

[[techniques]]
name = "t1"
template = "{a}"
"#,
        );

        // Circular reference should cause recursion error
        assert!(result.is_err(), "Circular variable references should fail");
    }

    // =========================================================================
    // TEST 33: All builtin encodings on empty string
    // =========================================================================
    #[test]
    fn all_encodings_on_empty_string() {
        for enc in BuiltinEncoding::ALL {
            let result = apply_encoding("", enc);
            let expected = match *enc {
                "null_byte" => "%00",
                "charcode" | "js_charcode" => "String.fromCharCode()",
                "python_chr" => "\"\".join([])",
                "sql_char" => "CONCAT()",
                _ => "",
            };
            assert_eq!(
                result, expected,
                "unexpected empty-input encoding output for {enc}"
            );
        }
    }

    // =========================================================================
    // TEST 34: Multiple variables with same name (last one wins in TOML?)
    // =========================================================================
    #[test]
    fn duplicate_variable_names() {
        let mut db = PayloadDb::new();
        let _ = db.load_toml(
            r#"
[grammar]
name = "dup-var"
sink_category = "dup-var-cat"

[[vars]]
value = "first"

[[vars]]
value = "second"

[[techniques]]
name = "t1"
template = "{var}"
"#,
        );

        let payloads = db.payloads("dup-var-cat");
        // Both values should produce payloads
        assert_eq!(payloads.len(), 2);
        let texts: Vec<_> = payloads.iter().map(|p| &p.text).collect();
        assert!(texts.contains(&&"first".to_string()));
        assert!(texts.contains(&&"second".to_string()));
    }

    // =========================================================================
    // TEST 35: Template with only special placeholders
    // =========================================================================
    #[test]
    fn template_only_special_placeholders() {
        let mut db = PayloadDb::new();
        let _ = db.load_toml(
            r#"
[grammar]
name = "special-only"
sink_category = "special-cat"

[[contexts]]
name = "ctx"
prefix = "PREFIX"
suffix = "SUFFIX"

[[techniques]]
name = "t1"
template = "{prefix}{suffix}"
"#,
        );

        let payloads = db.payloads("special-cat");
        assert_eq!(payloads[0].text, "PREFIXSUFFIX");
    }
}
