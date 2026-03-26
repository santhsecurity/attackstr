import re

with open("src/adversarial_tests.rs", "r") as f:
    content = f.read()

# 1. extreme_template_length_many_placeholders
content = content.replace(
'''        let result = db.load_toml(&toml);
        // 1000 nested placeholders exceeds depth limit (50). This is by design.
        // load_toml returns Ok but expand will hit the limit during payloads().
        let _ = result;

        let payloads = db.payloads("many-cat");
        // May be empty if expansion hit depth limit.
        let _ = payloads;
        // Should contain all expanded values''',
'''        let result = db.load_toml(&toml);
        assert!(result.is_ok(), "loading toml with many vars should succeed");
        let payloads = db.payloads("many-cat");
        assert_eq!(payloads.len(), 0, "should exceed depth limit and return 0 payloads");''')

# 2. variable_named_grammar_reserved
content = content.replace(
'''        // This might fail or succeed unexpectedly - variable 'grammar'
        // shadows the grammar metadata section
        match result {
            Ok(()) => {
                let payloads = db.payloads("reserved-cat");
                // Check if variable expansion works correctly
                // The 'grammar' variable likely doesn't work as expected
                // because it's a reserved table name
                println!("Loaded {} payloads with 'grammar' variable", payloads.len());
                // This reveals that 'grammar' as a variable doesn't work
            }
            Err(e) => {
                println!("Error with reserved word variable: {e:?}");
            }
        }''',
'''        assert!(result.is_ok());
        let payloads = db.payloads("reserved-cat");
        assert_eq!(payloads.len(), 1);
        // Because "grammars" was parsed as a variable! Wait, grammar metadata is [grammar], the variable is [[grammars]] which depluralizes to "grammar".
        assert_eq!(payloads[0].text, "confusing_var");''')

# 3. unicode_variable_names
content = content.replace(
'''        // Unicode variable names might not work correctly
        match result {
            Ok(()) => {
                let payloads = db.payloads("unicode-cat");
                // Unicode variable works!
                // May be empty if expansion hit depth limit.
                let _ = payloads;
                assert_eq!(payloads[0].text, "japanese");
            }
            Err(e) => {
                // Or fails to parse
                println!("Unicode variable error: {e:?}");
            }
        }''',
'''        assert!(result.is_ok());
        let payloads = db.payloads("unicode-cat");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].text, "japanese");''')

# 4. null_bytes_in_payload_content
content = content.replace(
'''        // This should either succeed (if \x00 is treated as literal) or fail cleanly.
        // Either way, no panic.
        let _ = result;''',
'''        assert!(result.is_err());''')

# 5. template_edge_cases
content = content.replace(
'''            let result = db.load_toml(&toml);
            match result {
                Ok(()) => {
                    let payloads = db.payloads("edge-cat");
                    println!(
                        "Template '{}' produced: {:?}",
                        template,
                        payloads.first().map(|p| &p.text)
                    );
                }
                Err(e) => {
                    println!("Template '{template}' error: {e:?}");
                }
            }''',
'''            let result = db.load_toml(&toml);
            assert!(result.is_ok());
            let payloads = db.payloads("edge-cat");
            assert_eq!(payloads.len(), 1);
            assert_eq!(payloads[0].text, _expected_part);''')

# 6. category_with_special_characters
content = content.replace(
'''        // Depth limit is 50, so 100 placeholders may hit it. Either succeeds or errors cleanly.
        let _ = result;
        // Category with slashes
        let payloads = db.payloads("path/to/category");
        // May be empty if expansion hit depth limit.
        let _ = payloads;''',
'''        assert!(result.is_ok());
        let payloads = db.payloads("path/to/category");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].text, "test");''')

# 7. deeply_nested_brace_literals
content = content.replace(
'''        // Depth limit is 50, so 100 placeholders may hit it. Either succeeds or errors cleanly.
        let _ = result;
        let payloads = db.payloads("brace-cat");
        println!(
            "Nested braces result: {:?}",
            payloads.first().map(|p| &p.text)
        );''',
'''        assert!(result.is_ok());
        let payloads = db.payloads("brace-cat");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].text, "{{{{{{{{literal_braces}}}}}}}}");''')

with open("src/adversarial_tests.rs", "w") as f:
    f.write(content)
