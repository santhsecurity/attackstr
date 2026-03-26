import re

with open("src/adversarial_tests.rs", "r") as f:
    content = f.read()

# 1. extreme_template_length_many_placeholders
content = content.replace(
'''        let result = db.load_toml(&toml);
        assert!(result.is_ok(), "loading toml with many vars should succeed");
        let payloads = db.payloads("many-cat");
        assert_eq!(payloads.len(), 0, "should exceed depth limit and return 0 payloads");''',
'''        let result = db.load_toml(&toml);
        assert!(result.is_err(), "should exceed depth limit and return an error");''')

# 2. unicode_variable_names
content = content.replace(
'''[[日本語]]
value = "japanese"''',
'''[["日本語"]]
value = "japanese"''')

# 3. template_edge_cases
content = content.replace(
'''        for (_expected_part, template) in test_cases {
            let mut db = PayloadDb::new();
            let toml = format!(
                r#"
[grammar]
name = "edge"
sink_category = "edge-cat"

[[techniques]]
name = "t1"
template = "{template}"
"#
            );

            let result = db.load_toml(&toml);
            assert!(result.is_ok());
            let payloads = db.payloads("edge-cat");
            assert_eq!(payloads.len(), 1);
            assert_eq!(payloads[0].text, _expected_part);
        }''',
'''        for (template, expected_part) in test_cases {
            let mut db = PayloadDb::new();
            let toml = format!(
                r#"
[grammar]
name = "edge"
sink_category = "edge-cat"

[[techniques]]
name = "t1"
template = "{template}"
"#
            );

            let result = db.load_toml(&toml);
            assert!(result.is_ok());
            let payloads = db.payloads("edge-cat");
            assert_eq!(payloads.len(), 1);
            assert_eq!(payloads[0].text, expected_part);
        }''')

with open("src/adversarial_tests.rs", "w") as f:
    f.write(content)
