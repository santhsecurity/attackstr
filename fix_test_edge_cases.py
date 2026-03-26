import re

with open("src/adversarial_tests.rs", "r") as f:
    content = f.read()

content = content.replace(
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
        }''',
'''        for (_desc, template) in test_cases {
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
            assert_eq!(payloads[0].text, template);
        }''')

with open("src/adversarial_tests.rs", "w") as f:
    f.write(content)
