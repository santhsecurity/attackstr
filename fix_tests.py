import re

with open("src/adversarial_tests.rs", "r") as f:
    content = f.read()

# Fix invalid_confidence_values
content = content.replace(
'''    fn invalid_confidence_values() {
        let mut db = PayloadDb::new();
        let _ = db.load_toml(
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

        let payloads = db.payloads("conf-cat");
        // Engine accepts any f64, validation should catch this
        // First clone the payloads to avoid borrow issues
        let payload_count = payloads.len();
        for p in payloads {
            println!("Technique {} has confidence {}", p.technique, p.confidence);
        }

        let issues = validate(&get_first_grammar(&db));
        let bad_conf = issues.iter().any(|i| i.message.contains("confidence"));
        assert!(
            bad_conf,
            "Validation should catch invalid confidence values"
        );

        assert_eq!(payload_count, 2);
    }''',
'''    fn invalid_confidence_values() {
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
        assert!(result.is_err(), "Loading should fail due to invalid confidence");
    }''')

with open("src/adversarial_tests.rs", "w") as f:
    f.write(content)
