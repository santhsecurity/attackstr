use attackstr::PayloadDb;

fn reverse(value: &str) -> String {
    value.chars().rev().collect()
}

fn main() -> Result<(), attackstr::PayloadError> {
    let mut db = PayloadDb::new();
    db.register_encoding("reverse", reverse);
    db.load_toml(
        r#"
[grammar]
name = "custom-encoding"
sink_category = "xss"

[[techniques]]
name = "basic"
template = "<svg/onload=alert(1)>"

[[encodings]]
name = "reverse"
transform = "reverse"
"#,
    )?;

    for payload in db.iter_payloads("sqli").filter_map(Result::ok) {
        println!("{} [{}]", payload.text, payload.encoding);
    }

    Ok(())
}
