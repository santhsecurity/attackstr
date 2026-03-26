use attackstr::{mutate_all, PayloadConfig, PayloadDb};

fn main() -> Result<(), attackstr::PayloadError> {
    let mut db = PayloadDb::with_config(
        PayloadConfig::builder()
            .max_per_category(8)
            .deduplicate(true)
            .build(),
    );

    db.load_toml(
        r#"
[grammar]
name = "example-xss"
sink_category = "xss"

[[contexts]]
name = "double-quoted"
prefix = "\""
suffix = "\""

[[techniques]]
name = "svg-onload"
template = "<svg/onload={handler}>"

[[handlers]]
value = "alert(1)"

[[handlers]]
value = "confirm(1)"

[[encodings]]
name = "raw"
transform = "identity"

[[encodings]]
name = "url"
transform = "url_encode"
"#,
    )?;

    for payload in db.iter_payloads("xss").filter_map(Result::ok).take(4) {
        println!(
            "[{}:{}:{}] {}",
            payload.technique, payload.context, payload.encoding, payload.text
        );
    }

    let mutated = mutate_all(&db.payloads("xss")[0].text);
    println!("generated {} evasive variants", mutated.len());

    Ok(())
}
