use attackstr::PayloadDb;
use std::path::PathBuf;

fn main() -> Result<(), attackstr::PayloadError> {
    let root = unique_temp_dir();
    let grammar_dir = root.join("grammars");
    std::fs::create_dir_all(&grammar_dir)?;

    std::fs::write(
        grammar_dir.join("cmdi.toml"),
        r#"
[grammar]
name = "cmdi"
sink_category = "command-injection"

[[techniques]]
name = "ping"
template = "; ping -c 1 {host}"

[[hosts]]
value = "127.0.0.1"

[[hosts]]
value = "localhost"
"#,
    )?;

    std::fs::write(
        root.join("attackstr.toml"),
        &format!(
            r#"
deduplicate = true
grammar_dirs = ["{}"]
"#,
            grammar_dir.display()
        ),
    )?;

    let config_path = root.join("attackstr.toml");
    let (mut db, errors) = PayloadDb::load_config_and_grammars(&config_path)?;
    assert!(errors.is_empty());

    for payload in db.payloads("command-injection") {
        println!("{}", payload.text);
    }

    std::fs::remove_dir_all(&root)?;
    Ok(())
}

fn unique_temp_dir() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "attackstr-example-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    ));
    path
}
