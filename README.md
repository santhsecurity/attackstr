# attackstr

Generate attack strings from TOML grammars. You define contexts, techniques, variables, and encodings in a TOML file. attackstr expands them into every combination and hands you back structured payloads with metadata.

```rust
use attackstr::PayloadDb;

let mut db = PayloadDb::new();
db.load_toml(
    r#"
[grammar]
name = "inline-example"
sink_category = "sql-injection"

[[contexts]]
name = "quoted"
prefix = "'"
suffix = " --"

[[techniques]]
name = "tautology"
template = "{prefix} OR 1=1{suffix}"

[[encodings]]
name = "raw"
transform = "identity"
"#,
)
.unwrap();

for payload in db.payloads("sql-injection") {
    println!("{}", payload.text);
}
```

## Why this exists

Every security scanner needs attack payloads. SQLi, XSS, command injection, SSTI, SSRF. Most tools hardcode them as string arrays. When you want to add a new encoding or context, you edit Rust code and recompile.

attackstr moves payloads into TOML files. Add a new technique by editing a file. No recompilation. The grammar expansion engine handles the combinatorics.

## What you get

- TOML grammar files define contexts, techniques, variables, encodings
- Cartesian expansion: contexts x techniques x variables x encodings
- 19 built-in encodings (URL, hex, unicode, base64, HTML entities, charcode, and more)
- 7 mutation strategies for WAF bypass variants (case, whitespace, null bytes, SQL comments, HTML, unicode normalization)
- Custom encoding registration (bring your own transforms)
- Taint markers for tracking payload flow through targets
- Grammar validation at load time with actionable error messages
- TOML configuration for all settings
- Serde on every type (serialize/deserialize payloads, cache them, send them over the wire)

## Grammar format

```toml
[grammar]
name = "sql-injection"
sink_category = "sql-injection"

[[contexts]]
name = "string-break"
prefix = "';"
suffix = ""

[[techniques]]
name = "union-based"
template = "{prefix} UNION SELECT {column}{suffix}"

[[columns]]
value = "NULL,NULL,NULL"

[[columns]]
value = "1,2,3"

[[encodings]]
name = "raw"
transform = "identity"

[[encodings]]
name = "url"
transform = "url_encode"
```

This grammar produces 4 payloads (2 columns x 1 technique x 2 encodings).

## Configuration

Load settings from TOML:

```toml
max_per_category = 1000
deduplicate = true
marker_prefix = "SLN"
target_runtime = ["php", "node"]
exclude_categories = ["xxe"]
grammar_dirs = ["./grammars", "/usr/share/grammars"]
```

## Mutations

Generate evasion variants from any payload:

```rust
use attackstr::mutate_all;

let variants = mutate_all("UNION SELECT 1,2,3");
// Produces: case alternation, whitespace variants, SQL comment injection,
// null byte insertion, unicode normalization bypasses, mixed encodings
```

## Contributing

Pull requests are welcome. There is no such thing as a perfect crate. If you find a bug, a better API, or just a rough edge, open a PR. We review quickly.

## License

MIT. Copyright 2026 CORUM COLLECTIVE LLC.

[![crates.io](https://img.shields.io/crates/v/attackstr.svg)](https://crates.io/crates/attackstr)
[![docs.rs](https://docs.rs/attackstr/badge.svg)](https://docs.rs/attackstr)
