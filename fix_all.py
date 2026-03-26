import os
import re

def read_file(path):
    with open(path, "r") as f: return f.read()

def write_file(path, content):
    with open(path, "w") as f: f.write(content)

# 1. lib.rs
lib_path = "../multimatch/src/lib.rs"
lib = read_file(lib_path)

lib = re.sub(r"pub trait Scanner \{.*?\n\}", "", lib, flags=re.DOTALL)
lib = re.sub(r"pub use crate::\{from_literals, from_regexes, Scanner\};", "pub use crate::{from_literals, from_regexes};", lib)
lib = re.sub(r"pub use pattern::\{PatternDef, PatternKind, PatternSet, PatternSetBuilder\};", "pub use pattern::{PatternDef, PatternKind, PatternSet, PatternSetBuilder};", lib)

lib = re.sub(r"AhoCorasick\(String\)", "AhoCorasick(#[source] aho_corasick::BuildError)", lib)

lib = re.sub(r"pub fn from_pairs.*?\}\n\}\n", "", lib, flags=re.DOTALL)

from_literal_pairs = """
/// Convenience: compile literal pairs.
pub fn from_literal_pairs(pairs: &[(&str, usize)]) -> Result<PatternSet, MatchError> {
    let mut builder = PatternSet::builder();
    for &(pattern, id) in pairs {
        builder = builder.add_literal(pattern, id);
    }
    builder.build()
}

/// Convenience: compile regex pairs.
pub fn from_regexes_pairs(pairs: &[(&str, usize)]) -> Result<PatternSet, MatchError> {
    let mut builder = PatternSet::builder();
    for &(pattern, id) in pairs {
        builder = builder.add_regex(pattern, id);
    }
    builder.build()
}
"""
lib = lib.replace("pub mod prelude", from_literal_pairs + "\npub mod prelude")

lib = re.sub(r"use crate::Scanner;\n", "", lib)
lib = re.sub(r"struct MockScanner;.*?\}\n\}", "", lib, flags=re.DOTALL)
lib = re.sub(r"\#\[test\]\n\s*fn custom_scanner_impl\(\) \{.*?\}\n", "", lib, flags=re.DOTALL)

# In lib.rs comments
lib = lib.replace("use multimatch::{PatternSet, MatchResult, Scanner};", "use multimatch::{PatternSet, MatchResult};")
lib = lib.replace("use multimatch::{from_literals, Scanner};", "use multimatch::{from_literals};")
lib = lib.replace("use multimatch::{from_regexes, Scanner};", "use multimatch::{from_regexes};")
lib = lib.replace("use multimatch::{from_pairs, Scanner};", "use multimatch::{from_literal_pairs};")

write_file(lib_path, lib)

print("lib.rs fixed")
