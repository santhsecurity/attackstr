import os
import re

def read_file(path):
    with open(path, "r") as f: return f.read()

def write_file(path, content):
    with open(path, "w") as f: f.write(content)

pattern_path = "../multimatch/src/pattern.rs"
pattern = read_file(pattern_path)

# PatternSet struct
pattern = pattern.replace(
    "pub struct PatternSet {\n    engine: MatchEngine,\n    pattern_count: usize,\n}",
    "pub struct PatternSet {\n    engine: MatchEngine,\n    pattern_count: usize,\n    max_matches: usize,\n}"
)

# Remove Scanner trait implementation and move methods to PatternSet
pattern = re.sub(
    r"impl crate::Scanner for PatternSet \{\n    fn scan\(&self, input: &\[u8\]\) -> Vec<crate::MatchResult> \{\n        self\.engine\.scan\(input\)\n    \}\n\n    fn is_match\(&self, input: &\[u8\]\) -> bool \{\n        self\.engine\.is_match\(input\)\n    \}\n\n    fn pattern_count\(&self\) -> usize \{\n        self\.pattern_count\n    \}\n\}",
    """
impl PatternSet {
    pub fn scan(&self, input: &[u8]) -> Vec<crate::MatchResult> {
        self.engine.scan(input, self.max_matches)
    }

    pub fn is_match(&self, input: &[u8]) -> bool {
        self.engine.is_match(input)
    }

    pub fn pattern_count(&self) -> usize {
        self.pattern_count
    }
}
""",
    pattern
)

# Replace crate::Scanner::scan with self.scan in scan_str
pattern = pattern.replace("crate::Scanner::scan(self, input.as_bytes())", "self.scan(input.as_bytes())")

# PatternSetBuilder struct
pattern = pattern.replace(
    "pub struct PatternSetBuilder {\n    patterns: Vec<PatternDef>,\n}",
    "pub struct PatternSetBuilder {\n    patterns: Vec<PatternDef>,\n    max_matches: usize,\n}"
)

# PatternSetBuilder::new
pattern = pattern.replace(
    "    pub fn new() -> Self {\n        Self {\n            patterns: Vec::new(),\n        }\n    }",
    "    pub fn new() -> Self {\n        Self {\n            patterns: Vec::new(),\n            max_matches: usize::MAX,\n        }\n    }\n\n    pub fn max_matches(mut self, max: usize) -> Self {\n        self.max_matches = max;\n        self\n    }"
)

# PatternSetBuilder::build
pattern = pattern.replace(
    "        Ok(PatternSet {\n            engine,\n            pattern_count: count,\n        })",
    "        Ok(PatternSet {\n            engine,\n            pattern_count: count,\n            max_matches: self.max_matches,\n        })"
)

# Builder methods taking impl Into<String>
pattern = re.sub(r"pub fn add_literal\(mut self, literal: &str, id: usize\) -> Self \{.*?\}",
                 "pub fn add_literal(mut self, literal: impl Into<String>, id: usize) -> Self {\n        self.patterns.push(PatternDef {\n            id,\n            kind: PatternKind::Literal(literal.into()),\n            case_insensitive: false,\n        });\n        self\n    }",
                 pattern, flags=re.DOTALL)

pattern = re.sub(r"pub fn add_literal_ci\(mut self, literal: &str, id: usize\) -> Self \{.*?\}",
                 "pub fn add_literal_ci(mut self, literal: impl Into<String>, id: usize) -> Self {\n        self.patterns.push(PatternDef {\n            id,\n            kind: PatternKind::Literal(literal.into()),\n            case_insensitive: true,\n        });\n        self\n    }",
                 pattern, flags=re.DOTALL)

pattern = re.sub(r"pub fn add_regex\(mut self, regex: &str, id: usize\) -> Self \{.*?\}",
                 "pub fn add_regex(mut self, regex: impl Into<String>, id: usize) -> Self {\n        self.patterns.push(PatternDef {\n            id,\n            kind: PatternKind::Regex(regex.into()),\n            case_insensitive: false,\n        });\n        self\n    }",
                 pattern, flags=re.DOTALL)

pattern = re.sub(r"pub fn add_regex_ci\(mut self, regex: &str, id: usize\) -> Self \{.*?\}",
                 "pub fn add_regex_ci(mut self, regex: impl Into<String>, id: usize) -> Self {\n        self.patterns.push(PatternDef {\n            id,\n            kind: PatternKind::Regex(regex.into()),\n            case_insensitive: true,\n        });\n        self\n    }",
                 pattern, flags=re.DOTALL)

# Fix tests
pattern = pattern.replace("use crate::Scanner;", "")
pattern = pattern.replace("let _res = ps.scan_str(\"test\");\n        // Usually matches at every boundary, Aho-Corasick handles empty string depending on configuration.",
                          "let _res = ps.scan_str(\"test\");\n        assert_eq!(_res.len(), 5);")

write_file(pattern_path, pattern)
print("pattern.rs fixed")
