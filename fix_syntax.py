import os
import re

def read_file(path):
    with open(path, "r") as f: return f.read()

def write_file(path, content):
    with open(path, "w") as f: f.write(content)

# Fix engine.rs tests
engine_path = "../multimatch/src/engine.rs"
engine = read_file(engine_path)
engine = engine.replace(", usize::MAX)", ")")
write_file(engine_path, engine)

# Fix pattern.rs builder functions
pattern_path = "../multimatch/src/pattern.rs"
pattern = read_file(pattern_path)

# Let's restore and properly rewrite the builder functions
# I will just write a regex that matches the whole function body

def replace_func(name, kind, case_insensitive):
    global pattern
    pattern = re.sub(
        rf"pub fn {name}\(mut self, [a-z]+: (?:&str|impl Into<String>), id: usize\) -> Self \{{[^}}]+\}}\);\n\s+self\n\s+\}}",
        f"""pub fn {name}(mut self, literal: impl Into<String>, id: usize) -> Self {{
        self.patterns.push(PatternDef {{
            id,
            kind: PatternKind::{kind}(literal.into()),
            case_insensitive: {case_insensitive},
        }});
        self
    }}""",
        pattern,
        flags=re.DOTALL
    )

replace_func("add_literal", "Literal", "false")
replace_func("add_literal_ci", "Literal", "true")

def replace_func_regex(name, kind, case_insensitive):
    global pattern
    pattern = re.sub(
        rf"pub fn {name}\(mut self, [a-z]+: (?:&str|impl Into<String>), id: usize\) -> Self \{{[^}}]+\}}\);\n\s+self\n\s+\}}",
        f"""pub fn {name}(mut self, regex: impl Into<String>, id: usize) -> Self {{
        self.patterns.push(PatternDef {{
            id,
            kind: PatternKind::{kind}(regex.into()),
            case_insensitive: {case_insensitive},
        }});
        self
    }}""",
        pattern,
        flags=re.DOTALL
    )
replace_func_regex("add_regex", "Regex", "false")
replace_func_regex("add_regex_ci", "Regex", "true")

write_file(pattern_path, pattern)
print("syntax fixed")
