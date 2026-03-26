import os
import re

def read_file(path):
    with open(path, "r") as f: return f.read()

def write_file(path, content):
    with open(path, "w") as f: f.write(content)

pattern_path = "../multimatch/src/pattern.rs"
pattern = read_file(pattern_path)

# Look at the malformed part:
# pub fn add_literal(...) -> Self {
# ...
#        });
#        self
#    });
#        self
#    }

pattern = re.sub(r"        \}\);\n        self\n    \}\);\n        self\n    \}", "        });\n        self\n    }", pattern)

write_file(pattern_path, pattern)
print("syntax fixed")
