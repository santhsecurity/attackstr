with open("src/validate.rs", "r") as f:
    content = f.read()

content = content.replace("grammar: meta(", "meta: meta(")

with open("src/validate.rs", "w") as f:
    f.write(content)
