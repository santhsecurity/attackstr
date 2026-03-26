import re

with open("src/adversarial_tests.rs", "r") as f:
    content = f.read()

content = content.replace(
'''            if template.contains('{') && !template[template.find('{')..].contains('}') {''',
'''            if template.contains('{') && !template[template.find('{').unwrap()..].contains('}') {''')

with open("src/adversarial_tests.rs", "w") as f:
    f.write(content)
