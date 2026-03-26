import re
import os

def fix_parser_expressions():
    with open('src/parser/expressions.rs', 'r') as f:
        content = f.read()
    
    # 17. Lowercase names during AST construction for expressions
    content = re.sub(
        r'Ok\(Expr::FunctionCall \{\s*name: (.*?),',
        r'Ok(Expr::FunctionCall {\n                name: \1.to_lowercase(),',
        content
    )
    content = re.sub(
        r'Ok\(Expr::MethodCall \{\s*object: (.*?),\s*method: (.*?),',
        r'Ok(Expr::MethodCall {\n                object: \1,\n                method: \2.to_lowercase(),',
        content
    )
    content = re.sub(
        r'Ok\(Expr::StaticCall \{\s*class: (.*?),\s*method: (.*?),',
        r'Ok(Expr::StaticCall {\n                class: \1,\n                method: \2.to_lowercase(),',
        content
    )

    with open('src/parser/expressions.rs', 'w') as f:
        f.write(content)

def fix_parser_statements():
    with open('src/parser/statements.rs', 'r') as f:
        content = f.read()

    # 17. Lowercase names during AST construction for statements
    content = re.sub(
        r'Ok\(Statement::FunctionDef \{\s*name: (.*?),',
        r'Ok(Statement::FunctionDef {\n            name: \1.to_lowercase(),',
        content
    )
    content = re.sub(
        r'Ok\(Statement::MethodDef \{\s*name: (.*?),',
        r'Ok(Statement::MethodDef {\n            name: \1.to_lowercase(),',
        content
    )
    content = re.sub(
        r'Ok\(Statement::ClassDef \{\s*name: (.*?),',
        r'Ok(Statement::ClassDef {\n            name: \1.to_lowercase(),',
        content
    )
    
    with open('src/parser/statements.rs', 'w') as f:
        f.write(content)

fix_parser_expressions()
fix_parser_statements()
