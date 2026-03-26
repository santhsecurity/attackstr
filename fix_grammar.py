import re
import os

with open("src/grammar.rs", "r") as f:
    content = f.read()

# 1. Add PayloadLimitExceeded to TemplateExpansionError
content = content.replace('    RecursionLimitExceeded {\n        /// Maximum supported nesting depth.\n        max_depth: usize,\n    },', '    RecursionLimitExceeded {\n        /// Maximum supported nesting depth.\n        max_depth: usize,\n    },\n    /// Number of generated payloads exceeded the circuit breaker limit.\n    #[error("grammar generated too many payloads (exceeded {limit})")]\n    PayloadLimitExceeded {\n        /// The limit that was exceeded.\n        limit: usize,\n    },')

# 2. Update expand to handle the Result item
content = content.replace('''    let mut results = Vec::new();
    for payload in iter_expanded(grammar, custom_encodings)? {
        results.push(payload);
    }
    Ok(results)''', '''    let mut results = Vec::new();
    for payload in iter_expanded(grammar, custom_encodings)? {
        results.push(payload?);
    }
    Ok(results)''')

# 3. Add generated_count to GrammarExpansionIter
content = content.replace('''    active_template: Option<String>,
    active_encoding_index: usize,''', '''    active_template: Option<String>,
    active_encoding_index: usize,
    generated_count: usize,''')

content = content.replace('''            active_template: None,
            active_encoding_index: 0,''', '''            active_template: None,
            active_encoding_index: 0,
            generated_count: 0,''')

# 4. Change GrammarExpansionIter Iterator Item to Result<ExpandedPayload, TemplateExpansionError>
content = content.replace('impl Iterator for GrammarExpansionIter<\'_> {\n    type Item = ExpandedPayload;', 'impl Iterator for GrammarExpansionIter<\'_> {\n    type Item = Result<ExpandedPayload, TemplateExpansionError>;')

# Update GrammarExpansionIter next() signature
content = content.replace('''    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(template) = self.active_template.as_ref() {''', '''    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.generated_count >= 1_000_000 {
                return Some(Err(TemplateExpansionError::PayloadLimitExceeded { limit: 1_000_000 }));
            }
            if let Some(template) = self.active_template.as_ref() {''')

content = content.replace('''                    let encoded = apply_encoding_dispatch(
                        template,
                        &encoding.transform,
                        self.custom_encodings,
                    );
                    return Some(ExpandedPayload {''', '''                    let encoded = apply_encoding_dispatch(
                        template,
                        &encoding.transform,
                        self.custom_encodings,
                    );
                    self.generated_count += 1;
                    return Some(Ok(ExpandedPayload {''')

content = content.replace('                    });\n                }\n\n                self.active_template = None;', '                    }));\n                }\n\n                self.active_template = None;')

content = content.replace('''            if let Some(templates) = self.active_templates.as_mut() {
                if let Some(template) = templates.next() {
                    self.active_template = Some(template);
                    continue;
                }
                self.active_templates = None;
            }''', '''            if let Some(templates) = self.active_templates.as_mut() {
                if let Some(template_res) = templates.next() {
                    match template_res {
                        Ok(template) => {
                            self.active_template = Some(template);
                            continue;
                        }
                        Err(e) => return Some(Err(e)),
                    }
                }
                self.active_templates = None;
            }''')

content = content.replace('''            match self.advance_source() {
                Ok(true) => (),
                Ok(false) | Err(_) => return None,
            }''', '''            match self.advance_source() {
                Ok(true) => (),
                Ok(false) => return None,
                Err(e) => return Some(Err(e)),
            }''')

# 5. Remove validate() and change TemplateExpansionIter Item to Result<String, TemplateExpansionError>
content = re.sub(r'    fn validate.*?Ok\(\(\)\)\n    }', '', content, flags=re.DOTALL)
content = content.replace('''        let mut iter = Self {
            lookup,
            stack: vec![TemplateFrame {
                prefix: String::new(),
                remaining: template,
                depth: 0,
            }],
        };
        iter.validate()?;
        Ok(iter)''', '''        Ok(Self {
            lookup,
            stack: vec![TemplateFrame {
                prefix: String::new(),
                remaining: template,
                depth: 0,
            }],
        })''')

content = content.replace('impl Iterator for TemplateExpansionIter {\n    type Item = String;', 'impl Iterator for TemplateExpansionIter {\n    type Item = Result<String, TemplateExpansionError>;')

# Update TemplateExpansionIter next()
content = content.replace('''            let Some(start) = frame.remaining.find('{') else {
                return Some(format!("{}{}", frame.prefix, frame.remaining));
            };
            let rel_end = frame.remaining[start..]
                .find('}')
                .expect("template iterator is validated before iteration");''', '''            if frame.depth > MAX_TEMPLATE_RECURSION_DEPTH {
                return Some(Err(TemplateExpansionError::RecursionLimitExceeded {
                    max_depth: MAX_TEMPLATE_RECURSION_DEPTH,
                }));
            }
            let Some(start) = frame.remaining.find('{') else {
                return Some(Ok(format!("{}{}", frame.prefix, frame.remaining)));
            };
            let Some(rel_end) = frame.remaining[start..].find('}') else {
                return Some(Err(TemplateExpansionError::UnclosedBrace {
                    template: format!("{}{}", frame.prefix, frame.remaining),
                }));
            };''')

# 6. Remove MARKER special casing
content = content.replace('''            } else {
                let literal = if var_name == "MARKER" {
                    "{MARKER}".to_string()
                } else {
                    format!("{{{var_name}}}")
                };
                self.stack.push(TemplateFrame {
                    prefix: format!("{prefix}{literal}"),''', '''            } else {
                let literal = format!("{{{var_name}}}");
                self.stack.push(TemplateFrame {
                    prefix: format!("{prefix}{literal}"),''')

content = content.replace('''    } else if var_name == "MARKER" {
        for expanded_after in expand_template_with_depth(after.to_string(), lookup, depth + 1)? {
            results.push(format!("{before}{{MARKER}}{expanded_after}"));
        }''', '')

# 7. Add Confidence custom deserializer
deser = '''fn deserialize_confidence<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let val = f64::deserialize(deserializer)?;
    if !(0.0..=1.0).contains(&val) || val.is_nan() {
        return Err(serde::de::Error::custom("confidence must be between 0.0 and 1.0"));
    }
    Ok(val)
}

fn default_confidence() -> f64 {'''
content = content.replace('fn default_confidence() -> f64 {', deser)
content = content.replace('    #[serde(default = "default_confidence")]\n    pub confidence: f64,', '    #[serde(default = "default_confidence", deserialize_with = "deserialize_confidence")]\n    pub confidence: f64,')

with open("src/grammar.rs", "w") as f:
    f.write(content)
