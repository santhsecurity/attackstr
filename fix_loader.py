with open("src/loader.rs", "r") as f:
    content = f.read()

content = content.replace(
'''impl Iterator for PayloadIter<'_> {
    type Item = Payload;

    fn next(&mut self) -> Option<Self::Item> {''',
'''impl Iterator for PayloadIter<'_> {
    type Item = Result<Payload, crate::grammar::TemplateExpansionError>;

    fn next(&mut self) -> Option<Self::Item> {''')

content = content.replace(
'''            if let Some(iter) = self.current_iter.as_mut() {
                if let Some(expanded_payload) = iter.next() {
                    let grammar = &self.grammars[self.grammar_index - 1];
                    if self.deduplicate && !self.seen_payloads.insert(expanded_payload.text.clone())
                    {
                        continue;
                    }

                    self.emitted += 1;
                    return Some(payload_from_expanded(
                        self.category,
                        grammar,
                        expanded_payload,
                    ));
                }

                self.current_iter = None;
            }''',
'''            if let Some(iter) = self.current_iter.as_mut() {
                if let Some(res) = iter.next() {
                    match res {
                        Ok(expanded_payload) => {
                            let grammar = &self.grammars[self.grammar_index - 1];
                            if self.deduplicate && !self.seen_payloads.insert(expanded_payload.text.clone())
                            {
                                continue;
                            }

                            self.emitted += 1;
                            return Some(Ok(payload_from_expanded(
                                self.category,
                                grammar,
                                expanded_payload,
                            )));
                        }
                        Err(e) => return Some(Err(e)),
                    }
                }

                self.current_iter = None;
            }''')

content = content.replace(
'''            let grammar = self.grammars.get(self.grammar_index)?;
            self.grammar_index += 1;
            self.current_iter = Some(
                grammar::iter_expanded(grammar, self.custom_encodings)
                    .expect("grammar templates are validated during load"),
            );''',
'''            let grammar = self.grammars.get(self.grammar_index)?;
            self.grammar_index += 1;
            match grammar::iter_expanded(grammar, self.custom_encodings) {
                Ok(iter) => self.current_iter = Some(iter),
                Err(e) => return Some(Err(e)),
            }''')

# Fix expand_category and payload_count
content = content.replace(
'''    fn expand_category(&self, category: &str) -> Vec<Payload> {
        self.iter_payloads(category).collect()
    }''',
'''    fn expand_category(&self, category: &str) -> Vec<Payload> {
        self.iter_payloads(category).filter_map(Result::ok).collect()
    }''')

content = content.replace(
'''    fn payload_count(&self) -> usize {
        // Expand all categories and sum their payloads
        self.grammars
            .keys()
            .map(|cat| self.iter_payloads(cat).count())
            .sum()
    }''',
'''    fn payload_count(&self) -> usize {
        // Expand all categories and sum their payloads
        self.grammars
            .keys()
            .map(|cat| self.iter_payloads(cat).filter(|r| r.is_ok()).count())
            .sum()
    }''')

with open("src/loader.rs", "w") as f:
    f.write(content)
