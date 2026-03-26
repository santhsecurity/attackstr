//! Payload mutation helpers for lightweight evasive variants.

use std::collections::HashSet;

use crate::encoding::apply_encoding;

/// Generate case-mutated variants of a payload.
#[must_use]
pub fn mutate_case(payload: &str) -> Vec<String> {
    collect_unique([
        payload.to_lowercase(),
        payload.to_uppercase(),
        alternate_case(payload, 0),
        alternate_case(payload, 1),
    ])
}

/// Generate whitespace and comment-split variants of a payload.
#[must_use]
pub fn mutate_whitespace(payload: &str) -> Vec<String> {
    let parts: Vec<&str> = payload.split_whitespace().collect();
    if parts.len() >= 2 {
        return collect_unique([
            parts.join("\t"),
            parts.join("\n"),
            parts.join("/**/"),
            parts.join("/*comment*/"),
        ]);
    }

    let chars: Vec<char> = payload.chars().collect();
    if chars.len() < 2 {
        return Vec::new();
    }

    let split = chars.len() / 2;
    let left: String = chars[..split].iter().collect();
    let right: String = chars[split..].iter().collect();

    collect_unique([
        format!("{left}\t{right}"),
        format!("{left}\n{right}"),
        format!("{left}/**/{right}"),
        format!("{left}/*comment*/{right}"),
    ])
}

/// Generate mixed-encoding variants by applying different transforms to payload segments.
#[must_use]
pub fn mutate_encoding_mix(payload: &str, encodings: &[&str]) -> Vec<String> {
    if encodings.len() < 2 || payload.len() < 2 {
        return Vec::new();
    }

    let split_at = payload
        .char_indices()
        .nth(payload.chars().count() / 2)
        .map_or(payload.len(), |(idx, _)| idx);
    let (left, right) = payload.split_at(split_at);

    let mut variants = Vec::new();
    for left_encoding in encodings {
        for right_encoding in encodings {
            if left_encoding == right_encoding {
                continue;
            }
            variants.push(format!(
                "{}{}",
                apply_encoding(left, left_encoding),
                apply_encoding(right, right_encoding)
            ));
        }
    }

    collect_unique(variants)
}

/// Insert null bytes at various positions.
#[must_use]
pub fn mutate_null_bytes(payload: &str) -> Vec<String> {
    if payload.is_empty() {
        return Vec::new();
    }
    let chars: Vec<char> = payload.chars().collect();
    if chars.len() < 3 {
        return collect_unique([
            format!("%00{payload}"),
            format!("{payload}%00"),
            format!("\x00{payload}"),
            format!("{payload}\x00"),
        ]);
    }
    let mid = chars.len() / 2;
    let left: String = chars[..mid].iter().collect();
    let right: String = chars[mid..].iter().collect();

    collect_unique([
        format!("%00{payload}"),
        format!("{payload}%00"),
        format!("{left}%00{right}"),
        format!("\x00{payload}"),
        format!("{payload}\x00"),
        format!("{left}\x00{right}"),
    ])
}

/// Generate SQL-specific comment variants for WAF bypass.
#[must_use]
pub fn mutate_sql_comments(payload: &str) -> Vec<String> {
    let parts: Vec<&str> = payload.split_whitespace().collect();
    if parts.len() < 2 {
        return Vec::new();
    }
    collect_unique([
        parts.join("/**/"),
        parts.join("/*!*/"),
        parts.join("/*! */"),
        parts.join("/**_**/"),
        parts.join("--\n"),
        parts.join("#\n"),
    ])
}

/// Generate HTML/JS-specific evasion variants.
#[must_use]
pub fn mutate_html(payload: &str) -> Vec<String> {
    let mut variants = Vec::new();

    // Tag case variants.
    if payload.contains('<') {
        let lower = payload.to_lowercase();
        let upper = payload.to_uppercase();
        if lower != payload {
            variants.push(lower);
        }
        if upper != payload {
            variants.push(upper);
        }
    }

    // Attribute quote variants.
    if payload.contains('"') {
        variants.push(payload.replace('"', "'"));
        variants.push(payload.replace('"', "`"));
        variants.push(payload.replace('"', ""));
    }

    // Event handler space injection.
    if payload.contains('=') {
        variants.push(payload.replace('=', " = "));
        variants.push(payload.replace('=', "\t=\t"));
    }

    // Forward slash insertion in tags.
    if payload.contains("<script") {
        variants.push(payload.replace("<script", "<script/"));
        variants.push(payload.replace("<script", "<ScRiPt"));
    }
    if payload.contains("<img") {
        variants.push(payload.replace("<img", "<img/"));
        variants.push(payload.replace("<img", "<IMG"));
    }

    collect_unique(variants)
}

/// Generate unicode normalization bypass variants.
#[must_use]
pub fn mutate_unicode(payload: &str) -> Vec<String> {
    let mut variants = Vec::new();
    // Fullwidth character substitution (A → Ａ, < → ＜).
    let fullwidth: String = payload
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c.is_ascii_punctuation() {
                (c as u32)
                    .checked_add(0xFEE0)
                    .and_then(char::from_u32)
                    .unwrap_or(c)
            } else {
                c
            }
        })
        .collect();
    if fullwidth != payload {
        variants.push(fullwidth);
    }

    // Homoglyph substitution (a → а cyrillic, o → ο greek).
    let homoglyph: String = payload
        .chars()
        .map(|c| match c {
            'a' => '\u{0430}', // cyrillic а
            'e' => '\u{0435}', // cyrillic е
            'o' => '\u{03BF}', // greek ο
            'p' => '\u{0440}', // cyrillic р
            'c' => '\u{0441}', // cyrillic с
            'x' => '\u{0445}', // cyrillic х
            _ => c,
        })
        .collect();
    if homoglyph != payload {
        variants.push(homoglyph);
    }

    collect_unique(variants)
}

/// Combine all built-in mutations into a deduplicated set.
#[must_use]
pub fn mutate_all(payload: &str) -> Vec<String> {
    let mut variants = Vec::new();
    variants.extend(mutate_case(payload));
    variants.extend(mutate_whitespace(payload));
    variants.extend(mutate_encoding_mix(
        payload,
        &["url_encode", "html_entities", "unicode"],
    ));
    variants.extend(mutate_null_bytes(payload));
    variants.extend(mutate_sql_comments(payload));
    variants.extend(mutate_html(payload));
    variants.extend(mutate_unicode(payload));
    collect_unique(variants)
}

fn alternate_case(payload: &str, offset: usize) -> String {
    payload
        .chars()
        .enumerate()
        .map(|(idx, ch)| {
            if !ch.is_ascii_alphabetic() {
                return ch.to_string();
            }

            if (idx + offset) % 2 == 0 {
                ch.to_ascii_lowercase().to_string()
            } else {
                ch.to_ascii_uppercase().to_string()
            }
        })
        .collect()
}

fn collect_unique<I>(variants: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut seen = HashSet::new();
    variants
        .into_iter()
        .filter(|variant| seen.insert(variant.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_mutations_are_generated() {
        let variants = mutate_case("ScRiPt");
        assert!(variants.contains(&"script".to_string()));
        assert!(variants.contains(&"SCRIPT".to_string()));
        assert!(variants.contains(&"sCrIpT".to_string()));
        assert!(variants.contains(&"ScRiPt".to_string()));
    }

    #[test]
    fn whitespace_mutations_are_generated() {
        let variants = mutate_whitespace("UNION SELECT");
        assert!(variants.contains(&"UNION\tSELECT".to_string()));
        assert!(variants.contains(&"UNION\nSELECT".to_string()));
        assert!(variants.contains(&"UNION/**/SELECT".to_string()));
    }

    #[test]
    fn encoding_mix_mutations_are_generated() {
        let variants = mutate_encoding_mix("alert(1)", &["url_encode", "unicode"]);
        assert!(!variants.is_empty());
        assert!(variants.iter().any(|variant| variant.contains('%')));
        assert!(variants.iter().any(|variant| variant.contains("\\u")));
    }

    #[test]
    fn all_mutations_combine_strategies() {
        let variants = mutate_all("UNION SELECT");
        assert!(variants.iter().any(|variant| variant.contains("/**/")));
        assert!(variants.iter().any(|variant| variant.contains('%')));
        assert!(variants.iter().any(|variant| variant != "UNION SELECT"));
    }

    #[test]
    fn null_byte_mutations() {
        let variants = mutate_null_bytes("test");
        assert!(variants.iter().any(|v| v.starts_with("%00")));
        assert!(variants.iter().any(|v| v.ends_with("%00")));
        assert!(variants
            .iter()
            .any(|v| v.contains("%00") && !v.starts_with("%00") && !v.ends_with("%00")));
    }

    #[test]
    fn null_byte_empty_input() {
        assert!(mutate_null_bytes("").is_empty());
    }

    #[test]
    fn null_byte_short_inputs_only_use_prefix_and_suffix_variants() {
        let variants = mutate_null_bytes("x");
        assert_eq!(variants.len(), 4);
        assert!(variants.iter().any(|v| v == "%00x"));
        assert!(variants.iter().any(|v| v == "x%00"));
        assert!(variants.iter().any(|v| v == "x\x00"));
        assert!(variants.iter().any(|v| v == "\x00x"));
    }

    #[test]
    fn sql_comment_mutations() {
        let variants = mutate_sql_comments("UNION SELECT 1");
        assert!(variants.iter().any(|v| v.contains("/**/")));
        assert!(variants.iter().any(|v| v.contains("/*!*/")));
        assert!(variants.iter().any(|v| v.contains("--\n")));
        assert!(variants.iter().any(|v| v.contains("#\n")));
    }

    #[test]
    fn sql_comment_single_word_returns_empty() {
        assert!(mutate_sql_comments("SELECT").is_empty());
    }

    #[test]
    fn html_mutations_tag_case() {
        let variants = mutate_html("<script>alert(1)</script>");
        assert!(variants.iter().any(|v| v.contains("<SCRIPT")));
        assert!(variants.iter().any(|v| v.contains("<ScRiPt")));
        assert!(variants.iter().any(|v| v.contains("<script/")));
    }

    #[test]
    fn html_mutations_quote_variants() {
        let variants = mutate_html("onload=\"alert(1)\"");
        assert!(variants.iter().any(|v| v.contains('\'')));
        assert!(variants.iter().any(|v| v.contains('`')));
    }

    #[test]
    fn html_mutations_no_tags_returns_fewer() {
        let variants = mutate_html("plain text");
        // No tags, no quotes, no equals — should produce nothing.
        assert!(variants.is_empty());
    }

    #[test]
    fn unicode_fullwidth_mutation() {
        let variants = mutate_unicode("alert");
        assert!(!variants.is_empty());
        // Fullwidth 'a' is U+FF41.
        assert!(variants.iter().any(|v| v.contains('\u{FF41}')));
    }

    #[test]
    fn unicode_homoglyph_mutation() {
        let variants = mutate_unicode("exec");
        assert!(!variants.is_empty());
        // Cyrillic 'е' (U+0435) replaces 'e'.
        assert!(variants.iter().any(|v| v.contains('\u{0435}')));
    }

    #[test]
    fn unicode_no_substitutable_chars() {
        let variants = mutate_unicode("123");
        // Fullwidth digits exist, so we should get a variant.
        assert!(!variants.is_empty());
    }

    #[test]
    fn unicode_high_codepoint_does_not_overflow() {
        let variants = mutate_unicode("\u{10ffff}");
        assert!(variants.is_empty());
    }

    #[test]
    fn mutate_all_includes_new_strategies() {
        let variants = mutate_all("UNION SELECT 1");
        // Should include SQL comments.
        assert!(variants.iter().any(|v| v.contains("/*!*/")));
        // Should include null bytes.
        assert!(variants.iter().any(|v| v.contains("%00")));
    }

    #[test]
    fn mutate_all_deduplicates() {
        let variants = mutate_all("test");
        let unique: std::collections::HashSet<&String> = variants.iter().collect();
        assert_eq!(
            variants.len(),
            unique.len(),
            "mutate_all produced duplicates"
        );
    }

    #[test]
    fn case_mutation_preserves_non_alpha() {
        let variants = mutate_case("alert(1)");
        for v in &variants {
            assert!(v.contains("(1)"), "non-alpha chars altered in: {v}");
        }
    }

    #[test]
    fn whitespace_mutation_single_char() {
        // Single char = too short, should return empty.
        assert!(mutate_whitespace("x").is_empty());
    }

    #[test]
    fn encoding_mix_single_encoding() {
        // Need at least 2 encodings to mix.
        assert!(mutate_encoding_mix("test", &["url_encode"]).is_empty());
    }

    #[test]
    fn encoding_mix_empty_payload() {
        assert!(mutate_encoding_mix("", &["url_encode", "hex"]).is_empty());
    }

    #[test]
    fn encoding_mix_single_char() {
        assert!(mutate_encoding_mix("x", &["url_encode", "hex"]).is_empty());
    }
}
