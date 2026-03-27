//! Encoding transforms — applied to payloads after template expansion.
//!
//! Built-in encodings cover the most common evasion techniques.
//! Custom encodings can be registered via [`PayloadDb::register_encoding`].

use serde::{Deserialize, Serialize};

/// A trait for encoding transforms.
///
/// Implement this trait to create custom encoders that can be used
/// with the attackstr encoding system.
///
/// # Thread Safety
/// This trait does not require `Send` or `Sync`. Thread-safety depends on the
/// concrete implementing type.
///
/// # Example
///
/// ```rust
/// use attackstr::Encoder;
///
/// struct Rot13Encoder;
///
/// impl Encoder for Rot13Encoder {
///     fn encode(&self, input: &str) -> String {
///         input.chars().map(|c| match c {
///             'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
///             'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
///             _ => c,
///         }).collect()
///     }
/// }
///
/// let encoder = Rot13Encoder;
/// assert_eq!(encoder.encode("hello"), "uryyb");
/// ```
pub trait Encoder {
    /// Encode the input string.
    fn encode(&self, input: &str) -> String;
}

impl<F> Encoder for F
where
    F: Fn(&str) -> String,
{
    fn encode(&self, input: &str) -> String {
        self(input)
    }
}

/// A custom encoder that wraps a function pointer.
///
/// This is useful for creating encoders from closures or function pointers
/// without defining a new type.
///
/// # Thread Safety
/// `CustomEncoder` is `Send` and `Sync`.
///
/// # Example
///
/// ```rust
/// use attackstr::{CustomEncoder, Encoder};
///
/// let encoder = CustomEncoder::new(|s: &str| s.chars().rev().collect::<String>());
/// assert_eq!(encoder.encode("hello"), "olleh");
/// ```
#[derive(Clone)]
pub struct CustomEncoder {
    func: fn(&str) -> String,
}

impl CustomEncoder {
    /// Create a new `CustomEncoder` from a function pointer.
    ///
    /// Example:
    /// ```rust
    /// use attackstr::{CustomEncoder, Encoder};
    ///
    /// let encoder = CustomEncoder::new(|value| value.to_uppercase());
    /// assert_eq!(encoder.encode("xss"), "XSS");
    /// ```
    #[must_use]
    pub const fn new(func: fn(&str) -> String) -> Self {
        Self { func }
    }

    /// Apply the encoding to an input string.
    ///
    /// Example:
    /// ```rust
    /// use attackstr::CustomEncoder;
    ///
    /// let encoder = CustomEncoder::new(|value| format!("<{value}>"));
    /// assert_eq!(encoder.encode("a"), "<a>");
    /// ```
    #[must_use]
    pub fn encode(&self, input: &str) -> String {
        (self.func)(input)
    }
}

impl std::fmt::Debug for CustomEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomEncoder").finish_non_exhaustive()
    }
}

impl Default for CustomEncoder {
    fn default() -> Self {
        Self::new(std::string::ToString::to_string)
    }
}

impl std::fmt::Display for CustomEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CustomEncoder(..)")
    }
}

/// Apply a built-in encoding transform by name.
///
/// Unknown transform names emit a one-time warning to stderr and return the
/// input unchanged.
///
/// Example:
/// ```rust
/// use attackstr::apply_encoding;
///
/// assert_eq!(apply_encoding("a b", "url"), "a%20b");
/// ```
#[must_use]
pub fn apply_encoding(s: &str, transform: &str) -> String {
    apply_url_encoding(s, transform)
        .or_else(|| apply_char_encoding(s, transform))
        .or_else(|| apply_format_encoding(s, transform))
        .unwrap_or_else(|| {
            tracing::warn!(
                transform,
                "unknown encoding transform requested; returning input unchanged"
            );
            s.to_string()
        })
}

fn apply_url_encoding(s: &str, transform: &str) -> Option<String> {
    match transform {
        "identity" | "raw" => Some(s.to_string()),
        "url_encode" | "url" => Some(urlencoding::encode(s).into_owned()),
        "double_url" => Some(urlencoding::encode(&urlencoding::encode(s)).into_owned()),
        "hex" => Some(percent_hex_encode(s)),
        "unicode" => Some(unicode_escape(s)),
        "html_entities" | "html" => Some(html_encode(s)),
        "null_byte" => Some(format!("{s}%00")),
        "base64" => Some(base64_encode(s)),
        "octal" => Some(octal_escape(s)),
        _ => None,
    }
}

fn apply_char_encoding(s: &str, transform: &str) -> Option<String> {
    match transform {
        "charcode" | "js_charcode" => Some(js_charcode(s)),
        "concat_split" | "js_concat" => Some(js_concat_split(s)),
        "case_alternate" => Some(alternate_case(s)),
        "tab_split" => Some(join_chars_with(s, "\t")),
        "newline_split" => Some(join_chars_with(s, "\n")),
        _ => None,
    }
}

fn apply_format_encoding(s: &str, transform: &str) -> Option<String> {
    match transform {
        "php_chr" => Some(php_chr_concat(s)),
        "python_chr" => Some(python_chr_join(s)),
        "sql_char" => Some(sql_char_concat(s)),
        "css_escape" => Some(css_escape(s)),
        _ => None,
    }
}

fn percent_hex_encode(s: &str) -> String {
    s.bytes()
        .fold(String::with_capacity(s.len() * 3), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(&mut acc, "%{b:02x}");
            acc
        })
}

fn unicode_escape(s: &str) -> String {
    s.chars()
        .fold(String::with_capacity(s.len() * 6), |mut acc, c| {
            use std::fmt::Write;
            let _ = write!(&mut acc, "\\u{:04x}", c as u32);
            acc
        })
}

fn octal_escape(s: &str) -> String {
    s.bytes()
        .fold(String::with_capacity(s.len() * 4), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(&mut acc, "\\{b:03o}");
            acc
        })
}

fn js_charcode(s: &str) -> String {
    let codes: Vec<String> = s.chars().map(|c| (c as u32).to_string()).collect();
    format!("String.fromCharCode({})", codes.join(","))
}

fn js_concat_split(s: &str) -> String {
    let parts: Vec<String> = s.chars().map(|c| format!("'{c}'")).collect();
    parts.join("+")
}

fn alternate_case(s: &str) -> String {
    s.chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_lowercase().to_string()
            } else {
                c.to_uppercase().to_string()
            }
        })
        .collect()
}

fn join_chars_with(s: &str, separator: &str) -> String {
    s.chars()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(separator)
}

fn php_chr_concat(s: &str) -> String {
    let parts: Vec<String> = s.bytes().map(|b| format!("chr({b})")).collect();
    parts.join(".")
}

fn python_chr_join(s: &str) -> String {
    let parts: Vec<String> = s.chars().map(|c| format!("chr({})", c as u32)).collect();
    format!("\"\".join([{}])", parts.join(","))
}

fn sql_char_concat(s: &str) -> String {
    let parts: Vec<String> = s.bytes().map(|b| format!("CHAR({b})")).collect();
    format!("CONCAT({})", parts.join(","))
}

fn css_escape(s: &str) -> String {
    s.chars()
        .fold(String::with_capacity(s.len() * 6), |mut acc, c| {
            use std::fmt::Write;
            let _ = write!(&mut acc, "\\{:02x}", c as u32);
            acc
        })
}

/// All built-in encoding names, for documentation and validation.
///
/// # Thread Safety
/// `BuiltinEncoding` is `Send` and `Sync`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum BuiltinEncoding {
    /// No encoding.
    Identity,
    /// URL percent-encoding.
    UrlEncode,
    /// Double URL encoding.
    DoubleUrl,
    /// Hex percent-encoding.
    Hex,
    /// Unicode \uXXXX escapes.
    Unicode,
    /// HTML entity encoding.
    HtmlEntities,
    /// Append null byte.
    NullByte,
    /// Base64 encoding.
    Base64,
    /// Octal \NNN escapes.
    Octal,
    /// JavaScript `String.fromCharCode()`.
    JsCharCode,
    /// JavaScript string concatenation.
    JsConcat,
    /// Alternating case.
    CaseAlternate,
    /// Tab-separated characters.
    TabSplit,
    /// Newline-separated characters.
    NewlineSplit,
    /// PHP `chr()` concatenation.
    PhpChr,
    /// Python `chr()` concatenation.
    PythonChr,
    /// SQL `CHAR()` function.
    SqlChar,
    /// CSS unicode escapes.
    CssEscape,
}

impl std::fmt::Display for BuiltinEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Identity => "identity",
            Self::UrlEncode => "url_encode",
            Self::DoubleUrl => "double_url",
            Self::Hex => "hex",
            Self::Unicode => "unicode",
            Self::HtmlEntities => "html_entities",
            Self::NullByte => "null_byte",
            Self::Base64 => "base64",
            Self::Octal => "octal",
            Self::JsCharCode => "js_charcode",
            Self::JsConcat => "js_concat",
            Self::CaseAlternate => "case_alternate",
            Self::TabSplit => "tab_split",
            Self::NewlineSplit => "newline_split",
            Self::PhpChr => "php_chr",
            Self::PythonChr => "python_chr",
            Self::SqlChar => "sql_char",
            Self::CssEscape => "css_escape",
        };
        f.write_str(value)
    }
}

impl BuiltinEncoding {
    /// All builtin encoding names as strings.
    pub const ALL: &'static [&'static str] = &[
        "identity",
        "raw",
        "url_encode",
        "url",
        "double_url",
        "hex",
        "unicode",
        "html_entities",
        "html",
        "null_byte",
        "base64",
        "octal",
        "charcode",
        "js_charcode",
        "concat_split",
        "js_concat",
        "case_alternate",
        "tab_split",
        "newline_split",
        "php_chr",
        "python_chr",
        "sql_char",
        "css_escape",
    ];
}

fn html_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn base64_encode(s: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            out.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    struct BufferWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for SharedBuffer {
        type Writer = BufferWriter;

        fn make_writer(&'a self) -> Self::Writer {
            BufferWriter(Arc::clone(&self.0))
        }
    }

    impl Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn capture_logs<F>(f: F) -> String
    where
        F: FnOnce(),
    {
        let buffer = SharedBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(buffer.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, f);

        let captured = buffer.0.lock().unwrap().clone();
        String::from_utf8(captured).unwrap()
    }

    #[test]
    fn identity_passthrough() {
        assert_eq!(apply_encoding("test<>&\"'", "identity"), "test<>&\"'");
        assert_eq!(apply_encoding("test<>&\"'", "raw"), "test<>&\"'");
    }

    #[test]
    fn url_encoding() {
        assert_eq!(apply_encoding("a b", "url_encode"), "a%20b");
        assert_eq!(apply_encoding("a b", "url"), "a%20b");
    }

    #[test]
    fn double_url() {
        assert_eq!(apply_encoding("a b", "double_url"), "a%2520b");
    }

    #[test]
    fn hex_encoding() {
        assert_eq!(apply_encoding("AB", "hex"), "%41%42");
    }

    #[test]
    fn unicode_encoding() {
        assert_eq!(apply_encoding("AB", "unicode"), "\\u0041\\u0042");
    }

    #[test]
    fn html_entities() {
        assert_eq!(
            apply_encoding("<script>alert('xss')</script>", "html_entities"),
            "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
        );
    }

    #[test]
    fn null_byte() {
        assert_eq!(apply_encoding("test", "null_byte"), "test%00");
    }

    #[test]
    fn base64() {
        assert_eq!(apply_encoding("hello", "base64"), "aGVsbG8=");
        assert_eq!(apply_encoding("AB", "base64"), "QUI=");
        assert_eq!(apply_encoding("ABC", "base64"), "QUJD");
    }

    #[test]
    fn charcode() {
        assert_eq!(
            apply_encoding("AB", "charcode"),
            "String.fromCharCode(65,66)"
        );
    }

    #[test]
    fn concat_split() {
        assert_eq!(apply_encoding("AB", "concat_split"), "'A'+'B'");
    }

    #[test]
    fn case_alternate() {
        assert_eq!(apply_encoding("script", "case_alternate"), "sCrIpT");
    }

    #[test]
    fn php_chr() {
        assert_eq!(apply_encoding("AB", "php_chr"), "chr(65).chr(66)");
    }

    #[test]
    fn python_chr() {
        assert_eq!(
            apply_encoding("AB", "python_chr"),
            "\"\".join([chr(65),chr(66)])"
        );
    }

    #[test]
    fn sql_char() {
        assert_eq!(
            apply_encoding("AB", "sql_char"),
            "CONCAT(CHAR(65),CHAR(66))"
        );
    }

    #[test]
    fn unknown_passthrough() {
        assert_eq!(apply_encoding("test", "unknown_enc"), "test");
    }

    #[test]
    fn unknown_encoding_emits_warning() {
        let logs = capture_logs(|| {
            assert_eq!(apply_encoding("test", "unknown_enc"), "test");
        });

        assert!(logs.contains("unknown encoding transform requested"));
        assert!(logs.contains("unknown_enc"));
    }

    #[test]
    fn all_builtins_listed() {
        // Verify ALL list has no empties.
        for name in BuiltinEncoding::ALL {
            assert!(!name.is_empty());
        }
        assert!(BuiltinEncoding::ALL.len() >= 18);
    }
}

#[cfg(test)]
mod roundtrip_tests {
    use super::*;

    #[test]
    fn url_encode_preserves_alphanumeric() {
        let input = "abcdefghijklmnopqrstuvwxyz0123456789";
        let encoded = apply_encoding(input, "url_encode");
        assert_eq!(
            encoded, input,
            "alphanumeric should pass through URL encoding"
        );
    }

    #[test]
    fn url_encode_encodes_special_chars() {
        assert!(apply_encoding("<script>", "url_encode").contains("%3C"));
        assert!(apply_encoding(" ", "url_encode").contains("%20"));
        assert!(apply_encoding("'", "url_encode").contains("%27"));
    }

    #[test]
    fn double_url_differs_from_single() {
        let input = "hello world";
        let single = apply_encoding(input, "url_encode");
        let double = apply_encoding(input, "double_url");
        assert_ne!(single, double);
        assert!(
            double.contains("%25"),
            "double URL should encode the % itself"
        );
    }

    #[test]
    fn hex_produces_percent_encoded_bytes() {
        let encoded = apply_encoding("A", "hex");
        assert_eq!(encoded, "%41");
    }

    #[test]
    fn unicode_produces_backslash_u() {
        let encoded = apply_encoding("A", "unicode");
        assert_eq!(encoded, "\\u0041");
    }

    #[test]
    fn base64_known_vectors() {
        assert_eq!(apply_encoding("", "base64"), "");
        assert_eq!(apply_encoding("f", "base64"), "Zg==");
        assert_eq!(apply_encoding("fo", "base64"), "Zm8=");
        assert_eq!(apply_encoding("foo", "base64"), "Zm9v");
        assert_eq!(apply_encoding("foob", "base64"), "Zm9vYg==");
        assert_eq!(apply_encoding("fooba", "base64"), "Zm9vYmE=");
        assert_eq!(apply_encoding("foobar", "base64"), "Zm9vYmFy");
    }

    #[test]
    fn html_entities_escapes_all_dangerous() {
        let encoded = apply_encoding("<>&\"'", "html_entities");
        assert!(!encoded.contains('<'));
        assert!(!encoded.contains('>'));
        assert_eq!(encoded, "&lt;&gt;&amp;&quot;&#39;");
        assert!(!encoded.contains('"') || encoded.contains("&quot;"));
    }

    #[test]
    fn null_byte_appends() {
        assert!(apply_encoding("test", "null_byte").ends_with("%00"));
    }

    #[test]
    fn charcode_produces_fromcharcode() {
        let encoded = apply_encoding("a", "charcode");
        assert_eq!(encoded, "String.fromCharCode(97)");
    }

    #[test]
    fn sql_char_produces_concat() {
        let encoded = apply_encoding("A", "sql_char");
        assert_eq!(encoded, "CONCAT(CHAR(65))");
    }

    #[test]
    fn empty_input_all_encodings() {
        for name in BuiltinEncoding::ALL {
            let result = apply_encoding("", name);
            assert!(
                result.is_empty() || !result.is_empty(),
                "encoding {name} should return a concrete string for empty input"
            );
        }
    }

    #[test]
    fn unicode_input_all_encodings() {
        for name in BuiltinEncoding::ALL {
            let result = apply_encoding("日本語テスト", name);
            assert!(
                !result.is_empty(),
                "encoding {name} should preserve a concrete unicode output"
            );
        }
    }

    #[test]
    fn very_long_input() {
        let long = "A".repeat(10_000);
        for name in &["identity", "url_encode", "hex", "base64"] {
            let result = apply_encoding(&long, name);
            assert!(!result.is_empty());
        }
    }
}
