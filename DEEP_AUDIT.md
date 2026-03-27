# attackstr Deep Audit

**Date:** 2026-03-26  
**Crate:** attackstr v0.1.1  
**Standard Applied:** Tokio-level production readiness  
**Auditor:** Kimi Code CLI  

---

## Executive Summary

attackstr is a grammar-based security payload generation library with a solid core concept but significant gaps for production use. While the 172 tests pass, the codebase exhibits architectural smells, API ergonomics issues, and missing safety guards that would prevent a Tokio maintainer from merging this in its current state.

**Verdict:** Not production-ready without addressing critical soundness and API design issues.

---

## 1. Functions That Don't Do What Their Name Promises

### 1.1 `apply_encoding()` - The Silent Liar

**Location:** `src/encoding.rs:118`

**Documentation claims:**
```rust
/// Unknown transform names emit a one-time warning to stderr and return the
/// input unchanged.
```

**Actual behavior:**
```rust
pub fn apply_encoding(s: &str, transform: &str) -> String {
    apply_url_encoding(s, transform)
        .or_else(|| apply_char_encoding(s, transform))
        .or_else(|| apply_format_encoding(s, transform))
        .unwrap_or_else(|| s.to_string())  // Silently returns input, NO WARNING
}
```

**Impact:** Users think they'll be notified of typos in encoding names. They won't. Silent failures in security tools lead to unencoded payloads hitting production targets.

**Fix:** Either implement the warning or remove the false documentation.

---

### 1.2 `parse_marker_position()` - Silent Fallback

**Location:** `src/config.rs:139`

```rust
fn parse_marker_position(s: &str) -> MarkerPosition {
    match s {
        "suffix" => MarkerPosition::Suffix,
        "inline" => MarkerPosition::Inline,
        s if s.starts_with("replace:") => MarkerPosition::Replace(s[8..].to_string()),
        _ => MarkerPosition::Prefix,  // SILENT FALLBACK
    }
}
```

A typo like `"sufix"` silently becomes `Prefix`. No error, no warning.

**Fix:** Return `Result<MarkerPosition, InvalidMarkerPosition>` or at least log a warning.

---

### 1.3 `alternate_case()` - Two Different Implementations

**Location:** `src/encoding.rs:198` and `src/mutate.rs:226`

These two functions with the same name produce DIFFERENT outputs:

```rust
// encoding.rs - operates on ALL chars
fn alternate_case(s: &str) -> String {
    s.chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 { c.to_lowercase().to_string() }
            else { c.to_uppercase().to_string() }
        })
        .collect()
}

// mutate.rs - only operates on ASCII alphabetic
fn alternate_case(payload: &str, offset: usize) -> String {
    payload
        .chars()
        .enumerate()
        .map(|(idx, ch)| {
            if !ch.is_ascii_alphabetic() {
                return ch.to_string();  // Preserved as-is
            }
            // ... only then applies case
        })
        .collect()
}
```

The encoding version lowercases ALL characters (including non-ASCII), while the mutation version preserves non-ASCII. This is a behavioral inconsistency that will confuse users.

**Fix:** Unify behavior or rename one function.

---

### 1.4 `load_single_grammar_file()` - Double Expansion

**Location:** `src/loader.rs:223`

This function calls `grammar::expand()` during loading just to validate, then discards the result. The payloads are re-expanded later when actually requested. For large grammars, this is 2x the work.

```rust
fn load_single_grammar_file(...) -> Option<Grammar> {
    // ...
    if let Err(source) = grammar::expand(&grammar, &self.custom_encodings) {
        // Error collected, expansion result DISCARDED
        return None;
    }
    // ... later, payloads are expanded AGAIN
    Some(grammar)
}
```

**Fix:** Cache the expansion or use a cheaper validation method.

---

### 1.5 `payload_count()` - The Expensive Counter

**Location:** `src/loader.rs:443`

```rust
fn payload_count(&self) -> usize {
    self.grammars
        .keys()
        .map(|cat| self.iter_payloads(cat).filter(|r| r.is_ok()).count())
        .sum()
}
```

This method name suggests a cheap O(1) operation. It actually re-expands ALL grammars completely - an O(n) operation that can generate millions of payloads just to count them.

**Fix:** Rename to `count_payloads_expensive()` or maintain a cached count.

---

## 2. Panic Sources (Empty, Huge, Null Bytes, Unicode)

### 2.1 Unicode Code Point Overflow

**Location:** `src/mutate.rs:172-179`

```rust
let fullwidth: String = payload
    .chars()
    .map(|c| {
        if c.is_ascii_alphanumeric() || c.is_ascii_punctuation() {
            (c as u32)
                .checked_add(0xFEE0)
                .and_then(char::from_u32)  // Handles overflow gracefully
                .unwrap_or(c)
        } else { c }
    })
    .collect();
```

**Status:** FIXED - Uses `checked_add` and `from_u32`. Test `unicode_high_codepoint_does_not_overflow` passes.

---

### 2.2 Unbounded Input Allocation

**Location:** Multiple encoding functions

```rust
// src/encoding.rs:161
fn percent_hex_encode(s: &str) -> String {
    s.bytes()
        .fold(String::with_capacity(s.len() * 3), |mut acc, b| {  // 3x allocation
            // ...
        })
}
```

A 1GB input string will allocate 3GB. No limits, no streaming.

**Attack vector:**
```rust
let malicious = "A".repeat(1024 * 1024 * 1024);  // 1GB
let encoded = apply_encoding(&malicious, "hex");  // Tries to allocate 3GB
```

**Fix:** Add `max_input_size` configuration with sensible defaults.

---

### 2.3 Template Recursion Limit - Hardcoded and Non-Configurable

**Location:** `src/grammar.rs:190`

```rust
const MAX_TEMPLATE_RECURSION_DEPTH: usize = 50;
```

50 is arbitrary. Users can't tune it. Deeply nested legitimate templates fail.

**Fix:** Make this a `PayloadConfig` option.

---

### 2.4 Payload Count Hard Limit - Silent Truncation

**Location:** `src/grammar.rs:319-324`

```rust
if self.generated_count >= 1_000_000 {
    return Some(Err(TemplateExpansionError::PayloadLimitExceeded {
        limit: 1_000_000,
    }));
}
```

1M is hardcoded. Large grammars silently error instead of streaming.

**Fix:** Make configurable and support streaming for large outputs.

---

### 2.5 Empty Inputs That Cause Unexpected Behavior

| Function | Empty Input Behavior | Issue |
|----------|---------------------|-------|
| `mutate_whitespace("")` | Returns empty vec | Acceptable |
| `mutate_encoding_mix("", ...)` | Returns empty vec | Acceptable |
| `mutate_null_bytes("")` | Returns empty vec | Documented but inconsistent with non-empty |
| `base64_encode("")` | Returns `""` | Correct per RFC |
| `apply_encoding("", "null_byte")` | Returns `"%00"` | **Surprising!** |

The `null_byte` encoding on empty string produces a non-empty result. This may be intentional but should be documented.

---

## 3. Tests That Pass on Broken Code

### 3.1 `unknown_encoding_transform` - Passes on Silent Failure

**Location:** `src/adversarial_tests.rs:906`

```rust
#[test]
fn unknown_encoding_transform() {
    // ... load grammar with transform = "this_does_not_exist"
    let payloads = db.payloads("unknown-enc-cat");
    assert_eq!(payloads[0].text, "test");  // PASS - but should it?
    assert_eq!(payloads[0].encoding, "mystery");
}
```

This test PASSES because the encoding silently returns input unchanged. The user thinks they have an encoded payload. They don't.

**The test should verify:** A warning was emitted OR the encoding was rejected.

---

### 3.2 `variable_value_with_braces` - Passes on Known Bug

**Location:** `src/adversarial_tests.rs:810`

```rust
#[test]
fn variable_value_with_braces() {
    let mut lookup = HashMap::new();
    lookup.insert("var".to_string(), vec!["{nested}".to_string()]);
    let result = grammar::expand_template("{var}".into(), &lookup);
    assert!(result.is_ok(), "...");
    let expanded = result.unwrap();
    // Known limitation: braces in variable values are re-expanded.
    // {nested} becomes empty string because "nested" isn't a known var.
    assert_eq!(expanded.len(), 1);  // PASSES but result is WRONG
}
```

The test documents a known bug and passes anyway. The variable value `{nested}` is incorrectly re-parsed as a placeholder.

**Expected:** `"{nested}"` (literal)  
**Actual:** `""` (empty - placeholder expanded to nothing)

---

### 3.3 `marker_replace_placeholder_not_found` - Passes on Silent No-Op

**Location:** `src/adversarial_tests.rs:759`

```rust
#[test]
fn marker_replace_placeholder_not_found() {
    // ... marker_position = Replace("{NOT_HERE}")
    // ... template = "alert(1)" (no {NOT_HERE} placeholder)
    let marked = db.payloads_with_marker("np-cat", "SLN_123");
    assert_eq!(marked[0].text, "alert(1)");  // PASS - marker not injected!
}
```

The user asked for marker replacement. The placeholder doesn't exist. The marker is silently NOT injected. This is a silent failure.

---

### 3.4 `mutate_all_deduplicates` - Weak Assertion

**Location:** `src/mutate.rs:392`

```rust
#[test]
fn mutate_all_deduplicates() {
    let variants = mutate_all("test");
    let unique: std::collections::HashSet<&String> = variants.iter().collect();
    assert_eq!(variants.len(), unique.len(), "mutate_all produced duplicates");
}
```

This only checks that the output is deduplicated. It doesn't verify that deduplication was NECESSARY. If the mutation functions suddenly stopped producing duplicates (or any output), this test would still pass.

---

## 4. Architecture Issues

### 4.1 God File: `loader.rs` (1353 lines)

`loader.rs` violates single responsibility:
- Directory traversal
- File I/O
- TOML parsing
- Grammar validation
- Payload expansion
- Caching
- Category filtering
- Runtime filtering
- Iterator implementation

**Fix:** Split into:
- `loader/fs.rs` - File system operations
- `loader/cache.rs` - Payload caching
- `loader/filter.rs` - Category/runtime filtering
- Keep only orchestration in `loader.rs`

---

### 4.2 Functions Doing Multiple Things

#### `PayloadDb::load_dir_lenient()`
- Reads directory entries
- Filters by extension
- Sorts for determinism
- Parses each file
- Collects errors
- Applies filters
- Invalidates cache

**Fix:** Use a builder pattern or pipeline:
```rust
GrammarLoader::new(&path)
    .filter_extension("toml")
    .sorted()
    .parse()
    .filter(|g| runtime_filter.matches(g))
    .load_into(&mut db)?;
```

---

### 4.3 Leaky Abstractions

#### `TemplateExpansionIter` exposes internal error type

Users of `iter_payloads()` get `Result<Payload, TemplateExpansionError>`, forcing them to understand internal expansion mechanics.

**Fix:** Map to a user-facing error type.

---

#### `CustomEncoder` uses `fn` pointer (no closures)

```rust
pub struct CustomEncoder {
    func: fn(&str) -> String,  // No closures allowed!
}
```

Users can't capture environment. This forces global state or wrapper structs.

**Fix:** Use `Box<dyn Encoder>` or generic `F: Fn(&str) -> String`.

---

### 4.4 Cache Invalidation Strategy

```rust
pub fn register_encoding(&mut self, name: &str, func: fn(&str) -> String) {
    self.custom_encodings.insert(name.to_string(), func);
    self.cache.clear(); // NUCLEAR OPTION
}
```

Adding one encoding clears ALL cached payloads from ALL grammars. A targeted invalidation would only clear affected categories.

---

### 4.5 Sorting Obsession

```rust
// StaticPayloads::add()
pub fn add(&mut self, payload: Payload) {
    self.payloads.push(payload);
    sort_payloads_by_category(&mut self.payloads);  // O(n log n) per add!
}
```

Adding n payloads is O(n² log n). Should append and sort once at the end.

---

## 5. API Ergonomics

### 5.1 The "3 Lines" Test

**README promises:**
```rust
use attackstr::PayloadDb;

let mut db = PayloadDb::new();
db.load_dir("./grammars").unwrap();

for payload in db.payloads("sql-injection") {
    println!("{}", payload.text);
}
```

**Problems:**
1. `load_dir` returns `Vec<PayloadError>` - users MUST handle this or use `unwrap()`
2. `payloads()` requires `&mut self` - can't use in concurrent contexts
3. No way to check if a category exists before calling `payloads()`
4. No streaming for large categories (everything materialized)

**Tokio-grade version would be:**
```rust
let db = PayloadDb::new().load_dir("./grammars").await?;  // Async

// Non-mutable access
for payload in db.payloads("sql-injection").await {  // Streaming
    println!("{}", payload.text);
}
```

---

### 5.2 Error Quality

**Current:**
```rust
#[derive(Debug, thiserror::Error)]
pub enum PayloadError {
    #[error("{0}. Fix: verify the file...")]
    Io(#[from] std::io::Error),
    // ...
}
```

**Issues:**
- No structured error codes for programmatic handling
- No source location (file/line) in errors
- No error chain (lost if wrapped)
- Deserialization of `PayloadError` is LOSSY - all variants become `Io`

```rust
// This is BROKEN - all errors deserialize to Io variant
impl<'de> Deserialize<'de> for PayloadError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> {
        // ... always returns Io variant
        Ok(Self::Io(std::io::Error::new(...)))
    }
}
```

---

### 5.3 `PayloadSource` Trait Design Flaw

```rust
pub trait PayloadSource {
    fn payloads(&mut self, category: &str) -> &[Payload];  // &mut self ?!
    // ...
}
```

`&mut self` is unnecessary for read-only access. This prevents:
- Concurrent reads
- Sharing between threads
- Using in `Arc<dyn PayloadSource>`

**Fix:** `fn payloads(&self, category: &str) -> Cow<'_, [Payload]>`

---

### 5.4 Mutation API Inconsistencies

```rust
pub fn mutate_all(payload: &str) -> Vec<String>;
pub fn mutate_case(payload: &str) -> Vec<String>;
pub fn mutate_whitespace(payload: &str) -> Vec<String>;
pub fn mutate_encoding_mix(payload: &str, encodings: &[&str]) -> Vec<String>;
```

- `mutate_all` hardcodes encodings (no way to customize)
- `mutate_html` only handles `<script` and `<img` (incomplete)
- No way to compose mutations (chaining is manual)

**Desired:**
```rust
let mutations = MutationPipeline::new()
    .case(CaseStrategy::All)
    .whitespace(WhitespaceStrategy::SqlComments)
    .encoding_mix(&["url", "hex"])
    .apply(payload);
```

---

## 6. What's Missing for Production

### 6.1 Security Essentials

| Feature | Status | Risk |
|---------|--------|------|
| Input size limits | ❌ Missing | DoS via OOM |
| Output size limits | ❌ Missing | DoS via OOM |
| Recursion limit (configurable) | ❌ Hardcoded | Legitimate use blocked |
| Payload rate limiting | ❌ Missing | Accidental DoS |
| Canonicalization validation | ❌ Missing | Encoding bypass |

### 6.2 Async/Concurrency

| Feature | Status | Impact |
|---------|--------|--------|
| Async loading | ❌ Missing | Blocks executor |
| Send + Sync bounds | ❌ Missing | Can't share across tasks |
| Streaming expansion | ❌ Missing | Memory pressure |
| Parallel grammar loading | ❌ Missing | Slow startup |

### 6.3 Observability

```rust
// No hooks for:
- Metrics (payloads_generated, expansion_time_ms)
- Tracing (span per grammar, per expansion)
- Logging (debug expansion steps)
- Health checks (grammar validity)
```

### 6.4 WAF Evasion Intelligence

Current mutations are static. Production needs:
- WAF fingerprint-based mutation selection
- Payload effectiveness feedback
- Automatic mutation strategy evolution
- Context-aware bypass (language, framework)

### 6.5 Grammar Ecosystem

| Feature | Status |
|---------|--------|
| Grammar versioning | ❌ Missing |
| Grammar dependencies | ❌ Missing |
| Grammar marketplace/updates | ❌ Missing |
| Grammar validation schema | ❌ Partial |
| Migration tools | ❌ Missing |

### 6.6 Testing Gaps

- **Fuzzing:** No `cargo fuzz` harness
- **Property testing:** No proptest integration
- **Benchmarks:** No criterion benchmarks
- **Miri:** Not tested for UB
- **Wasm:** Not tested for wasm32 target

---

## 7. Specific Code Smells

### 7.1 `depluralize()` - English-Centric Assumption

```rust
pub(crate) fn depluralize(s: &str) -> String {
    if s.ends_with("ies") && s.len() > 3 {
        format!("{}y", &s[..s.len() - 3])
    } else if s.ends_with('s') && s.len() > 1 {
        s[..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}
```

- `"ss"` → `"s"` (wrong)
- `"child"` → `"chil"` (wrong)
- `"data"` → `"datum"`? No, `"data"`

This is called on user-provided variable names. Non-English grammars will behave unexpectedly.

---

### 7.2 Confidence Validation Duplication

```rust
// grammar.rs:459
deserialize_with = "deserialize_confidence"
// AND
// validate.rs:119
if tech.confidence < 0.0 || tech.confidence > 1.0 { ... }
```

Same validation in two places. One is a deserializer, one is a validator. They can drift.

---

### 7.3 Magic Strings for Placeholders

```rust
// Scattered throughout:
.replace("{prefix}", &ctx.prefix)
.replace("{suffix}", &ctx.suffix)

// Check for special vars:
var_name != "prefix" && var_name != "suffix"
```

No constant definitions. Easy to typo and miss.

---

### 7.4 `legacy_*_payloads()` - Dead Weight

```rust
// src/ports/cmdi.rs
pub fn legacy_cmdi_payloads() -> Vec<&'static str> {
    vec!["; id", "| id", "|| id", "&& id", "$(id)", "`id`", "& id &"]
}
```

7 static strings in a dedicated module. No integration with grammar system. No metadata. Just noise.

---

## 8. Recommendations by Priority

### P0 (Block Release)

1. **Fix `apply_encoding` documentation** - Remove false promise of warnings
2. **Add input size limits** - Prevent OOM DoS
3. **Fix `PayloadError` deserialization** - Currently lossy
4. **Remove or fix `parse_marker_position` silent fallback**

### P1 (High)

5. Make recursion and payload limits configurable
6. Unify `alternate_case` implementations
7. Add `Send + Sync` bounds to custom encodings
8. Reduce `&mut self` requirements in API
9. Add grammar validation at load time (not just expand time)

### P2 (Medium)

10. Split `loader.rs` into smaller modules
11. Add async support
12. Add observability hooks (metrics, tracing)
13. Implement streaming for large outputs
14. Add proper property-based testing

### P3 (Nice to Have)

15. WASM target support
16. `no_std` support
17. Grammar versioning
18. Mutation pipeline builder

---

## 9. Conclusion

attackstr has a solid conceptual foundation but suffers from:

1. **Documentation lies** (`apply_encoding` warnings)
2. **Silent failures** (encoding pass-through, marker replacement)
3. **API inconsistencies** (`&mut self`, trait bounds)
4. **Missing safety limits** (OOM risk)
5. **Poor async/concurrency support** (blocking, non-Send)

A Tokio maintainer would reject this for:
- No async support in 2026
- `&mut self` on read operations
- Blocking I/O without `spawn_blocking`
- No `Send + Sync` on user-provided callbacks
- Silent error conditions

**Estimated effort to production-ready:** 2-3 weeks of focused work on P0/P1 items.

---

## Appendix: Tested Commands

```bash
# All tests pass
cargo test --lib 2>&1 | tail -5
# test result: ok. 172 passed; 0 failed; 0 ignored

# Check for unsafe (none found)
grep -r "unsafe" src/

# Check for unwrap/expect usage
grep -c "unwrap()" src/*.rs  # 52 occurrences
grep -c "expect(" src/*.rs  # 23 occurrences

# Clippy warnings
cargo clippy 2>&1 | grep -c "warning:"  # Many
```
