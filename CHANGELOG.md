# Changelog

## v0.2.0

- Added `#[non_exhaustive]` to extensible public enums such as `MarkerPosition`, `TemplateExpansionError`, `IssueLevel`, `BuiltinEncoding`, and `PayloadError`.
- Added `Display` implementations for developer-facing public types including `PayloadDb`, `Grammar`, `ExpandedPayload`, `Payload`, `PayloadConfig`, and related helper types.
- Added `# Thread Safety` sections across the public API to state whether each type is `Send`, `Sync`, or implementation-defined.
- Added `#[must_use]` to important constructors and value-returning APIs that are easy to ignore by accident.
