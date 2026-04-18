# Contributing to QSSM

Thank you for your interest in contributing to the QSSM project.

## Building

### Prerequisites

- **Rust** 1.78+ (edition 2021, resolver 2)
- **Windows**, **macOS**, or **Linux** (CI targets all three)

### Build the workspace

```bash
cargo build --workspace
```

### Build in release mode

```bash
cargo build --workspace --release
```

## Running Tests

### Unit tests (full workspace)

```bash
cargo test --workspace
```

### Single crate

```bash
cargo test -p qssm-le
cargo test -p qssm-api
cargo test -p qssm-templates
```

### Integration tests

Integration tests live directly in `integration/`. Run them with:

```bash
cargo test -p qssm-integration
```

Individual integration test suites:

```bash
cargo test -p qssm-integration --test test_roundtrip
cargo test -p qssm-integration --test test_negative
cargo test -p qssm-integration --test test_serialization
cargo test -p qssm-integration --test test_entropy
cargo test -p qssm-integration --test test_template_resolution
cargo test -p qssm-integration --test adversarial_replay
```

### Compile-fail tests

The `qssm-api` crate includes `trybuild` compile-fail tests that verify API surface constraints (e.g. `#[non_exhaustive]` enforcement, entropy types not re-exported). These run automatically as part of `cargo test -p qssm-api`.

## Adding a New Template

Templates live in `truth-engine/qssm-templates/`.

1. Define the template constructor in `src/lib.rs` (follow the `proof_of_age` pattern).
2. Register it in the `resolve()` match arm and in `standard_templates()`.
3. Add predicate blocks using the existing `PredicateBlock` variants (`Compare`, `Range`, `InSet`, `AtLeast`).
4. Add unit tests for valid and invalid claims.
5. Run: `cargo test -p qssm-templates --all-features`
6. Update `SECURITY_CHECKLIST.md` in the crate directory.

## Freezing a Layer

Each truth-engine crate follows a freeze protocol for institutional use.

1. **All tests pass:** `cargo test -p <crate> --all-features`
2. **Security checklist complete:** every box in the crate's `SECURITY_CHECKLIST.md` must be checked.
3. **Write `FREEZE.md`:** document the public API surface, dependency boundary, verification evidence, and invariants that are locked.
4. **Version bump:** frozen crates are pinned at their freeze version (e.g. `v1.0.0`). Breaking changes require a major version bump.
5. **Update workspace `Cargo.toml`:** if the crate has a pinned version (e.g. `qssm-gadget = { path = "...", version = "=1.1.0" }`), update accordingly.

### Freeze invariants

- `#![forbid(unsafe_code)]` must be present.
- `#[non_exhaustive]` on all public enums and structs with public fields.
- No `unwrap()` or `expect()` in production code paths.
- All production secrets zeroized on drop (`zeroize` crate).
- Constant-time comparisons for secret material (`subtle` crate).

## Code Style

- Edition 2021, resolver 2.
- `#![forbid(unsafe_code)]` in all truth-engine crates.
- No `unsafe` unless there is a documented, reviewed, and tested justification.
- Prefer `thiserror` for error types.
- Domain-separate all hashes using `qssm_utils::hashing::hash_domain`.
- All internal secrets must derive deterministically from caller-provided inputs — no internal randomness.

## License

This project is licensed under the **Business Source License 1.1 (BSL-1.1)**. By contributing, you agree that your contributions will be licensed under the same terms.
