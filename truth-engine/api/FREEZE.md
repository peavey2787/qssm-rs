# zk-api v1.0.0 — FROZEN FOR INSTITUTIONAL USE

**Crate:** `zk-api`
**Version:** 1.0.0
**Freeze date:** 2026-04-18
**License:** BUSL-1.1

---

## Scope

Layer 5 API for the QSSM zero-knowledge stack (truth-engine).

- **Role:** Stable SDK facade — the only interface the outside world uses to prove and verify
- **Pipeline:** `prove()` orchestrates predicate check → MS commit → truth binding → LE proof. `verify()` delegates predicate check → MS verify → cross-engine rebinding → LE verify.
- **Wire format:** `ProofBundle` provides versioned, serde-compatible JSON serialization with strict validation.
- **Key schedule:** All internal secrets derive deterministically from caller-provided `entropy_seed + binding_ctx` via domain-separated BLAKE3. Same inputs → same proof.

## Freeze Contract

This crate is **frozen** at v1.0.0. The following invariants are locked:

1. **Public API surface** — `prove()`, `verify()`, `ProofContext`, `Proof`, `ProofBundle`, `ZkError`, `WireFormatError`, `PROTOCOL_VERSION`, `template_lib` re-export. Additions allowed; removals require major version bump.
2. **Dependency boundary** — zk-api depends on `qssm-le`, `qssm-ms`, `qssm-gadget`, `qssm-utils`, `template-lib`, `serde`, `serde_json`, `thiserror`, `hex`. No `qssm-he` or hardware-specific crates.
3. **Prove pipeline** — 6-step deterministic pipeline (predicate → key schedule → MS commit/prove → truth binding → LE witness → LE prove). Step order and domain separators are locked.
4. **Verify pipeline** — 4-step delegation (predicate → MS verify → cross-engine rebinding → LE verify). Rebinding recomputes truth digest from MS transcript — never trusts prover-claimed values.
5. **Wire format** — `ProofBundle` field names, types, and serialization semantics are locked. `#[serde(deny_unknown_fields)]` enforced. Version check on deserialization.
6. **Non-exhaustive enums and structs** — `ZkError`, `WireFormatError`, `Proof`, `ProofBundle` are all `#[non_exhaustive]`. New variants/fields may be added in minor releases.

Any change that violates these invariants requires a new security review and a major version bump.

## Layer 5 API Stability Contract

### Stable (locked at v1.0.0)

The following items are part of the **stable public API** and must not be modified or removed without a major version bump:

| Item | Kind | Stability |
|------|------|-----------|
| `prove()` | Function | Signature locked. Return type locked. |
| `verify()` | Function | Signature locked. Return type locked. |
| `ProofContext::new(seed)` | Constructor | Signature locked. |
| `ProofContext::seed()` | Accessor | Return type locked. |
| `ProofContext::vk()` | Accessor | Return type locked. |
| `Proof` (all pub fields) | Struct | Existing fields locked. New fields allowed (minor bump). |
| `ProofBundle::from_proof()` | Method | Signature locked. |
| `ProofBundle::to_proof()` | Method | Signature locked. Return type locked. |
| `ProofBundle` (all pub fields) | Struct | Existing field names/types locked. New fields allowed (minor bump, with `#[serde(default)]`). |
| `ZkError` (all variants) | Enum | Existing variants locked. New variants allowed (minor bump). |
| `WireFormatError` (all variants) | Enum | Existing variants locked. New variants allowed (minor bump). |
| `PROTOCOL_VERSION` | Const | Value locked at `1` for this wire format generation. |
| `template_lib` re-export | Module | Must remain re-exported. |

### Allowed to change (minor version bump)

- **Additive-only changes:** new public functions, new enum variants, new struct fields (with `#[serde(default)]` for wire types), new re-exports.
- **Performance improvements** to `derive_le_witness` or key schedule internals, provided determinism is preserved (same inputs → same outputs).
- **New dev-dependencies** for additional test infrastructure.
- **Documentation** updates to doc-comments or markdown files.

### Forbidden to change (requires major version bump)

- **Removing** any item from the stable table above.
- **Changing** the signature of `prove()`, `verify()`, or any stable method.
- **Changing** the deterministic key schedule — the domain separators (`DOMAIN_SDK_MS_SEED`, `DOMAIN_SDK_LE_WITNESS`, `DOMAIN_SDK_LE_MASK`, `DOMAIN_EXTERNAL_ENTROPY`, `MS_CONTEXT_TAG`) are locked.
- **Changing** the wire format field names, types, or serialization order in `ProofBundle`.
- **Relaxing** `#[serde(deny_unknown_fields)]` on `ProofBundle`.
- **Relaxing** `#[non_exhaustive]` on any type.
- **Adding** `qssm-he` or any hardware-specific crate to production dependencies.
- **Moving** `derive_le_witness` to a different crate (it is SDK-level key schedule).

### Not part of the API surface

The following are **internal** and may change without notice:

- `pub(crate) const MS_CONTEXT_TAG` — shared internal constant.
- `prove::derive_le_witness()` — internal key schedule helper (`pub(crate)` visibility).
- `wire::PROOF_BUNDLE_VERSION` — internal wire format constant (`pub(crate)`).
- All `mod` declarations and internal module structure.
- Dev-dependencies and test infrastructure.
- `SECURITY_CHECKLIST.md` and `FREEZE.md` content (living documents).

## What Was Hardened for v1.0.0

### 1. `#![forbid(unsafe_code)]`

Crate-wide prohibition on unsafe code.

### 2. `#[non_exhaustive]` on all public types

`ZkError`, `WireFormatError`, `Proof`, and `ProofBundle` — enforced by 2 compile-fail tests.

### 3. `ProofContext.vk` encapsulated

Changed from `pub` to `pub(crate)` with a `pub fn vk()` accessor. No external code accessed the field directly.

### 4. Entropy re-exports stripped

`qssm-he` removed from dependencies. `entropy.rs` module deleted. `harvest_entropy_seed()` and all `qssm-he` type re-exports removed. Callers must depend on `qssm-he` directly.

### 5. `SovereignProofBundle` alias removed

Dead type alias removed from wire format surface.

### 6. Magic string deduplicated

`b"qssm-sdk-v1"` extracted to `pub(crate) const MS_CONTEXT_TAG` shared between prove and verify.

### 7. `ProofBundle` strict parsing

`#[serde(deny_unknown_fields)]` added — rejects JSON with unknown fields.

### 8. Test hardening

Expanded from 1 test to 22 tests (18 unit + 3 compile-fail + 1 doc-test).

### 9. Unused dev-dependency removed

`tempfile` removed from `[dev-dependencies]`.

## Verification Evidence

| Check | Result |
|-------|--------|
| `cargo test -p zk-api` | **22/22 passed** (18 unit + 3 compile-fail + 1 doc-test) |
| `cargo check` on workspace | **Clean** |
| `#![forbid(unsafe_code)]` | **Present** |
| `#[non_exhaustive]` on ZkError | **Present** (compile-fail verified) |
| `#[non_exhaustive]` on WireFormatError | **Present** (compile-fail verified) |
| `#[non_exhaustive]` on Proof | **Present** |
| `#[non_exhaustive]` on ProofBundle | **Present** |
| `#[serde(deny_unknown_fields)]` on ProofBundle | **Present** (unit test verified) |
| No `qssm-he` in dependencies | **Verified** |
| No `unwrap()`/`expect()` in production | **Verified** |
| `SECURITY_CHECKLIST.md` | **Rev 1 — all boxes checked** |

## Dependencies (pinned at freeze)

| Crate | Version | Purpose |
|-------|---------|---------|
| `qssm-le` | path (workspace) | Layer 1 lattice engine |
| `qssm-ms` | path (workspace) | Layer 2 mirror-shift engine |
| `qssm-gadget` | path (workspace) | Layer 3 truth binding gadgets |
| `qssm-utils` | path (workspace) | Hashing utilities, domain separators |
| `template-lib` | path (relative) | Predicate template gallery |
| `serde` | workspace | Serialization |
| `serde_json` | workspace | JSON claim type |
| `thiserror` | workspace | Error derive |
| `hex` | workspace | Hex encoding for wire format |

Dev-only: `trybuild` (compile-fail tests).

## File Inventory

```
src/
  lib.rs          — module declarations, re-exports, MS_CONTEXT_TAG, 18 unit tests
  context.rs      — ProofContext, Proof
  error.rs        — ZkError
  prove.rs        — prove(), derive_le_witness()
  verify.rs       — verify()
  wire.rs         — ProofBundle, WireFormatError, serialization
tests/
  compile_tests.rs              — trybuild runner (3 compile-fail tests)
  ui/
    exhaustive_zk_error.rs      — ZkError non-exhaustive enforcement
    exhaustive_wire_format_error.rs  — WireFormatError non-exhaustive enforcement
    entropy_not_reexported.rs   — entropy removal regression guard
SECURITY_CHECKLIST.md           — Rev 1, all items checked
FREEZE.md                       — This file
Cargo.toml                      — v1.0.0
```

---

**This crate is frozen. Do not modify without a security review.**
