# qssm-api v2.0.0 — FROZEN FOR INSTITUTIONAL USE

**Crate:** `qssm-api`
**Version:** 2.0.0
**Freeze date:** 2026-04-18
**License:** BUSL-1.1

---

## Scope

Layer 6 facade for the QSSM zero-knowledge truth engine.

- **Role:** The only crate developers import. Five functions, byte arrays, nothing else.
- **Pipeline:** `compile()` resolves a template and harvests entropy. `prove()` delegates to `qssm-local-prover`. `verify()` delegates to `qssm-local-verifier`. `commit()` / `open()` are domain-separated BLAKE3 hashes.
- **Public surface:** Exactly 5 functions. Zero public types, structs, enums, traits, constants, or re-exports. All data exchanged as `Vec<u8>` / `&[u8]` and primitives.

## Freeze Contract

This crate is **frozen** at v2.0.0. The following invariants are locked:

1. **Public API surface** — exactly 5 public functions (`compile`, `commit`, `prove`, `verify`, `open`). No public types. No re-exports.
2. **Function signatures** — locked as specified below. Changes require major version bump.
3. **Error handling** — `compile()` and `prove()` return `Result<Vec<u8>, String>`. `verify()` returns `bool`. No public error types.
4. **Byte-array contract** — all proof/blueprint/commitment data is opaque `Vec<u8>`. Internal wire format is not part of the public contract.
5. **Delegation** — the facade contains no cryptographic logic. All proving delegates to `qssm-local-prover`, all verification to `qssm-local-verifier`.

## Stable Public API (locked at v2.0.0)

| Function  | Signature | Stability |
|-----------|-----------|-----------|
| `compile` | `(template_id: &str) -> Result<Vec<u8>, String>` | Locked |
| `commit`  | `(secret: &[u8], salt: &[u8; 32]) -> Vec<u8>` | Locked |
| `prove`   | `(secret: &[u8], salt: &[u8; 32], blueprint: &[u8]) -> Result<Vec<u8>, String>` | Locked |
| `verify`  | `(proof: &[u8], blueprint: &[u8]) -> bool` | Locked |
| `open`    | `(secret: &[u8], salt: &[u8; 32]) -> Vec<u8>` | Locked |

**That is the entire public surface. There is nothing else.**

## Forbidden (requires major version bump + security review)

- Adding any public type, struct, enum, trait, constant, or module.
- Adding any re-export from any engine crate.
- Changing any function signature above.
- Replacing `Result<Vec<u8>, String>` with a custom error type.
- Exposing internal wire format, protocol version, or JSON schema.
- Adding panicking code paths to production functions.

## Allowed (minor version bump)

- Internal refactoring that preserves all 5 function signatures and byte-level output.
- Bug fixes to internal serialization/deserialization.
- Performance improvements that preserve determinism.
- Additional tests.
- Documentation updates.

## Dependencies (pinned at freeze)

| Crate | Purpose |
|-------|---------|
| `qssm-local-prover` | Internal proof generation + wire format |
| `qssm-local-verifier` | Internal verification |
| `qssm-templates` | Internal predicate templates |
| `qssm-entropy` | Internal hardware entropy harvesting |
| `qssm-utils` | Internal hashing utilities |
| `serde` | Internal serialization |
| `serde_json` | Internal JSON handling |
| `hex` | Internal hex encoding |

None of these are re-exported. The facade does NOT depend on `qssm-le`, `qssm-ms`, or `qssm-gadget`.

## File Inventory

```
src/
  lib.rs          — 5 public functions, internal wire structs, unit tests
  commit_impl.rs  — domain-separated BLAKE3 commit hash (pub(crate))
SECURITY_CHECKLIST.md
FREEZE.md
README.md
Cargo.toml
```

## Verification Evidence

| Check | Result |
|-------|--------|
| `cargo test -p qssm-api` | All passed |
| `cargo check --workspace` | Clean |
| `#![forbid(unsafe_code)]` | Present |
| Zero public types | Enforced by test |
| Exactly 5 public functions | Enforced by test |
| No re-exports | Enforced by test |
| Proof round-trip via byte arrays | Tested |
| `compile()` returns `Err` for bad input | Tested |
| `commit`/`open` equality via `==` | Tested |

---

**This crate is frozen. Do not modify without a security review.**
# qssm-api v1.0.0 â€” FROZEN FOR INSTITUTIONAL USE

**Crate:** `qssm-api`
**Version:** 1.0.0
**Freeze date:** 2026-04-18
**License:** BUSL-1.1

---

## Scope

Layer 5 API for the QSSM zero-knowledge stack (truth-engine).

- **Role:** Stable SDK facade â€” the only interface the outside world uses to prove and verify
- **Pipeline:** `prove()` orchestrates predicate check â†’ MS commit â†’ truth binding â†’ LE proof. `verify()` delegates predicate check â†’ MS verify â†’ cross-engine rebinding â†’ LE verify.
- **Wire format:** `ProofBundle` provides versioned, serde-compatible JSON serialization with strict validation.
- **Key schedule:** All internal secrets derive deterministically from caller-provided `entropy_seed + binding_ctx` via domain-separated BLAKE3. Same inputs â†’ same proof.

## Freeze Contract

This crate is **frozen** at v1.0.0. The following invariants are locked:

1. **Public API surface** â€” `prove()`, `verify()`, `ProofContext`, `Proof`, `ProofBundle`, `ZkError`, `WireFormatError`, `PROTOCOL_VERSION`, `qssm_templates` re-export. Additions allowed; removals require major version bump.
2. **Dependency boundary** â€” qssm-api depends on `qssm-le`, `qssm-ms`, `qssm-gadget`, `qssm-utils`, `qssm-templates`, `serde`, `serde_json`, `thiserror`, `hex`. No `qssm-entropy` or hardware-specific crates.
3. **Prove pipeline** â€” 6-step deterministic pipeline (predicate â†’ key schedule â†’ MS commit/prove â†’ truth binding â†’ LE witness â†’ LE prove). Step order and domain separators are locked.
4. **Verify pipeline** â€” 4-step delegation (predicate â†’ MS verify â†’ cross-engine rebinding â†’ LE verify). Rebinding recomputes truth digest from MS transcript â€” never trusts prover-claimed values.
5. **Wire format** â€” `ProofBundle` field names, types, and serialization semantics are locked. `#[serde(deny_unknown_fields)]` enforced. Version check on deserialization.
6. **Non-exhaustive enums and structs** â€” `ZkError`, `WireFormatError`, `Proof`, `ProofBundle` are all `#[non_exhaustive]`. New variants/fields may be added in minor releases.

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
| `qssm_templates` re-export | Module | Must remain re-exported. |

### Allowed to change (minor version bump)

- **Additive-only changes:** new public functions, new enum variants, new struct fields (with `#[serde(default)]` for wire types), new re-exports.
- **Performance improvements** to `derive_le_witness` or key schedule internals, provided determinism is preserved (same inputs â†’ same outputs).
- **New dev-dependencies** for additional test infrastructure.
- **Documentation** updates to doc-comments or markdown files.

### Forbidden to change (requires major version bump)

- **Removing** any item from the stable table above.
- **Changing** the signature of `prove()`, `verify()`, or any stable method.
- **Changing** the deterministic key schedule â€” the domain separators (`DOMAIN_SDK_MS_SEED`, `DOMAIN_SDK_LE_WITNESS`, `DOMAIN_SDK_LE_MASK`, `DOMAIN_EXTERNAL_ENTROPY`, `MS_CONTEXT_TAG`) are locked.
- **Changing** the wire format field names, types, or serialization order in `ProofBundle`.
- **Relaxing** `#[serde(deny_unknown_fields)]` on `ProofBundle`.
- **Relaxing** `#[non_exhaustive]` on any type.
- **Adding** `qssm-entropy` or any hardware-specific crate to production dependencies.
- **Moving** `derive_le_witness` to a different crate (it is SDK-level key schedule).

### Not part of the API surface

The following are **internal** and may change without notice:

- `pub(crate) const MS_CONTEXT_TAG` â€” shared internal constant.
- `prove::derive_le_witness()` â€” internal key schedule helper (`pub(crate)` visibility).
- `wire::PROOF_BUNDLE_VERSION` â€” internal wire format constant (`pub(crate)`).
- All `mod` declarations and internal module structure.
- Dev-dependencies and test infrastructure.
- `SECURITY_CHECKLIST.md` and `FREEZE.md` content (living documents).

## What Was Hardened for v1.0.0

### 1. `#![forbid(unsafe_code)]`

Crate-wide prohibition on unsafe code.

### 2. `#[non_exhaustive]` on all public types

`ZkError`, `WireFormatError`, `Proof`, and `ProofBundle` â€” enforced by 2 compile-fail tests.

### 3. `ProofContext.vk` encapsulated

Changed from `pub` to `pub(crate)` with a `pub fn vk()` accessor. No external code accessed the field directly.

### 4. Entropy re-exports stripped

`qssm-entropy` removed from dependencies. `entropy.rs` module deleted. `harvest_entropy_seed()` and all `qssm-entropy` type re-exports removed. Callers must depend on `qssm-entropy` directly.

### 5. `SovereignProofBundle` alias removed

Dead type alias removed from wire format surface.

### 6. Magic string deduplicated

`b"qssm-sdk-v1"` extracted to `pub(crate) const MS_CONTEXT_TAG` shared between prove and verify.

### 7. `ProofBundle` strict parsing

`#[serde(deny_unknown_fields)]` added â€” rejects JSON with unknown fields.

### 8. Test hardening

Expanded from 1 test to 22 tests (18 unit + 3 compile-fail + 1 doc-test).

### 9. Unused dev-dependency removed

`tempfile` removed from `[dev-dependencies]`.

## Verification Evidence

| Check | Result |
|-------|--------|
| `cargo test -p qssm-api` | **22/22 passed** (18 unit + 3 compile-fail + 1 doc-test) |
| `cargo check` on workspace | **Clean** |
| `#![forbid(unsafe_code)]` | **Present** |
| `#[non_exhaustive]` on ZkError | **Present** (compile-fail verified) |
| `#[non_exhaustive]` on WireFormatError | **Present** (compile-fail verified) |
| `#[non_exhaustive]` on Proof | **Present** |
| `#[non_exhaustive]` on ProofBundle | **Present** |
| `#[serde(deny_unknown_fields)]` on ProofBundle | **Present** (unit test verified) |
| No `qssm-entropy` in dependencies | **Verified** |
| No `unwrap()`/`expect()` in production | **Verified** |
| `SECURITY_CHECKLIST.md` | **Rev 1 â€” all boxes checked** |

## Dependencies (pinned at freeze)

| Crate | Version | Purpose |
|-------|---------|---------|
| `qssm-le` | path (workspace) | Layer 1 lattice engine |
| `qssm-ms` | path (workspace) | Layer 2 mirror-shift engine |
| `qssm-gadget` | path (workspace) | Layer 3 truth binding gadgets |
| `qssm-utils` | path (workspace) | Hashing utilities, domain separators |
| `qssm-templates` | path (relative) | Predicate template gallery |
| `serde` | workspace | Serialization |
| `serde_json` | workspace | JSON claim type |
| `thiserror` | workspace | Error derive |
| `hex` | workspace | Hex encoding for wire format |

Dev-only: `trybuild` (compile-fail tests).

## File Inventory

```
src/
  lib.rs          â€” module declarations, re-exports, MS_CONTEXT_TAG, 18 unit tests
  context.rs      â€” ProofContext, Proof
  error.rs        â€” ZkError
  prove.rs        â€” prove(), derive_le_witness()
  verify.rs       â€” verify()
  wire.rs         â€” ProofBundle, WireFormatError, serialization
tests/
  compile_tests.rs              â€” trybuild runner (3 compile-fail tests)
  ui/
    exhaustive_zk_error.rs      â€” ZkError non-exhaustive enforcement
    exhaustive_wire_format_error.rs  â€” WireFormatError non-exhaustive enforcement
    entropy_not_reexported.rs   â€” entropy removal regression guard
SECURITY_CHECKLIST.md           â€” Rev 1, all items checked
FREEZE.md                       â€” This file
Cargo.toml                      â€” v1.0.0
```

---

**This crate is frozen. Do not modify without a security review.**
