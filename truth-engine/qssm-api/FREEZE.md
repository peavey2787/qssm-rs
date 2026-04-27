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
