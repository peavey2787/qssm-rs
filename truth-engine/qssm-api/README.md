# qssm-api

The single entry point for the QSSM truth engine.
Developers only import this crate — everything else is internal.

## Five functions, byte arrays, that's it

| Function  | Signature |
|-----------|-----------|
| `compile` | `(template_id: &str) -> Result<Vec<u8>, String>` |
| `commit`  | `(secret: &[u8], salt: &[u8; 32]) -> Vec<u8>` |
| `prove`   | `(secret: &[u8], salt: &[u8; 32], blueprint: &[u8]) -> Result<Vec<u8>, String>` |
| `verify`  | `(proof: &[u8], blueprint: &[u8]) -> bool` |
| `open`    | `(secret: &[u8], salt: &[u8; 32]) -> Vec<u8>` |

There are **zero** public types, structs, enums, traits, constants, or re-exports.
All data is exchanged as `Vec<u8>` / `&[u8]` and primitives (`bool`, `String`).

## Quick Start

```rust
use qssm_api::{compile, commit, prove, verify, open};

let blueprint = compile("age-gate-21").unwrap();
let commitment = commit(b"my-secret", &[1u8; 32]);
let claim = br#"{"claim":{"age_years":25}}"#;
let proof = prove(claim, &[1u8; 32], &blueprint).unwrap();
assert!(verify(&proof, &blueprint));
assert_eq!(open(b"my-secret", &[1u8; 32]), commitment);
```

## Security Model

- `compile()` and `prove()` return `Result` — the façade never panics.
- `verify()` collapses all internal errors to `false`.
- No engine types (`ProofContext`, `Proof`, `ProofBundle`, `ZkError`, etc.) are exposed.
- No wire format, protocol version, JSON schema, or internal fields are visible.
- Entropy is delegated to `qssm-entropy`, never implemented in the façade.
- The blueprint byte array contains seed material — callers must protect it at rest.

## What This Crate Does Not Do

- It does not implement proving or verifying logic — it delegates to internal crates.
- It does not expose Layer 1/2/3/4/5 internals.
- It does not re-export anything from any engine crate.

## Verification

```sh
cargo test -p qssm-api
```

Before changing public behavior, review `FREEZE.md` and `SECURITY_CHECKLIST.md`.

If a change would alter the stable API surface, wire format, or verifier
rebinding semantics, stop and treat it as a new security review item.
