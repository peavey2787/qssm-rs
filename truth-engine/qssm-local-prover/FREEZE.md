# QSSM-LOCAL-PROVER v1.0.0 — FROZEN FOR INSTITUTIONAL USE

**Crate:** `qssm-local-prover`
**Version:** 1.0.0
**Freeze date:** 2026-04-18
**License:** BUSL-1.1

---

## Scope

Layer 4 Deterministic Prove Pipeline for the QSSM zero-knowledge stack.

- **Pipeline:** Predicates → MS commit → Truth binding → LE proof
- **Role:** Orchestrates `qssm-ms` (Merkle inequality), `qssm-gadget` (truth binding), and `qssm-le` (lattice proof) into a single deterministic `prove()` call
- **Security model:** Fully deterministic — all secrets derived from caller-provided `entropy_seed` + `binding_ctx` via domain-separated BLAKE3. No internal randomness, no OS entropy.

## Freeze Contract

This crate is **frozen** at v1.0.0. The following invariants are locked:

1. **Public API** — `pub fn prove(ctx, template, claim, value, target, binding_ctx, entropy_seed) -> Result<Proof, ZkError>` is the sole export. Signature changes require a major version bump.

2. **Key schedule order** — The derivation sequence is immutable:
   - `ms_seed = BLAKE3(DOMAIN_SDK_MS_SEED ‖ entropy_seed ‖ binding_ctx)`
   - `binding_entropy = BLAKE3(binding_ctx)`
   - `external_entropy = BLAKE3(DOMAIN_EXTERNAL_ENTROPY ‖ entropy_seed ‖ binding_ctx)`
   - `witness = derive_le_witness(entropy_seed, binding_ctx)` (counter-mode BLAKE3)
   - `le_mask_seed = BLAKE3(DOMAIN_SDK_LE_MASK ‖ entropy_seed ‖ binding_ctx)`

3. **Domain tags** — All domain separation strings are immutable:
   - `DOMAIN_EXTERNAL_ENTROPY = "QSSM-SDK-EXTERNAL-ENTROPY-v1"`
   - `DOMAIN_SDK_MS_SEED`, `DOMAIN_SDK_LE_WITNESS`, `DOMAIN_SDK_LE_MASK` (defined in `qssm-utils`)

4. **Pipeline order** — The prove pipeline follows an immutable sequence:
   1. Predicate check (`verify_public_claim`)
   2. Key schedule (`ms_seed`, `binding_entropy`)
   3. MS commit + prove
   4. Truth binding (`TruthWitness::bind` + `validate`)
   5. LE public instance + witness derivation
   6. LE prove (`prove_arithmetic`)
   7. Proof construction (`Proof::new`)

5. **Proof construction** — `Proof::new()` argument order is immutable: `(ms_root, ms_proof, le_commitment, le_proof, external_entropy, external_entropy_included, value, target, binding_entropy)`.

6. **Zeroization invariants** — The following stack-secret scrubbing points are locked:
   - [x] `ms_seed` is always zeroized immediately after MS commit completes.
   - [x] `le_mask_seed` is always zeroized immediately after LE prove completes.
   - [x] `entropy_seed` local copy is always zeroized before returning `Proof`.
   - [x] `r` array in `derive_le_witness()` is always zeroized after `Witness` construction.
   - `Witness::new(r)` copies the array (`[i32; N]` is `Copy`); the original stack buffer `r` is explicitly zeroized after construction to avoid residual witness coefficients on the stack. This is a locked invariant.

Any change that violates these invariants requires a new security review, a major version bump, and synchronized updates to `qssm-api`, `qssm-local-verifier`, and `qssm-integration`.

## What Was Hardened for v1.0.0

Four improvements were implemented for the freeze:

### 1. Explicit zeroization of intermediate secrets

`ms_seed`, `le_mask_seed`, `entropy_seed` (local copy), and the witness `r` array are now explicitly zeroized via the `zeroize` crate (volatile writes) after their last use. Prior to freeze, these values fell off the stack without scrubbing.

### 2. SECURITY_CHECKLIST.md created

A comprehensive, per-item security checklist covering public surface, key schedule, secret lifetime, error handling, domain separation, truth binding, adversarial test coverage, integration test coverage, and constant-time delegation.

### 3. Zeroization best-effort disclosure

All zeroization is documented as best-effort within Rust's compilation and optimization model. The `zeroize` crate uses volatile writes for strong practical assurance, but no formal hardware-level guarantee is claimed.

### 4. API simplicity preserved

`entropy_seed` remains a plain `[u8; 32]` rather than a `Zeroizing<[u8; 32]>` wrapper to keep the public API simple and avoid type-level coupling to the `zeroize` crate. The parameter is received by value (`mut entropy_seed: [u8; 32]`) and scrubbed locally — zeroization is confined to this frame.

## Verification Evidence

| Check | Result |
|-------|--------|
| `cargo test -p qssm-local-prover` | **17/17 passed** (1 witness + 1 roundtrip + 5 adversarial + 2 wire roundtrip + 5 wire rejection + 2 injectivity + 1 field-names) |
| `cargo test -p qssm-integration` | **52/52 passed** (5 test files exercising `prove()`) |
| `cargo check` on downstream crates | **Clean** (qssm-local-verifier, qssm-integration, examples) |
| `#![forbid(unsafe_code)]` | **1/1 source file** |
| `SECURITY_CHECKLIST.md` | **Rev 1 — all boxes checked** |
| `grep "panic!\|todo!\|unimplemented!"` | **0 production matches** |
| `grep "unwrap\|expect"` | **0 production matches** (all inside `#[cfg(test)]`) |
| `grep "SECURITY-CONCESSION"` | **1 match** (`h` loop variable in `derive_le_witness`) |
| `grep ".zeroize()"` | **4 production scrub calls** — `ms_seed` L56, `le_mask_seed` L92, `entropy_seed` L93, `r` L132 |

## Security Concessions (documented and accepted)

1. **`h` loop variable in `derive_le_witness()`** — The 32-byte hash output `h` is loop-scoped and overwritten each of the 32 iterations. Not explicitly zeroized. Accepted: `h` is a derived hash output (not a master key), overwritten per iteration, and the stack frame is reclaimed on function return. Tagged `// SECURITY-CONCESSION` in `lib.rs`.

All concessions are tagged with `// SECURITY-CONCESSION` in source and cross-referenced in `SECURITY_CHECKLIST.md`.

## Versioning

`qssm-local-prover` is consumed from the workspace root with an exact version pin (`=1.0.0`) to prevent accidental upgrades or semver drift. This mirrors the `qssm-gadget` `=1.1.0` precedent.

## Dependencies (pinned at freeze)

| Crate | Source | Purpose |
|-------|--------|---------|
| `qssm-api` | path `../qssm-api` | `Proof`, `ProofContext`, `ZkError`, `MS_CONTEXT_TAG` |
| `qssm-gadget` | workspace | `TruthWitness` — digest binding bridge |
| `qssm-le` | workspace | `PublicInstance`, `Witness`, `prove_arithmetic`, `BETA`, `N` |
| `qssm-ms` | workspace | `commit`, `prove` — Merkle inequality |
| `qssm-utils` | workspace | `hash_domain`, `blake3_hash`, domain constants |
| `qssm-templates` | path `../qssm-templates` | `QssmTemplate` — predicate evaluation |
| `serde_json` | workspace | Claim JSON parsing |
| `zeroize` | `1.8` (features: derive) | `Zeroize` trait for stack-secret scrubbing |
| `hex` | workspace (dev) | Hex encoding in tests |

## File Inventory

```
src/
  lib.rs                  — prove(), derive_le_witness(), DOMAIN_EXTERNAL_ENTROPY,
                            17 inline tests
Cargo.toml                — v1.0.0
FREEZE.md                 — This file
SECURITY_CHECKLIST.md     — Rev 1, all items checked
```

---

**This crate is frozen. Do not modify without a security review.**
