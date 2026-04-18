# QSSM-MS v1.0.0 — FROZEN FOR INSTITUTIONAL USE

**Crate:** `qssm-ms`
**Version:** 1.0.0
**Freeze date:** 2026-04-18
**License:** BUSL-1.1

---

## Scope

Layer 2 Mirror-Shift Engine for the QSSM zero-knowledge stack.

- **Protocol:** Ghost-Mirror commitments — 128-leaf position-aware Merkle tree with BLAKE3 domain-separated hashing
- **Predicate:** Succinct proof that `value > target` via wrapping u64 rotation + highest differing bit
- **Security model:** Succinct predicate proof (NOT zero-knowledge — both values are known to verifier)

## Freeze Contract

This crate is **frozen** at v1.0.0. The following invariants are locked:

1. **Wire format** — FS transcript layout (10 inputs, fixed order via `hash_domain`), proof body structure (`n`, `k`, `bit_at_k`, `opened_salt`, `path[7]`, `challenge`), and `"fs_v2"` version tag are immutable.
2. **Tree parameters** — 128 leaves, depth 7, leaf index `2k + bit_at_k`, nonce range `[0, 255]`, `MERKLE_PATH_LEN = 7` are immutable.
3. **Domain separators** — `DOMAIN_MS` = `"QSSM-MS-v1.0"`, sub-labels `"fs_v2"`, `"leaf"`, `"salt"`, `"rot_nonce"` are immutable.
4. **Salt derivation** — `BLAKE3(DOMAIN_MS ‖ "salt" ‖ seed ‖ i_le ‖ bit)` for all 128 leaves.
5. **Leaf construction** — `BLAKE3(DOMAIN_MS ‖ "leaf" ‖ k ‖ bit ‖ salt ‖ binding_ent)`.
6. **Public API surface** — All `pub use` re-exports in `lib.rs` are stable. Additions are allowed; removals require a major version bump.

Any change that violates these invariants requires a new security review, a major version bump, and synchronized updates to `qssm-api`, `qssm-local-verifier`, `qssm-gadget`, and `mssq-batcher`.

## What Was Hardened for v1.0.0

Seven improvements were implemented for the freeze:

### 1. Dependencies added (`subtle`, `zeroize`)

`subtle = "2.6"` for constant-time comparisons. `zeroize = { version = "1.8", features = ["derive"] }` for secret scrubbing on drop.

### 2. `Salts` newtype with `Zeroize + ZeroizeOnDrop`

Formerly `pub type Salts = [[u8; 32]; 128]`. Now a proper newtype struct with private inner field, `Zeroize + ZeroizeOnDrop`, manual `Debug` (prints `"Salts([REDACTED; 128])"`), no `Clone`/`Copy`. Access via `Index<usize>` and `get()`.

### 3. `Root` encapsulation

Inner `[u8; 32]` field made private. External callers use `Root::new(bytes)` and `Root::as_bytes()`.

### 4. `GhostMirrorProof` encapsulation

All 6 fields made `pub(crate)`. Added validating constructor `GhostMirrorProof::new()` that checks `bit_at_k ∈ {0,1}`, `k ≤ 63`, `path.len() == 7`. Added 6 read-only accessors. Manual `Debug` impl redacts `opened_salt` and `challenge`. `PartialEq`/`Eq` gated behind `#[cfg(test)]`.

### 5. Constant-time comparisons

Merkle root comparison in `verify_path_to_root()` and FS challenge comparison in `verify()` both use `subtle::ConstantTimeEq`. Prevents timing oracles.

### 6. `commit()` API cleanup

Removed unused `_value: u64` parameter from `commit()`. Signature is now `commit(seed, binding_entropy) -> Result<(Root, Salts), MsError>`.

### 7. Test hardening

Added 16 new tests (boundary values, constructor validation, determinism, replay rejection, salt uniqueness, debug redaction) bringing total to 25. Added structured fuzz target for the verifier.

## Verification Evidence

| Check | Result |
|-------|--------|
| `cargo test -p qssm-ms` | **25/25 passed** (9 adversarial + 5 boundary + 5 constructor + 4 determinism/replay + 2 salt/debug) |
| `cargo check` on 6 downstream crates | **Clean** (qssm-api, qssm-local-verifier, qssm-gadget, qssm-le, mssq-batcher, e2e-node-flow) |
| `#![forbid(unsafe_code)]` | **1/1 source files** (lib.rs) |
| `SECURITY_CHECKLIST.md` | **Rev 1 — all boxes checked** |
| Fuzz harness | Structured 397-byte verifier fuzzing (panic safety + rejection correctness) |

## Security Concessions (documented and accepted)

1. **`binding_rotation()` uses 8/32 entropy bytes** — The rotation is derived from the first 8 bytes of binding entropy. The remaining 24 bytes are unused. Acceptable: rotation is deterministic and public; entropy utilization does not affect security.
2. **`highest_differing_bit()` is not constant-time** — Branching loop over bit positions. Acceptable: `k` is a public proof field, not secret.
3. **`GhostMirrorProof` retains unconditional `Clone`** — Required by downstream `Proof` struct in qssm-api. The opened salt is intentionally revealed in proofs and is not a persistent secret.

## Dependencies (pinned at freeze)

| Crate | Version | Purpose |
|-------|---------|---------|
| `qssm-utils` | workspace | `hash_domain`, `DOMAIN_MS`, `PositionAwareTree`, `MerkleError` |
| `subtle` | 2.6 | `ConstantTimeEq` |
| `zeroize` | 1.8 (features: derive) | `Zeroize`, `ZeroizeOnDrop` |
| `thiserror` | workspace | `MsError` derive |

## File Inventory

```
src/
  lib.rs                  — Facade, Root, GhostMirrorProof, commit, prove, verify
  core.rs                 — binding_rotation, rot_for_nonce, highest_differing_bit
  error.rs                — MsError
  transcript.rs           — fs_challenge (Fiat-Shamir binding)
  commitment/
    mod.rs                — Module declarations
    leaves.rs             — Salts, derive_salts, build_leaves, ms_leaf
    tree.rs               — verify_path_to_root (CT root comparison)
unit_tests/
  mirror_shift_adversarial.rs — 25 adversarial + hardening tests
fuzz/
  fuzz_targets/
    verify_mirror_shift.rs — Structured verifier fuzz target (397 bytes)
SECURITY_CHECKLIST.md     — Rev 1, all items checked
FREEZE.md                 — This file
Cargo.toml                — v1.0.0
```

---

**This crate is frozen. Do not modify without a security review.**
