# QSSM-UTILS v1.0.0 — FROZEN FOR INSTITUTIONAL USE

**Crate:** `qssm-utils`
**Version:** 1.0.0
**Freeze date:** 2026-04-18
**License:** BUSL-1.1

---

## Scope

Shared cryptographic utility crate for the QSSM zero-knowledge stack.

- **Modules:** `hashing`, `merkle`, `entropy_density`, `entropy_stats`, `entropy_audit`
- **Role:** Provides BLAKE3 domain-separated hashing, versioned domain tags, binary Merkle trees, and entropy audit heuristics
- **Consumers:** 12 workspace members including all frozen crates (`qssm-le`, `qssm-ms`, `qssm-gadget`, `qssm-local-prover`)

## Frozen Contract

This crate is **frozen** at v1.0.0. The following invariants are locked:

### Domain tags and hashing invariants

- `DOMAIN_MS = "QSSM-MS-v1.0"`
- `DOMAIN_LE = "QSSM-LE-v1.0"`
- `DOMAIN_MERKLE_PARENT = "QSSM-MERKLE-PARENT-v1.0"`
- `DOMAIN_SDK_MS_SEED = "QSSM-SDK-MS-SEED-v1"`
- `DOMAIN_SDK_LE_WITNESS = "QSSM-SDK-LE-WITNESS-v1"`
- `DOMAIN_SDK_LE_MASK = "QSSM-SDK-LE-MASK-v1"`
- `LE_FS_PUBLIC_BINDING_LAYOUT_VERSION = 1`
- `hash_domain(domain, chunks)` is immutable in semantics: UTF-8 domain prefix first, then chunks in order
- `blake3_hash(data)` remains a thin 32-byte BLAKE3 wrapper

### Merkle invariants

- `merkle_parent(left, right)` is domain-separated by `DOMAIN_MERKLE_PARENT`
- Parent hashing order is left-then-right; swapping inputs changes the digest
- `PositionAwareTree::new()` pads to the next power of two using `hash_domain(DOMAIN_MERKLE_PARENT, &[b"pad"])`
- `get_proof(index)` returns siblings from leaf level toward the root (deepest first)
- Sibling selection remains `idx ^ 1`
- Error semantics are stable: empty input returns `MerkleError::EmptyLeaves`, invalid proof index returns `MerkleError::IndexOutOfBounds`

### Entropy invariants

- `MIN_RAW_BYTES = 256`
- `verify_density()` remains a heuristic density screen only; it is not a formal randomness certification or NIST SP 800-90B claim
- `validate_entropy_distribution()` remains the χ² + distinct-byte gate for sufficiently large inputs
- `validate_entropy_full()` remains density-first, then distribution validation

### Error model invariants

- Public error enums are `MerkleError`, `EntropyAuditError`, `EntropyStatsError`
- All 3 public error enums are `#[non_exhaustive]`
- All 3 public error enums use `thiserror`
- Error display strings remain stable unless intentionally revised under review

Any change that violates these invariants requires a new security review, a major version bump, and synchronized updates to all 12 downstream consumers.

## What Was Hardened for v1.0.0

Four improvements were implemented for the freeze:

### 1. Public error model hardened with `#[non_exhaustive]`

All 3 public error enums (`MerkleError`, `EntropyAuditError`, `EntropyStatsError`) now carry `#[non_exhaustive]`, preventing downstream crates from writing exhaustive `match` arms and preserving semver freedom to add variants.

### 2. `EntropyStatsError` migrated to `thiserror`

`EntropyStatsError` previously used manual `Display`/`Error` implementations while the other two enums used `thiserror`. Migrated to `thiserror` for consistency across the frozen API. Exact display strings were preserved.

### 3. Comprehensive Merkle test suite added

10 tests covering roundtrip proof verification, single-leaf behavior, non-power-of-two padding, determinism, error cases, proof length, parent non-commutativity, and a 128-leaf realism case matching `qssm-ms` usage patterns.

### 4. Direct entropy density test coverage added

6 tests covering boundary conditions, constant-byte rejection, all-0xFF rejection, square-wave detection, pseudo-random acceptance, and exact-minimum-boundary behavior.

## Verification Evidence

| Check | Result |
|-------|--------|
| `cargo test -p qssm-utils --all-features` | **23/23 passed** (1 hashing + 10 Merkle + 6 density + 3 stats + 3 audit) |
| `cargo check` on downstream crates | **Clean** (qssm-ms, qssm-gadget, qssm-local-prover, qssm-api) |
| `cargo test -p qssm-integration` | **15/15 passed** |
| `#![forbid(unsafe_code)]` | **Crate-root level** — covers all 5 modules |
| `SECURITY_CHECKLIST.md` | **Rev 1 — all boxes checked** |
| `grep "#[non_exhaustive]"` | **3 matches** — `MerkleError`, `EntropyAuditError`, `EntropyStatsError` |
| `grep "panic!\|todo!\|unimplemented!"` | **0 production matches** |
| `grep "unwrap\|expect"` | **0 production matches** (all inside `#[cfg(test)]`) |

## Not Applicable

| Item | Status | Rationale |
|---|---|---|
| `zeroize` | Not applicable | No secret material handled by this crate |
| `subtle` | Not applicable | No secret comparisons performed by this crate |
| `SECURITY-CONCESSION` tags | Not applicable | No security concessions exist |
| Constant-time operations | Not applicable | No secret-dependent branching |

## Versioning

`qssm-utils` is consumed from the workspace root with an exact version pin (`=1.0.0`) to prevent accidental upgrades or semver drift. This mirrors the `qssm-gadget` `=1.1.0` and `qssm-local-prover` `=1.0.0` precedents.

## Dependencies (pinned at freeze)

| Crate | Source | Purpose |
|-------|--------|---------|
| `blake3` | workspace | BLAKE3 hashing primitive |
| `rayon` | workspace | Parallel bit counting in `verify_density()` |
| `thiserror` | workspace | Error enum derives for all 3 public error types |

## File Inventory

```
src/
  lib.rs                  — crate root, #![forbid(unsafe_code)], re-exports
  hashing.rs              — 7 domain constants, blake3_hash, hash_domain, 1 test
  merkle.rs               — PositionAwareTree, merkle_parent, MerkleError, 10 tests
  entropy_density.rs      — verify_density, MIN_RAW_BYTES, heuristic gates, 6 tests
  entropy_stats.rs        — validate_entropy_distribution, EntropyStatsError, 3 tests
  entropy_audit.rs        — validate_entropy_full, EntropyAuditError, 3 tests
Cargo.toml                — v1.0.0
FREEZE.md                 — This file
SECURITY_CHECKLIST.md     — Rev 1, all items checked
```

---

**Freeze decision:** `qssm-utils` v1.0.0 is approved for institutional use and added to the frozen primitive set.

**This crate is frozen. Do not modify without a security review.**
