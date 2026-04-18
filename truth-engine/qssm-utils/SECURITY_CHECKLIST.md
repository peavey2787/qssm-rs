QSSM-UTILS "BANK-GRADE" PRODUCTION READINESS CHECKLIST

**Scope:** Shared cryptographic utility crate (`truth-engine/qssm-utils`)
**Modules:** `hashing`, `merkle`, `entropy_density`, `entropy_stats`, `entropy_audit`
**Date:** 2026-04-18 (rev 1 — v1.0.0 freeze)

---

**CONTRACT:** Any change that violates or bypasses an item in this checklist
requires a new security review and version bump. This crate is consumed by 12
workspace members including all frozen crates (`qssm-le`, `qssm-ms`, `qssm-gadget`,
`qssm-local-prover`).

---

Explicitly confirm each item.

1. PUBLIC SURFACE & BOUNDARY SAFETY

Unsafe Code

[x] `#![forbid(unsafe_code)]` in `lib.rs` (crate root). No `unsafe` blocks are possible in any module.

Public API Exposure

[x] The crate re-exports all public items through `lib.rs`. Public surface:
  - 7 domain constants (`DOMAIN_MS`, `DOMAIN_LE`, `DOMAIN_MERKLE_PARENT`, `DOMAIN_SDK_MS_SEED`, `DOMAIN_SDK_LE_WITNESS`, `DOMAIN_SDK_LE_MASK`, `LE_FS_PUBLIC_BINDING_LAYOUT_VERSION`)
  - 2 hashing functions (`blake3_hash`, `hash_domain`)
  - 1 Merkle struct (`PositionAwareTree`) with private fields
  - 1 Merkle function (`merkle_parent`)
  - 3 error enums (`MerkleError`, `EntropyAuditError`, `EntropyStatsError`)
  - 3 entropy functions (`verify_density`, `validate_entropy_distribution`, `validate_entropy_full`)
  - 1 constant (`MIN_RAW_BYTES`)

[x] All 3 public error enums are `#[non_exhaustive]`. Downstream crates cannot write exhaustive `match` arms, preserving semver freedom to add variants.

Error Handling

[x] No `unwrap()` or `expect()` in production code. All `unwrap()`/`expect()` calls are exclusively inside `#[cfg(test)]` modules.

[x] No `panic!`, `todo!`, or `unimplemented!` macros in production code. Verification gate: `grep "panic!\|todo!\|unimplemented!"` returns zero production matches.

[x] `unwrap_or(0)` in `byte_max_fraction()` (`entropy_density.rs`) operates on a fixed-size 256-element array iterator — the `.max()` call can never return `None`. Documented as dead-code branch, not changed.

[x] All 3 public error enums use `thiserror` for consistent, derive-based `Display`/`Error` implementations.

2. DOMAIN SEPARATION

[x] All 7 domain constants are versioned UTF-8 strings with `QSSM-` prefix.

[x] `hash_domain(domain, chunks)` is the sole domain-separated hashing primitive. Semantics: UTF-8 domain prefix first, then chunks in order. Immutable at freeze.

[x] `blake3_hash(data)` is a thin 32-byte BLAKE3 wrapper with no domain separation. Used only for raw leaf hashing.

[x] Domain tags tested for divergence: `domain_tags_diverge_for_same_chunks` confirms different domains produce different digests for identical payloads.

3. MERKLE CORRECTNESS

[x] `merkle_parent(left, right)` is domain-separated by `DOMAIN_MERKLE_PARENT`. Non-commutative: `merkle_parent(a, b) != merkle_parent(b, a)`.

[x] `PositionAwareTree::new()` pads to the next power of two using `hash_domain(DOMAIN_MERKLE_PARENT, &[b"pad"])`. Padding is deterministic.

[x] `get_proof(index)` returns siblings from leaf level toward the root (deepest first). Sibling selection is `idx ^ 1`.

[x] Error semantics: empty input → `MerkleError::EmptyLeaves`, invalid proof index → `MerkleError::IndexOutOfBounds`.

[x] Comprehensive Merkle test suite (10 tests):
  - `single_leaf_root_is_leaf` — single leaf tree, root equals leaf, empty proof
  - `two_leaf_roundtrip` — proof verification for both leaves
  - `three_leaf_pads_to_four` — non-power-of-two padding, all proofs verify
  - `five_leaf_pads_to_eight` — 5→8 padding, proof length = 3
  - `determinism` — identical inputs produce identical roots
  - `empty_leaves_error` — empty input correctly rejected
  - `index_out_of_bounds_error` — invalid index correctly rejected
  - `parent_non_commutativity` — `merkle_parent(a,b) != merkle_parent(b,a)`
  - `power_of_two_no_padding` — exact power-of-two needs no padding
  - `large_tree_128_leaves` — 128-leaf tree with proof length = 7, spot-checked at 5 indices

4. ENTROPY SEMANTICS

[x] `verify_density()` is a heuristic density screen only. It is **not** a formal randomness certification or NIST SP 800-90B claim. This is a documented API behavior, not a security concession.

[x] `MIN_RAW_BYTES = 256` — inputs shorter than this are unconditionally rejected by `verify_density()`.

[x] `verify_density()` checks 5 heuristic gates: minimum length, bit bias (>0.99), byte max fraction (>0.95), bit transition rate (>0.98), and square-wave detection.

[x] `validate_entropy_distribution()` applies χ² test for 256 byte categories vs uniform when input ≥ 256 bytes. Shorter inputs pass without testing (avoid false positives on tiny buffers).

[x] `validate_entropy_full()` is density-first, then distribution: `verify_density()` then `validate_entropy_distribution()`.

[x] Entropy density test suite (6 tests):
  - `too_short_rejected` — below `MIN_RAW_BYTES` boundary
  - `exact_min_boundary_constant_rejected` — constant at exact boundary
  - `all_0xff_rejected` — single-value high byte
  - `square_wave_rejected` — 0x00/0xFF alternation
  - `pseudo_random_accepted` — well-distributed synthetic data passes
  - `exact_min_boundary_good_data_accepted` — good data at exact boundary passes

5. NOT APPLICABLE

| Item | Status | Rationale |
|---|---|---|
| `zeroize` | Not applicable | No secret material handled by this crate |
| `subtle` | Not applicable | No secret comparisons performed by this crate |
| `SECURITY-CONCESSION` tags | Not applicable | No security concessions; the entropy heuristic is a documented API behavior |
| Constant-time operations | Not applicable | No secret-dependent branching or comparison |

6. TEST COVERAGE

[x] 23 inline tests across 5 modules:
  - `hashing.rs` — 1 test (domain tag divergence)
  - `merkle.rs` — 10 tests (roundtrip, padding, determinism, errors, commutativity, large tree)
  - `entropy_density.rs` — 6 tests (boundaries, rejection, acceptance)
  - `entropy_stats.rs` — 3 tests (chi-square, distinct bytes, short skip)
  - `entropy_audit.rs` — 3 tests (density failure, zeros, smoke)

[x] All tests pass: `cargo test -p qssm-utils --all-features` — **23/23 passed**.

[x] Downstream integration tests pass: `cargo test -p qssm-integration` exercises this crate transitively through all frozen consumers.

7. FINAL CERTIFICATION

[x] No `unsafe` code in the entire crate (`#![forbid(unsafe_code)]`).
[x] All 3 public error enums are `#[non_exhaustive]` and use `thiserror`.
[x] No panics, no `todo!`, no `unimplemented!` in production code.
[x] No `unwrap()` or `expect()` in production code.
[x] No secret material handled — no zeroization needed.
[x] No secret comparisons — no constant-time operations needed.
[x] Domain separation is versioned and tested.
[x] Merkle tree has comprehensive roundtrip proof verification.
[x] Entropy heuristics have direct in-crate testing.
[x] 23 inline unit tests, all passing.
[x] No security concessions.

---

**This checklist was completed at v1.0.0 freeze. Any modification to production code
requires re-review of all applicable items and a version bump.**
