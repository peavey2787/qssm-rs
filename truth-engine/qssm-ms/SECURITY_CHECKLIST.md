QSSM-MS "BANK-GRADE" PRODUCTION READINESS CHECKLIST

**Scope:** Layer 2 — Mirror-Shift Engine (`truth-engine/qssm-ms`)
**Protocol:** 128-leaf position-aware Merkle tree, BLAKE3 domain-separated hashing, wrapping u64 rotation, Fiat-Shamir binding transcript
**Parameters:** 128 leaves, depth 7, nonce range [0,255], ~291-byte proof body, `DOMAIN_MS` separator
**Date:** 2026-04-18 (rev 1 — v1.0.0 freeze)

---

**CONTRACT:** Any change that violates or bypasses an item in this checklist
requires a new security review and version bump. Every concession is tagged with
`// SECURITY-CONCESSION` in the source and referenced here with its file location.
Grep `SECURITY-CONCESSION` to audit all compromises.

---

Explicitly confirm each item.

1. PUBLIC SURFACE & BOUNDARY SAFETY

Public API Exposure

[x] `#![forbid(unsafe_code)]` on `lib.rs`. No `unsafe` blocks possible in the crate.

[x] All internal modules are private (`mod commitment`, `mod core`, `mod error`, `mod transcript` in `lib.rs`). Sub-modules (`commitment::leaves`, `commitment::tree`, `core`) are `pub(crate)`.

[x] Public API is strictly the `pub use` re-exports in `lib.rs`: `Root`, `GhostMirrorProof`, `Salts`, `MsError`, `commit`, `prove`, `verify`, and `MERKLE_PATH_LEN` (const). No internal types are directly importable from outside.

[x] `Root` inner field is private. External callers use `Root::new(bytes)` and `Root::as_bytes()`. No field mutation possible.

[x] `GhostMirrorProof` — all 6 fields are `pub(crate)`. External callers use `GhostMirrorProof::new()` (validates inputs) and 6 read-only accessors: `n()`, `k()`, `bit_at_k()`, `opened_salt()`, `path()`, `challenge()`.

[x] `Salts` inner field is `pub(crate)`. External callers use `Index<usize>` and `get()`. No `Clone` or `Copy` — prevents unmanaged copies that bypass `ZeroizeOnDrop`.

[x] `GhostMirrorProof::new()` validates all fields at construction: `bit_at_k ∈ {0,1}`, `k ≤ 63`, `path.len() == 7`. Returns `Err(MsError::InvalidProofField)` for invalid inputs.

Error Handling

[x] All failures return typed `MsError` — no panics reachable from any exported path. Variants: `NoValidRotation`, `InvalidProofField(&'static str)`, `Merkle(MerkleError)`.

[x] `InvalidProofField` carries only a `&'static str` message — no secret material in errors. `NoValidRotation` and `Merkle` are unit/transparent variants with no data fields.

[x] No `unwrap()` or `expect()` in any production path (`lib.rs`, `core.rs`, `transcript.rs`, `commitment/leaves.rs`, `commitment/tree.rs`).

2. MERKLE TREE CORRECTNESS

[x] 128-leaf position-aware Merkle tree via `qssm_utils::PositionAwareTree`. Tree depth = 7 (`log2(128)`). Leaf index = `2 * k + bit_at_k` where `k ∈ [0,63]`, `bit_at_k ∈ {0,1}`.

[x] Leaf construction binds position, bit value, salt, and binding entropy: `BLAKE3(DOMAIN_MS ‖ "leaf" ‖ k ‖ bit ‖ salt ‖ binding_ent)`. — Evidence: `ms_leaf()` in `leaves.rs`.

[x] Salt derivation is deterministic from seed: `BLAKE3(DOMAIN_MS ‖ "salt" ‖ seed ‖ i_le ‖ bit)` for all 128 leaves. — Evidence: `derive_salts()` in `leaves.rs`.

[x] Merkle path verification uses `qssm_utils::merkle_parent` for sibling pairing and checks `idx == 0` (exhausted all levels), `proof.len() == log2(width)`, and root equality. — Evidence: `verify_path_to_root()` in `tree.rs`.

3. FIAT-SHAMIR TRANSCRIPT & DOMAIN SEPARATION

Transcript Completeness

[x] FS hash binds all public inputs in fixed order:
  1. `DOMAIN_MS` = `"QSSM-MS-v1.0"` (domain separator)
  2. `b"fs_v2"` (version tag)
  3. `root` (32 bytes)
  4. `n` (1 byte — nonce)
  5. `k` (1 byte — bit position)
  6. `entropy` (32 bytes — binding entropy)
  7. `value` (8 bytes LE)
  8. `target` (8 bytes LE)
  9. `context` (variable length — purpose tag)
  10. `binding_context` (32 bytes)
— Evidence: `fs_challenge()` in `transcript.rs`.

Domain Separation

[x] All MS hashing uses `DOMAIN_MS` = `"QSSM-MS-v1.0"` via `hash_domain()`. Distinct from `DOMAIN_LE` = `"QSSM-LE-v1.0"`.

[x] Sub-operations further domain-separated: `"fs_v2"` (transcript), `"leaf"` (leaf construction), `"salt"` (salt derivation), `"rot_nonce"` (per-nonce rotation).

4. TIMING SIDE-CHANNEL SAFETY

Constant-Time Comparisons

[x] `verify_path_to_root()` — Merkle root comparison uses `subtle::ConstantTimeEq` (`acc.ct_eq(root).unwrap_u8() == 1`). Prevents timing oracle on root match. — Evidence: `tree.rs`.

[x] `verify()` — FS challenge comparison uses `subtle::ConstantTimeEq` (`expect_c.ct_eq(&proof.challenge).unwrap_u8() == 0`). Prevents timing oracle on challenge match. — Evidence: `lib.rs` verify function.

Not Constant-Time (by design)

[x] `highest_differing_bit()` — branching loop over bit positions. Acceptable: `k` is a public proof field, not secret. — Evidence: `core.rs`.

[x] `verify()` early returns on `bit_at_k`, `k` range, and value-bit check. Acceptable: these check public proof fields against public values.

Concession — `binding_rotation()` uses only the first 8 of 32 binding entropy bytes. The remaining 24 bytes are unused. Acceptable: the rotation is deterministic and public; entropy utilization does not affect security. — Code: `core.rs` line 6.

5. SECRET LIFECYCLE & MEMORY SAFETY

Zeroize / ZeroizeOnDrop

[x] `Salts` (`[[u8; 32]; 128]`, 4 KiB) — `Zeroize + ZeroizeOnDrop`. Scrubbed when dropped. No `Clone` or `Copy`. — Evidence: `leaves.rs` struct definition.

Debug Redaction

[x] `Salts` has manual `Debug` impl: prints `"Salts([REDACTED; 128])"`. Never leaks salt values to logs. — Test: `debug_redacts_secrets`.

[x] `GhostMirrorProof` has manual `Debug` impl that redacts `opened_salt` and `challenge` (prints `[REDACTED; 32]`). `n`, `k`, `bit_at_k` are public and printed normally. — Test: `debug_redacts_secrets`.

Test-Only Traits

[x] `GhostMirrorProof` derives `PartialEq`/`Eq` only under `#[cfg(test)]`. Non-constant-time comparison is absent from production binaries. `Clone` is unconditional (required by downstream `Proof` struct in zk-api). — Evidence: `lib.rs` struct definition.

Error Safety

[x] No secret material in any `MsError` variant. `InvalidProofField` carries only `&'static str`. `NoValidRotation` is a unit variant. `Merkle` wraps `MerkleError` (public tree errors only).

6. CROSSING PREDICATE CORRECTNESS

[x] `prove()` rejects `value <= target` immediately with `NoValidRotation`. — Evidence: `lib.rs` prove function.

[x] Rotation per nonce: `rot_for_nonce(r, n) = BLAKE3(DOMAIN_MS ‖ "rot_nonce" ‖ r_le ‖ n)` — full-width u64 tweak, not a narrow XOR. 256 trials (`n ∈ [0,255]`). — Evidence: `core.rs` `rot_for_nonce()`.

[x] Crossing check: `a' = value.wrapping_add(rot)`, `b' = target.wrapping_add(rot)`. Accept only if `a' > b'` AND `highest_differing_bit(a', b')` is well-defined. — Evidence: `lib.rs` prove and verify.

[x] Verifier re-derives `k` from rotated values and checks `highest_differing_bit(a', b') == Some(proof.k)`. Prevents `k`-substitution attacks.

[x] Verifier checks `((value >> proof.k) & 1) == proof.bit_at_k` — ensures the opened bit position matches the claimed value.

7. ADVERSARIAL TEST COVERAGE

Roundtrip Tests (9 original)

[x] `equal_values_no_proof` — `prove(42, 42, ...)` returns `NoValidRotation`.
[x] `value_not_greater_than_target` — `prove(50, 100, ...)` returns error.
[x] `verify_fails_when_values_do_not_satisfy_inequality` — reversed values fail verification.
[x] `verify_rejects_wrong_root` — tampered root fails verification.
[x] `verify_rejects_tampered_merkle_sibling` — bit-flipped path sibling fails.
[x] `verify_rejects_tampered_fs_challenge` — bit-flipped challenge fails.
[x] `verify_rejects_mutated_opening_fields` — flipped `bit_at_k` fails.
[x] `verify_fails_on_mismatched_binding_context` — different binding context fails.
[x] `worst_case_nonce_scan_still_finds_proof_when_relation_holds` — `prove(255, 0, ...)` succeeds.

Boundary Tests (5 new)

[x] `boundary_u64_max_vs_zero_may_exceed_nonce_budget` — documents nonce budget limitation for extreme values.
[x] `boundary_u64_max_vs_max_minus_one` — adjacent maximum values.
[x] `boundary_one_vs_zero` — minimum non-trivial inequality.
[x] `boundary_2pow63_vs_2pow63_minus_one` — sign-bit boundary.
[x] `boundary_2pow32_vs_zero` — 32-bit boundary.

Constructor Validation Tests (5 new)

[x] `constructor_rejects_bit_at_k_two` — `bit_at_k=2` → `InvalidProofField`.
[x] `constructor_rejects_k_64` — `k=64` → `InvalidProofField`.
[x] `constructor_rejects_path_len_zero` — empty path → `InvalidProofField`.
[x] `constructor_rejects_path_len_six` — short path → `InvalidProofField`.
[x] `constructor_accepts_valid_fields` — maximal valid inputs accepted.

Determinism & Replay Tests (4 new)

[x] `deterministic_commit` — same inputs → same root.
[x] `deterministic_prove` — same inputs → same proof fields.
[x] `cross_context_replay_rejected` — proof replayed under different purpose tag fails.
[x] `different_seeds_different_roots` — different seeds → different roots.

Salt & Debug Tests (2 new)

[x] `salt_uniqueness_all_128` — all 128 salts distinct.
[x] `debug_redacts_secrets` — `Debug` on proof and salts does not leak secret material.

Fuzz Coverage

[x] `verify_mirror_shift` fuzz target (`fuzz/fuzz_targets/verify_mirror_shift.rs`) — structured fuzzing of the verifier with arbitrary root, proof fields, values, binding entropy, purpose tag, and binding context. Minimum input: 397 bytes. Covers: panic safety, rejection correctness, no false accepts.

8. PARAMETER SAFETY

[x] 128 leaves — `2 × 64` (one leaf per bit position × {0, 1}).
[x] Tree depth 7 — `log2(128)`.
[x] Nonce range `[0, 255]` — 256 rotation trials per proof attempt.
[x] `MERKLE_PATH_LEN = 7` — enforced at construction and implicitly at verification.
[x] Salt size: 32 bytes per leaf (BLAKE3 output width).
[x] All domain separator strings versioned (`"v1.0"`, `"v2"`).

9. FINAL CERTIFICATION

[x] No `unsafe` code in the crate (`#![forbid(unsafe_code)]`)
[x] All internal modules private — facade re-exports only
[x] All proof fields private — constructor validates, accessors read
[x] `Salts` private inner — `Zeroize + ZeroizeOnDrop`, no `Clone`/`Copy`
[x] `Root` private inner — `new()`/`as_bytes()` only
[x] `PartialEq`/`Eq` on `GhostMirrorProof` gated behind `#[cfg(test)]`
[x] All FS transcript inputs domain-separated and versioned
[x] CT comparisons in Merkle root check and challenge check (`subtle::ConstantTimeEq`)
[x] All `Debug` impls on secret-carrying types redacted (`Salts`, `GhostMirrorProof`)
[x] All error variants free of secret material
[x] 25 tests passing (9 original + 16 hardening)
[x] 6 downstream crates compile clean
[x] Fuzz harness covers verifier attack surface
[x] All concessions documented

All boxes checked — qssm-ms v1.0.0 Layer 2 is bank-grade and frozen for institutional use.
