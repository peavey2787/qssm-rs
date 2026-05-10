QSSM-LOCAL-PROVER "BANK-GRADE" PRODUCTION READINESS CHECKLIST

**Scope:** Layer 4 — Deterministic Prove Pipeline (`truth-engine/qssm-local-prover`)
**Pipeline:** Predicates → MS commit → Truth binding → LE proof
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

[x] `#![forbid(unsafe_code)]` on the sole source module — `lib.rs`. No `unsafe` blocks possible in the crate.

[x] The crate exports exactly **one** public item: `pub fn prove(...)`. No public structs, enums, traits, type aliases, constants, or re-exports. All types in the `prove()` signature (`ProofContext`, `QssmTemplate`, `Proof`, `ZkError`) are owned by upstream crates (`qssm-api`, `qssm-templates`).

[x] The private function `derive_le_witness()` and the private constant `DOMAIN_EXTERNAL_ENTROPY` are not externally reachable.

[x] No `#[non_exhaustive]` annotations are needed — there are zero public structs or enums in this crate.

[x] No `subtle` dependency is needed — this crate performs no secret comparisons. All constant-time operations are delegated to `qssm-le` (which uses `subtle` for challenge comparison and norm checking) and `qssm-ms`.

Error Handling

[x] All failures in `prove()` return typed `ZkError` via `?` and `.map_err()`. No `unwrap()` or `expect()` in any production path. All `unwrap()`/`expect()` calls are exclusively inside `#[cfg(test)] mod tests`.

[x] No `panic!`, `todo!`, or `unimplemented!` macros in production code. Verification gate: `grep "panic!\|todo!\|unimplemented!" truth-engine/qssm-local-prover/src/lib.rs` returns zero production matches.

[x] No secret material (entropy seeds, witness coefficients, mask seeds, salt data) is ever included in any `ZkError` variant. Error variants carry only public metadata (`value`, `target`, upstream error sources).

[x] All zeroize calls (§3) are on the happy path. The crate has **no panic-based early exits** in production code — every fallible operation returns `Result` via `?`. There is no code path where a panic could bypass zeroization.

2. KEY SCHEDULE & DETERMINISTIC DERIVATION

Domain Separation

[x] Four unique, versioned domain tags separate all key-schedule derivations:
  - `DOMAIN_SDK_MS_SEED` — MS commitment salt seed
  - `DOMAIN_EXTERNAL_ENTROPY` = `"QSSM-SDK-EXTERNAL-ENTROPY-v1"` — external entropy derivation
  - `DOMAIN_SDK_LE_WITNESS` — LE witness coefficient derivation
  - `DOMAIN_SDK_LE_MASK` — LE Lyubashevsky masking seed

[x] All domain-separated derivations bind both `entropy_seed` and `binding_ctx`: `BLAKE3(domain ‖ entropy_seed ‖ binding_ctx)`. No derivation uses `entropy_seed` alone.

Determinism

[x] The crate generates **no internal randomness**. All entropy flows from the caller-provided `entropy_seed` parameter. No OS entropy, no hardware calls, no `rand::thread_rng()`, no `CryptoRng` construction.

[x] Two calls to `prove()` with identical arguments produce identical proofs. The doc-comment on `prove()` explicitly states this invariant.

[x] `derive_le_witness()` uses counter-mode domain separation (`chunk_idx` appended as LE bytes) to expand 32 bytes of seed into 256 witness coefficients. Deterministic and reproducible.

3. SECRET LIFETIME & ZEROIZATION

Zeroization is best-effort within Rust's compilation and optimization model; no guarantees against compiler reordering or elision. The `zeroize` crate uses volatile writes which provide strong practical assurance but not a formal hardware-level guarantee.

`entropy_seed` is passed by value as a stack array, not as a shared reference or heap allocation; zeroization is local to this frame.

All zeroize calls are on the happy path. Production code has no panic-based early exits — every fallible operation uses `?` / `.map_err()` and returns `Result`. There is no code path where a panic could bypass a zeroize call.

[x] `ms_seed` — derived via `hash_domain(DOMAIN_SDK_MS_SEED, ...)`, consumed by MS v2 commitment generation (`commit_value_v2` path), then zeroized before returning. Lifetime remains short and explicit in prover flow.

[x] `le_mask_seed` — derived at `lib.rs:L86` via `hash_domain(DOMAIN_SDK_LE_MASK, ...)`, consumed by `qssm_le::prove_arithmetic()` at `L89`, zeroized at `L92`. Lifetime: 6 lines.

[x] `entropy_seed` (local copy) — received as `mut` by-value parameter at `L42`, consumed for 4 domain-separated derivations (MS seed L49, external entropy L66, LE witness L83, LE mask seed L86), zeroized at `L93` before proof construction. Lifetime: entire function body.

[x] `r` array — local `[i32; 256]` witness buffer in `derive_le_witness()`, constructed at `L111`, populated in chunk loop `L112–L127`, copied into `Witness::new(r)` at `L130` (`[i32; N]` is `Copy` — `Witness::new` takes a copy, original remains on stack), zeroized at `L132`. Lifetime: function body.

[x] `Salts` (upstream, `qssm-ms`) — derives `Zeroize + ZeroizeOnDrop`. The 4 KiB salt buffer is scrubbed when `salts` drops at `prove()` return. No action needed in this crate.

[x] `Witness` (upstream, `qssm-le`) — derives `Zeroize + ZeroizeOnDrop`. The witness coefficients are scrubbed when `witness` drops. No action needed in this crate.

4. PREDICATE EVALUATION

[x] `template.verify_public_claim(claim)?` executes as the **first operation** in `prove()` (line L45), before any key material is derived. Defense-in-depth: invalid public claims fail fast without touching the key schedule.

[x] Predicate failures return `ZkError::PredicateFailed(...)` — no secret material is allocated or derived before this check.

5. TRUTH BINDING

[x] `TruthWitness::bind()` at `L71` anchors the MS root, binding context, MS proof metadata (`n`, `k`, `bit_at_k`, `challenge`), and external entropy into a single digest. This digest becomes the LE public instance, cryptographically linking the MS and LE proof layers.

[x] `tw.validate()` at `L77` is called immediately after construction — invalid truth witnesses are rejected before the LE proof is attempted. Failure returns `ZkError::TruthWitnessInvalid`.

[x] The `digest_coeff_vector` from `TruthWitness` is validated a second time by `PublicInstance::digest_coeffs()` at `L80`, which checks all 64 coefficients are ≤ `PUBLIC_DIGEST_COEFF_MAX`. Belt-and-suspenders validation.

6. PIPELINE ORDER

[x] The prove pipeline follows a strict, immutable order:
  1. Predicate check (`verify_public_claim`)
  2. Key schedule (`ms_seed`, `binding_entropy`)
  3. MS commit + prove
  4. Truth binding (`TruthWitness::bind` + `validate`)
  5. LE public instance + witness derivation
  6. LE prove (`prove_arithmetic`)
  7. Proof construction

[x] Each stage depends on outputs from the previous stage. Reordering would break the cryptographic binding chain.

7. ADVERSARIAL TEST COVERAGE (inline `#[cfg(test)]`)

Roundtrip Tests

[x] `prove_and_verify_round_trip` — full prove → verify cycle with valid inputs.
[x] `wire_round_trip_json` — prove → serialize → deserialize → verify cycle.
[x] `wire_format_forward_compat` — serialized bundle remains parseable, field values preserved.

Witness Tests

[x] `derive_le_witness_deterministic_and_bounded` — same inputs → same output, all coefficients in `[-BETA, BETA]`, correct length `N`.

Adversarial Verify Tests

[x] `tampered_ms_root_rejected` — bit-flipped MS root → `MsVerifyFailed`.
[x] `wrong_binding_context_rejected` — altered binding context → `MsVerifyFailed`.
[x] `tampered_external_entropy_rejected` — bit-flipped external entropy → LE or rebinding failure.
[x] `wrong_claim_rejected` — mismatched claim → `PredicateFailed`.
[x] `wrong_value_target_rejected` — swapped value/target → `MsVerifyFailed`.

Wire Format Rejection Tests

[x] `wire_rejects_bad_version` — version 99 → `UnsupportedVersion`.
[x] `wire_rejects_bad_hex` — invalid hex → `HexDecode`.
[x] `wire_rejects_wrong_length` — truncated root → `BadLength`.
[x] `wire_rejects_wrong_coeff_count` — wrong coefficient count → `BadCoeffCount`.
[x] `wire_rejects_unknown_fields` — extra JSON fields → deserialization error.

Injectivity & Preservation Tests

[x] `proof_bundle_from_proof_injective` — different entropy → different bundles.
[x] `proof_bundle_preserves_all_fields` — round-trip is lossless, no field drift.
[x] `proof_bundle_json_field_names_stable` — JSON field names match frozen schema.

8. INTEGRATION TEST COVERAGE

[x] 5 integration test files in `integration/` exercise `qssm_local_prover::prove`:
  - `test_roundtrip.rs` — full prove → verify pipeline
  - `test_negative.rs` — adversarial/negative path tests
  - `test_serialization.rs` — wire format round-trips
  - `test_entropy.rs` — determinism and entropy tests
  - `test_template_resolution.rs` — template resolution pipeline

9. CONSTANT-TIME & SIDE CHANNELS

[x] Not applicable to this crate. `qssm-local-prover` performs no secret comparisons and no norm checks on secret data. All constant-time operations are delegated to:
  - `qssm-le` — `subtle::ConstantTimeEq` for challenge comparison, `gamma_bound_scan()` for CT norm check
  - `qssm-ms` — internal CT operations on salt/commitment data

[x] The crate's role is pipeline orchestration — it passes secret material to downstream crates that handle CT guarantees, then zeroizes its local copies.

10. SECURITY CONCESSIONS (documented and accepted)

// SECURITY-CONCESSION: `h` loop variable in `derive_le_witness()` — `lib.rs` line L116. The 32-byte hash output `h` is loop-scoped and overwritten each of the 32 iterations. Not explicitly zeroized. Classified as accepted due to negligible residual risk: (1) `h` is a derived hash output, not a master secret or key; (2) it is overwritten by the next iteration's `hash_domain` call; (3) only the final iteration's `h` persists on the stack momentarily before the function returns and the frame is reclaimed.

11. FINAL CERTIFICATION

[x] No `unsafe` code in the entire crate (`#![forbid(unsafe_code)]`).
[x] Single public function (`pub fn prove`) — minimal attack surface.
[x] All four intermediate secrets explicitly zeroized (best-effort, volatile writes via `zeroize` crate).
[x] All upstream secret types (`Salts`, `Witness`) have `ZeroizeOnDrop`.
[x] No panics, no `todo!`, no `unimplemented!` in production code.
[x] No `unwrap()` or `expect()` in production code.
[x] Deterministic pipeline — no internal randomness.
[x] 17 inline unit tests + 5 integration test files.
[x] One documented security concession (`h` loop variable).

---

**This checklist was completed at v1.0.0 freeze. Any modification to production code
in `lib.rs` requires re-review of all applicable items and a version bump.**
