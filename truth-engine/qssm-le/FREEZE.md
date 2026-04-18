# QSSM-LE v1.0.0 — FROZEN FOR INSTITUTIONAL USE

**Crate:** `qssm-le`
**Version:** 1.0.0
**Freeze date:** 2026-04-17
**License:** BUSL-1.1

---

## Scope

Layer 1 Lattice Engine for the QSSM zero-knowledge stack.

- **Ring:** $R_q = \mathbb{Z}_q[X]/(X^{256}+1)$, $q = 8\,380\,417$ (Dilithium/ML-DSA prime)
- **Protocol:** Module-LWE commitment $C = Ar + \mu$ with Lyubashevsky-style Fiat–Shamir + rejection sampling
- **Security model:** Witness-hiding proof (no witness on the wire), deterministic prover (BLAKE3-XOF CSPRNG)

## Freeze Contract

This crate is **frozen** at v1.0.0. The following invariants are locked:

1. **Wire format** — FS transcript layout (11 inputs, fixed order, fixed sizes), public binding tag byte (`0x01`), challenge polynomial derivation, and `LE_FS_PUBLIC_BINDING_LAYOUT_VERSION = 1` are immutable.
2. **Ring parameters** — $N = 256$, $Q = 8\,380\,417$, $\beta = 8$, $\eta = 2048$, $\gamma = 4096$, $C\_POLY\_SIZE = 64$, $C\_POLY\_SPAN = 16$ are immutable.
3. **Domain separators** — `DOMAIN_LE_FS`, `DST_LE_COMMIT`, `DST_MS_VERIFY`, `CROSS_PROTOCOL_BINDING_LABEL`, `DOMAIN_LE_CHALLENGE_POLY` are immutable.
4. **CRS expansion** — `BLAKE3(DOMAIN_LE ‖ "A_row" ‖ seed ‖ index_le)` with golden values `[7960407, 1320365, 6344295, 2508853]` for seed `[0x42; 32]`.
5. **Public API surface** — All `pub use` re-exports in `lib.rs` are stable. Additions are allowed; removals require a major version bump.

Any change that violates these invariants requires a new security review, a major version bump, and synchronized updates to `qssm-gadget`, `qssm-api`, and `qssm-local-verifier`.

## What Was Hardened for v1.0.0

Six improvements were implemented for the freeze:

### 1. Secret-type field encapsulation

`Witness.r` and `CommitmentRandomness.y` are now **private fields**. External callers use:
- `Witness::new(r)` / `Witness::coeffs()` (read-only)
- `CommitmentRandomness::new(y)` / `CommitmentRandomness::coeffs()` (read-only)

This prevents accidental downstream reads of secret material through public struct fields.

### 2. Construction-time validation on `PublicInstance`

`PublicInstance::digest_coeffs()` now returns `Result<Self, LeError>` and validates all 64 coefficients are ≤ `PUBLIC_DIGEST_COEFF_MAX` (0x0f) at construction time. Invalid inputs are rejected immediately — not deferred to `commit_mlwe` or `verify_lattice_algebraic`.

### 3. `PartialEq`/`Eq` gated behind `#[cfg(test)]`

`Witness`, `SecretKey`, `CommitmentRandomness`, and `ScrubbedPoly` now derive `PartialEq`/`Eq` only under `#[cfg(test)]`. Non-constant-time comparisons are **physically absent from production binaries**.

### 4. `Clone` removed from secret types

`Clone` is removed from `Witness` and `CommitmentRandomness` in production builds. (`ScrubbedPoly` retains `Clone` only under `#[cfg(test)]`.) This eliminates the risk class of cloned-and-forgotten copies that bypass `ZeroizeOnDrop`.

### 5. CT assembly verification

`scripts/verify_ct_asm.py` was run against the release build. Result: **PASSED** — `ct_reject_if_above_gamma` contains zero conditional branch (`jcc`) instructions in the emitted x86-64 assembly. The triple anti-optimization barrier (`#[inline(never)]` + `dyn Fn` dispatch + `black_box`) survives all LLVM optimization passes.

### 6. Formal acceptance probability documentation

The acceptance probability analysis is now documented in `SECURITY_CHECKLIST.md` §11 with:
- Worst-case bound: $\eta + \|c\|_1 \cdot \beta = 10\,240 \gg \gamma = 4096$
- Empirical: >99% acceptance for zero witnesses, >50% for maximal-norm witnesses
- Safety margin: `MAX_PROVER_ATTEMPTS = 65,536` provides $> 2^{128}$ safety against `ProverAborted`

## Verification Evidence

| Check | Result |
|-------|--------|
| `cargo test -p qssm-le` | **32/32 passed** (6 internal + 10 adversarial + 2 cross-domain + 13 lab + 1 doctest) |
| `cargo check` on 8 downstream crates | **Clean** (qssm-gadget, qssm-api, qssm-proofs, qssm-integration, zk-examples, mssq-batcher, p2p-net, qssm-desktop) |
| `verify_ct_asm.py` | **PASSED** — zero jcc in `ct_reject_if_above_gamma` |
| `#![forbid(unsafe_code)]` | **7/7 source files** |
| `SECURITY_CHECKLIST.md` | **Rev 5 — all boxes checked** |
| Fuzz harness | Structured 3424-byte verifier fuzzing (panic safety + rejection correctness) |

## Security Concessions (documented and accepted)

1. **CRS modular bias** — `u32 % Q` gives ~0.098% bias. Acceptable for transparent CRS.
2. **Nonce sampling bias** — `u32 % 4097` gives ~$6 \times 10^{-6}$% bias. Negligible.
3. **Challenge coefficient bias** — `u32 % 33` gives ~$10^{-9}$ bias. Negligible.
4. **`Blake3Rng` OutputReader** — Opaque, cannot be zeroized. Acceptable: derived value, short-lived, streaming state only.
5. **`ScrubbedPoly::as_public()` temporaries** — Stack temporaries not zeroized. Acceptable: same frame, overwritten by subsequent ops.

All concessions are tagged with `// SECURITY-CONCESSION` in source and cross-referenced in `SECURITY_CHECKLIST.md`.

## Dependencies (pinned at freeze)

| Crate | Version | Purpose |
|-------|---------|---------|
| `blake3` | workspace | Hash, XOF, domain separation |
| `qssm-utils` | workspace | `hash_domain`, `DOMAIN_LE`, `LE_FS_PUBLIC_BINDING_LAYOUT_VERSION` |
| `rand` | workspace | `RngCore` trait |
| `thiserror` | workspace | `LeError` derive |
| `subtle` | 2.6 | `ConstantTimeEq`, `ConstantTimeLess`, `Choice` |
| `zeroize` | 1.8 (features: derive) | `Zeroize`, `ZeroizeOnDrop` |

## File Inventory

```
src/
  lib.rs                  — Facade, prove_arithmetic, Blake3Rng, re-exports
  crs.rs                  — VerifyingKey, CRS expansion
  error.rs                — LeError (non_exhaustive)
  algebra/
    mod.rs                — Module declarations
    ntt.rs                — Length-512 NTT, negacyclic_mul, OnceLock omega
    ring.rs               — RqPoly, ScrubbedPoly, encode, short_vec_to_rq
  protocol/
    mod.rs                — Module declarations
    params.rs             — N, Q, BETA, ETA, GAMMA, etc.
    commit.rs             — PublicBinding, PublicInstance, Witness, CommitmentRandomness,
                            Commitment, LatticeProof, commit_mlwe, prove_with_witness,
                            verify_lattice_algebraic, gamma_bound_scan, ct_reject,
                            challenge_poly, FS transcript
unit_tests/
  adversarial_lattice.rs  — 10 adversarial tests
  cross_domain.rs         — 2 cross-engine domain separation tests
  lab_tests.rs            — 13 functional tests
fuzz/
  fuzz_targets/
    verify_lattice.rs     — Structured verifier fuzz target (3424 bytes)
SECURITY_CHECKLIST.md     — Rev 5, all items checked
FREEZE.md                 — This file
README.md                 — Internal crate notice
Cargo.toml                — v1.0.0
```

---

**This crate is frozen. Do not modify without a security review.**
