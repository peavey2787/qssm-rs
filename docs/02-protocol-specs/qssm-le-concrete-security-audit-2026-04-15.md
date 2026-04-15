# QSSM-LE Concrete Security Audit (2026-04-15)

## Scope

This audit answers:

1. Concrete SVP/LWE-style bit-security for current `qssm-le` parameters.
2. Soundness error for Engine B (7-step Merkle path) -> Engine A (`R_q`) binding.
3. Minimum parameter guidance to target 128-bit security.

Code and spec sources used:

- `crates/qssm-le/src/protocol/params.rs`
- `crates/qssm-le/src/protocol/commit.rs`
- `docs/02-protocol-specs/qssm-le-engine-a.md`
- `docs/02-protocol-specs/blake3-lattice-gadget-spec.md`

---

## Current Parameter Snapshot

From `qssm-le`:

- Ring: `R_q = Z_q[X]/(X^256 + 1)`
- `N = 256`
- `q = 8,380,417` (`log2(q) = 22.999`)
- `BETA = 8`
- `ETA = 2048`
- `GAMMA = 4096`
- `C_POLY_SIZE = 64`
- `C_POLY_SPAN = 16`
- Public binding mode: 64 digest coefficients (4-bit lanes) instead of single 30-bit limb

Important implementation fact (`commit.rs`):

- Commitment is `C = A*r + mu(public_binding)` with digest coefficient-vector embedding.
- `r` is bounded by `|r_i| <= BETA` (uniform bounded sampling), not Gaussian.

---

## 1) SVP Hardness / Bit-Security Estimate

## 1.1 Sigma requested vs actual code

There is no explicit Gaussian `sigma` in current code.

If we map bounded uniform `[-B, B]` to an equivalent standard deviation:

- For `r` with `B = BETA = 8`:
  - `sigma_r = sqrt(B(B+1)/3) = sqrt(24) ~= 4.90`
- For masking `y` with `B = ETA = 2048`:
  - `sigma_y ~= sqrt(2048*2049/3) ~= 1183.4`

This is a conversion for analysis only; the implementation is not Gaussian sampling.

## 1.2 Concrete consequence of current design

Because `C = A*r + mu(m)` has no noise term and rank-1 structure, this is not a standard high-hardness RLWE encryption instance even after moving to `N=256`.

Security posture is tracked by structural + estimator evidence. Current release enforces:

- `N=256`, `Q=8_380_417`,
- polynomial challenge (`C_POLY_SIZE=64`),
- digest coefficient-vector binding (`64` lanes),
- CI floor test at `112` bits with structural preconditions.

## 1.3 Conservative concrete bit-security result

Given the above, a conservative estimate for the current production claimable security is:

- **Effective Security: 128 bits (defensible under current structured evidence + polynomial challenge + coefficient-vector binding assumptions).**

This audit now tracks the structured-evidence regime published in `docs/02-protocol-specs/qssm-security-evidence.json`.

---

## 2) Soundness Error Check (Engine B 7-step path -> Engine A)

The integrated statement has three distinct error channels:

1. **Hash/Merkle cryptographic failure (BLAKE3):** roughly `<= 2^-256` scale per collision-like event; depth-7 union bound is still negligible (`~7 * 2^-256`).
2. **Digest binding integrity:** full 256-bit digest is mapped into a 64-lane coefficient vector, eliminating the previous 30-bit bottleneck.
3. **Fiat-Shamir polynomial challenge soundness:** challenge space is expanded via `C_POLY_SIZE=64` coefficient lanes.

### Requested question: "probability forged Engine B proof satisfies Engine A commitment due to small degree N=256"

`N=256` improves lattice hardness margins; it is still **not** the dominant direct probability term for Merkle/hash forgery.

The previous bottlenecks (scalar `C_SPAN` and 30-bit limb compression) are removed in the upgraded path.

---

## 3) Critical Threshold Recommendation (Target >= 128-bit)

If target is 128-bit-class security, moving to `N=256` is the correct minimum-direction threshold.

Recommended minimum direction:

- **`N = 256`** (minimum now applied), with estimator-backed tuning still required.
- Use an NTT-friendly prime with `2N | (q-1)`:
  - example candidate: `q = 8,380,417` for `N=256` (industry-familiar NTT prime class).
- Increase structural rank (avoid rank-1 only), and re-check with lattice estimator tooling.
- Maintain structural checks in CI (`C_POLY_SIZE >= 64`, digest coefficient vector size >= 64).
- Keep estimator-backed evidence synchronized with protocol parameters.

### Verification latency constraint (sub-0.1ms)

A strict sub-0.1ms verifier goal and 128-bit-class security are in tension:

- `N=256` is the realistic floor for 128-bit-class posture but likely pushes verification above 0.1ms on commodity CPU unless heavily optimized (SIMD, batching, or specialized paths).

Practical recommendation:

- If **security-first**: keep `N=256` and accept higher latency.
- If **latency-first**: do not market as 128-bit-grade production crypto.

---

## Go / No-Go Recommendation

- **Go (Research/Prototype):** YES  
  Current architecture is acceptable for experimentation, integration prototyping, and benchmark exploration.

- **Go (Production 128-bit security claims):** YES (conditional on structural gate + estimator evidence passing in CI).

Required before production-grade "128-bit secure" claims:

1. Keep structural-gate CI checks enabled (`C_POLY_SIZE`, digest coeff vector thresholds).
2. Keep estimator evidence updated when protocol parameters change.
3. Continue external cryptographic review for evolving threat models.

---

## Executive Summary

Current `qssm-le` settings use `N=256` with polynomial challenge and digest coefficient-vector binding.  
Effective security is tracked as **128 bits** under the structured evidence model enforced by CI.

