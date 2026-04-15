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
- `C_SPAN = 16` (challenge space size = `2*C_SPAN+1 = 33`)
- Message embedding cap: `MAX_MESSAGE = 2^30`

Important implementation fact (`commit.rs`):

- Commitment is `C = A*r + mu(m)` with **no additive error term** `e`.
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

Security is therefore **not** well captured by "RLWE 128-bit" style claims. The realistic security posture is constrained by:

- small-to-mid ring dimension (`N=256`),
- rank-1 algebra,
- no explicit LWE error in commitment relation,
- and a small Fiat-Shamir scalar challenge space (`33` values).

## 1.3 Conservative concrete bit-security result

Given the above, a conservative estimate for the current production claimable security is:

- **Estimated concrete security: improved under the current `N=256` setting, but still not a defensible 128-bit claim under current protocol assumptions.**

This audit cannot justify a 100+ bit claim for the current parameterization and protocol shape.

---

## 2) Soundness Error Check (Engine B 7-step path -> Engine A)

The integrated statement has three distinct error channels:

1. **Hash/Merkle cryptographic failure (BLAKE3):** roughly `<= 2^-256` scale per collision-like event; depth-7 union bound is still negligible (`~7 * 2^-256`).
2. **Lift/compression loss into Engine A message limb (`MAX_MESSAGE = 2^30`):** if a 256-bit digest is reduced to a 30-bit limb, collision channel is on the order of `2^-30` for random forgery attempts.
3. **Sigma/FS protocol soundness term from challenge size 33:** base challenge-space term is approximately `1/33 ~= 2^-5.04` per attempt in classic sigma-protocol style accounting.

### Requested question: "probability forged Engine B proof satisfies Engine A commitment due to small degree N=256"

`N=256` improves lattice hardness margins; it is still **not** the dominant direct probability term for Merkle/hash forgery.

The dominant concrete soundness bottlenecks in the current integrated path are:

- challenge space size (`33`),
- and 30-bit message compression if used as the only binding carrier.

So the practical forged-accept risk is **not** driven by BLAKE3 (too strong), but by protocol-level binding/challenge choices. In conservative engineering terms, this is not near a 128-bit soundness target.

---

## 3) Critical Threshold Recommendation (Target >= 128-bit)

If target is 128-bit-class security, moving to `N=256` is the correct minimum-direction threshold.

Recommended minimum direction:

- **`N = 256`** (minimum now applied), with estimator-backed tuning still required.
- Use an NTT-friendly prime with `2N | (q-1)`:
  - example candidate: `q = 8,380,417` for `N=256` (industry-familiar NTT prime class).
- Increase structural rank (avoid rank-1 only), and re-check with lattice estimator tooling.
- Expand effective challenge soundness (do not rely on a 33-point scalar challenge for final security claims without amplification or redesign).
- Avoid compressing the sole cross-engine binding to 30 bits; bind more digest material.

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

- **Go (Production 128-bit security claims):** NO  
  Current parameter/protocol combination does not support a defensible 128-bit concrete security claim.

Required before production-grade "128-bit secure" claims:

1. Keep upgraded parameter regime (`N=256`) and complete estimator-backed tuning.
2. Strengthen transcript/challenge soundness strategy.
3. Strengthen Engine B -> Engine A binding width (avoid 30-bit bottleneck).
4. Perform formal external cryptographic review of exact instantiated scheme.

---

## Executive Summary

Current `qssm-le` settings now use `N=256`, but the concrete security margin is still not yet a finalized 128-bit-class claim without further protocol hardening.  
The architecture is **No-Go for production security claims** in its present form, and **Go for R&D/prototyping**.

