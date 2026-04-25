# LE Parameter Stability Report

**Version:** QSSM-PROOF-FROZEN-v2.0
**Date:** 2026-04-25

## Frozen Set B Parameters

| Parameter | Symbol | Value | Role |
|-----------|--------|-------|------|
| Ring dimension | N | 256 | Polynomial ring R_q = Z_q[X]/(X^N+1) |
| Modulus | Q | 8,380,417 | Ring modulus (Dilithium prime) |
| Witness bound | β | 8 | Max |r_i| for witness coefficients |
| Masking bound | η | 196,608 | Uniform y sampling range [-η, η] |
| Acceptance bound | γ | 199,680 | Verifier rejects if ||z||_∞ > γ |
| Challenge size | c_poly_size | 48 | Number of nonzero challenge coefficients |
| Challenge span | c_poly_span | 8 | Max |c_i| for challenge coefficients |

## Critical Derived Quantities

```
worst_case ||cr||_∞ = c_poly_size × c_poly_span × β = 48 × 8 × 8 = 3,072
gamma - eta = 199,680 - 196,608 = 3,072
support_containment_margin = gamma - eta - ||cr||_∞ = 3,072 - 3,072 = 0
required_eta_for_hvzk ≈ 185,786   (via [Lyu12] Lemma 3.2, ε = 2^{-128})
eta_headroom = eta - required_eta = 196,608 - 185,786 ≈ 10,822  (5.5%)
abort_probability = 0.0  (because gamma ≥ eta + ||cr||_∞)
```

## Finding 1: Support Containment Margin is EXACTLY ZERO

The acceptance bound γ = η + ||cr||_∞ with **zero slack**.

```
γ = 199,680 = 196,608 + 3,072 = η + ||cr||_∞
```

This means:
- The verifier accepts z if ||z||_∞ ≤ 199,680
- The worst-case shifted sample is |y_i + (cr)_i| ≤ η + ||cr||_∞ = 199,680
- The prover NEVER aborts (abort probability = 0)

**This is by design.** Zero-abort means the prover is deterministic given coins — no retry loop at the protocol level. This is good for constant-time implementation.

**But:** it means any perturbation to γ downward, or to ||cr||_∞ upward, immediately causes nonzero abort probability.

## Finding 2: Sensitivity to η Changes

| Perturbation | η value | HVZK met? | Margin to required | Abort probability |
|-------------|---------|-----------|-------------------|-------------------|
| η - 20% | 157,286 | NO (required ≈ 185,786) | -28,500 | 0 (but HVZK broken) |
| η - 10% | 176,947 | NO | -8,839 | 0 |
| η - 5.5% | 185,786 | BARELY | ~0 | 0 |
| η (current) | 196,608 | YES | +10,822 | 0 |
| η + 10% | 216,269 | YES | +30,483 | 0 (γ would need increase too) |

**Breakpoint:** η must be ≥ 185,786 for the HVZK template to hold. Current η exceeds this by 5.5%.

**Risk assessment:** A 5.5% headroom is **tight but deliberate**. The system is not fragile (η is a compile-time constant), but it means Set B was optimized for proof size rather than wide margins.

## Finding 3: Sensitivity to γ Changes

| Perturbation | γ value | gamma - eta - ||cr||_∞ | Abort probability |
|-------------|---------|----------------------|-------------------|
| γ - 1% | 197,683 | -1,997 | >0 (abort possible) |
| γ - 0.5% | 198,682 | -998 | >0 |
| γ (current) | 199,680 | 0 | 0 |
| γ + 1% | 201,677 | +1,997 | 0 |
| γ + 5% | 209,664 | +9,984 | 0 |

**Breakpoint:** Any decrease in γ below η + ||cr||_∞ = 199,680 causes nonzero abort probability.

**Risk assessment:** γ is a compile-time constant. It cannot drift. But if β, c_poly_size, or c_poly_span were ever increased, γ would need to increase proportionally.

## Finding 4: Sensitivity to β (Witness Bound)

| Perturbation | β | ||cr||_∞ | γ - η - ||cr||_∞ | HVZK required η |
|-------------|---|---------|------------------|-----------------|
| β = 4 | 4 | 1,536 | +1,536 | ~92,893 |
| β = 8 (current) | 8 | 3,072 | 0 | ~185,786 |
| β = 12 | 12 | 4,608 | -1,536 (BROKEN) | ~278,679 |
| β = 16 | 16 | 6,144 | -3,072 (BROKEN) | ~371,572 |

**β is the most dangerous parameter.** Doubling β from 8 to 16 would:
- Break support containment (abort probability > 0)
- Require η ≈ 371,572 (nearly 2× current) for HVZK
- Require γ ≈ 377,716

## Finding 5: Fiat-Shamir Challenge Space (The True Security Floor)

```
challenge_space_log2 = c_poly_size × log2(2 × c_poly_span + 1)
                     = 48 × log2(17)
                     ≈ 48 × 4.087
                     ≈ 196.2 bits

FS security = challenge_space_log2 - query_budget_log2
            = 196.2 - 64.0
            = 132.2 bits
```

This is the true security floor for the entire system. The only way to increase it:
- Increase c_poly_size (more challenge coefficients → larger proofs)
- Increase c_poly_span (wider coefficient range → larger ||cr||_∞ → needs more η,γ)

Both have cascading costs.

## Stability Summary

| Quantity | Current | Breakpoint | Margin | Risk |
|----------|---------|------------|--------|------|
| η vs HVZK requirement | 196,608 vs 185,786 | η < 185,786 | 5.5% | Low (compile-time) |
| γ vs support containment | 199,680 vs 199,680 | γ < 199,680 | **0%** | Low (compile-time, zero by design) |
| β impact on ||cr||_∞ | 3,072 | β > 8 breaks γ | none above | Medium (if ever changed) |
| FS security floor | 132.2 bits | <128 bits | 4.2 bits | Low |
| Overall epsilon_le | ~2^{-132.2} | ~2^{-128} | ~16× | Moderate |

## Conclusion

The LE parameters are **deliberately tight** — zero support-containment slack, 5.5% HVZK headroom, and a 132.2-bit FS floor. This is an optimization choice, not a fragility symptom.

The system is **stable under the frozen Set B constants** but has **no tolerance for parameter drift**. Any future parameter change (especially to β or c_poly_span) requires full re-derivation of η, γ, and the HVZK bound.

The true bottleneck is the Fiat-Shamir challenge space at 132.2 bits, which is the binding constraint on the total system security.
