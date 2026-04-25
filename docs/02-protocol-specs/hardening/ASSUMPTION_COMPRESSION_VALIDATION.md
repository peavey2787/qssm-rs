# Assumption Compression Validation

**Version:** QSSM-PROOF-FROZEN-v2.0
**Date:** 2026-04-25

## Claim Under Validation

The previous analysis claimed:

> "The minimal assumption set is ROM alone. A1 + A2 + A4 compress to ROM + verifiable parameter conditions."

This document validates whether that claim is **mathematically precise** or **heuristic framing**.

## Rigorous Decomposition

### A1 (epsilon_ms_hash_binding) → CR(Blake3)

**Claim:** A1 is implied by collision resistance of Blake3 in the ROM.

**Validation: MATHEMATICALLY VALID.**

The MS-1 step replaces real commitment handling with a boundary-consistent abstraction. Any distinguisher that detects this replacement must find either:
- A collision in the statement digest (Blake3)
- A second preimage in the value commitment

In the ROM, Blake3 collision resistance gives CR advantage ≤ Q_H² / 2^{257}. This IS a standard model property — CR does not require programmability.

**Precision: A1 needs collision resistance, which is WEAKER than ROM.** A1 survives in the standard model. Compressing it into "ROM" is conservative (safe but imprecise). The precise statement is A1 = CR(Blake3).

### A2 (epsilon_ms_rom_programmability) → ROM

**Claim:** A2 is implied by the ROM.

**Validation: MATHEMATICALLY VALID.**

A2 IS programmable ROM. It's definitional — the ability to program hash outputs at chosen points is exactly what the ROM gives you. In the standard model, no hash function has this property.

**Precision: A2 = ROM. This is exact.**

### A4 (epsilon_le) → ROM + parameter condition?

**Claim:** A4 decomposes into ROM (Fiat-Shamir) + parameter condition (rejection sampling).

**Validation: PARTIALLY VALID. There is a subtle hidden dependency.**

The LE HVZK argument has three sub-components:

**Sub-component 1: Rejection sampling statistical distance.**
This is purely information-theoretic. It depends on η, γ, β, c_poly_size, c_poly_span. It does not require ROM, lattice hardness, or any computational assumption. It is a verifiable mathematical inequality:

```
η ≥ 11 · ||cr||_∞ · √(ln(2N/ε)/π)
γ ≥ η + ||cr||_∞
```

**Verdict: Parameter condition. Not an assumption.**

**Sub-component 2: Fiat-Shamir simulation.**
The LE simulator programs `fs_challenge_bytes(...)` to return a chosen challenge seed. This requires programmability.

**Verdict: ROM. Same as A2.**

**Sub-component 3: Commitment indistinguishability.**
HERE IS THE HIDDEN DEPENDENCY.

The LE simulator produces a commitment C = A·r_sim + μ where r_sim is sampled independently (not the real witness). For the simulated transcript to be indistinguishable from the real transcript, the distinguisher must not be able to tell that C was produced with r_sim instead of the real witness r.

In the ROM, this is handled by the FS programming — the verifier only sees (C, t, z, challenge_seed), and the algebraic relation A·z = t + c·(C - μ) is satisfied by construction. The commitment C looks uniformly random in the ROM because the hash is independent.

**But in the standard model,** if the distinguisher could compute C from the verifying key and public instance, and could tell whether C = A·r + μ for a short r vs C = A·r_sim + μ for a different short r_sim, the simulation breaks. This is the **decisional module-LWE** problem.

**Verdict: The commitment indistinguishability sub-step implicitly requires that decisional module-LWE is hard, OR that the ROM hides the commitment structure.**

### The Hidden Computational Assumption

In the ROM, the commitment indistinguishability is free because the hash function makes everything look random. The simulator can produce any C and the ROM will supply consistent challenges.

But if we remove the ROM and ask "what computational assumption does A4 actually rest on?", the answer includes:

```
A4 (standard model) = rejection-sampling parameter condition
                     + Fiat-Shamir (needs ROM or CRS)
                     + decisional module-LWE (commitment hiding)
```

The module-LWE assumption is NOT needed for the ZK proof AS STATED (which is in the ROM). But it IS implicitly needed if you tried to instantiate the ZK theorem in the standard model.

## Revised Compression Statement

### In the ROM (the actual theorem statement):

```
A1 + A2 + A4 = CR(Blake3) + ROM + (ROM + parameter condition)
             = CR(Blake3) + ROM + parameter condition
```

Since CR is implied by ROM:

```
= ROM + parameter condition
```

**This compression IS mathematically valid in the ROM.**

### In the standard model (hypothetical):

```
A1 + A2 + A4 = CR(Blake3) + ??? + (parameter condition + ??? + d-MLWE)
```

Where ??? means "no known instantiation" for the programmability requirement.

**The compression to "ROM + parameters" is NOT valid in the standard model** because there is no standard-model replacement for programmability, and commitment hiding would need d-MLWE.

## Verdict

| Claim | Valid? | Caveat |
|-------|--------|--------|
| A1 + A2 compress to ROM | YES (A1 is even weaker: just CR) | A1 could be stated as standard-model CR |
| A4 decomposes to ROM + parameters | YES in ROM | Standard-model version would need d-MLWE |
| "ROM + parameters" is the minimal set | YES for the theorem as stated | The ROM is doing more work than just "programmability" — it also hides commitment structure |
| No hidden computational assumption in the ZK proof | YES under ROM | d-MLWE is hidden behind the ROM curtain |

## What This Means for Publishability

The theorem statement "QSSM is ZK in the ROM under parameter conditions" is **mathematically precise**.

The informal claim "no computational assumptions beyond ROM" is **true but subtly misleading**. The ROM is hiding the d-MLWE requirement that would appear in a standard-model instantiation.

**Honest framing for a paper:**

> Under the programmable Random Oracle Model and the frozen Set B parameter conditions (η ≥ 185,786; γ ≥ η + ||cr||_∞; challenge space ≥ 2^{132.2}), the composed QSSM protocol is simulation-based zero-knowledge with explicit additive bound epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le. The ROM simultaneously provides collision resistance for commitment binding, programmability for Fiat-Shamir simulation, and computational hiding for the LE commitment scheme.

This is the precise statement. It does not overclaim "no computational assumptions" — it honestly attributes all three security services to the ROM.
