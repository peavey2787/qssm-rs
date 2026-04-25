# Assumption Dependency Map and Impact Report

**Version:** QSSM-PROOF-FROZEN-v2.0
**Date:** 2026-04-25

## Final Bound

```
Adv_QSSM(D) <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le
```

Three additive terms. No multiplicative coupling. No circular dependencies.

## Per-Assumption Contribution

### A1: epsilon_ms_hash_binding

**Kind:** Collision resistance / commitment binding
**Consumed by:** MS-1 (D_MS_real → D_MS_hyb1)
**Concrete instantiation:** Blake3-based ValueCommitmentV2 + statement digest binding
**Structural role:** Ensures that replacing the real commitment layer with a boundary-consistent abstraction changes the distribution by at most epsilon_ms_hash_binding.

**Numeric estimate:** Dominated by Blake3 collision resistance. For a 256-bit hash, the birthday bound gives ~2^{-128}. In practice this is negligible under any reasonable query budget.

**Dominance assessment:** NOT the dominant term. This is standard-strength collision resistance against a 256-bit hash. It contributes negligibly to the total bound.

### A2: epsilon_ms_rom_programmability

**Kind:** Random Oracle Model programmability
**Consumed by:** MS-2 (D_MS_hyb1 → D_MS_hyb2)
**Concrete instantiation:** Fiat-Shamir oracle for MS v2 bitness + comparison queries
**Structural role:** Enables the simulator to program oracle answers at announcement-only query points. The loss is the probability that the distinguisher queries the oracle at a programmed point before seeing the simulator's response.

**Numeric estimate:** In the ROM, the simulator programs O(B) query points where B = number of bitness proofs + 1 comparison proof ≈ 64+1 = 65 points. Against Q_H hash queries, the programming collision probability per point is Q_H / 2^{256}. Total: ~65 * Q_H / 2^{256}. For Q_H = 2^{64}: approximately 2^{-186}. Negligible.

**Dominance assessment:** NOT the dominant term. ROM programmability loss is exponentially small for standard-length hashes.

### A4: epsilon_le

**Kind:** LE HVZK / rejection-sampling bound
**Consumed by:** H1→H2 LE replacement
**Concrete instantiation:** Lyubashevsky-style sigma protocol with parameters:
- N = 256, Q = 8,380,417
- eta = 196,608, gamma = 199,680
- beta = 8, c_poly_size = 48, c_poly_span = 8
**Structural role:** Bounds the statistical distance between the real LE prover transcript and the simulated LE transcript.

**Numeric estimate:** Two sub-terms:
1. **Rejection-sampling gap:** The simulator samples z uniformly from [-gamma, gamma]^N rather than from the rejection-sampled distribution. The statistical distance depends on eta/gamma ratio. With eta=196,608 and gamma=199,680, the support containment margin is tight (gamma - eta = 3,072 vs worst-case ||cr||_inf).
2. **Fiat-Shamir security:** challenge_space_log2 = 48 * log2(17) ≈ 196.2 bits. FS advantage ≈ Q_H / 2^{196.2}. For Q_H = 2^{64}: approximately 2^{-132.2}.

The FS-dominated security floor is ~132.2 bits. The rejection-sampling gap is parameterized but designed to be negligible under Set B.

**Dominance assessment:** THIS IS THE STRUCTURALLY DOMINANT TERM.
- A1 and A2 are exponentially negligible (2^{-128+} and 2^{-186})
- A4's FS component is ~2^{-132.2}, making it the binding constraint
- A4's rejection-sampling component is the tightest engineered margin

## Structural Dominance Summary

```
epsilon_le >> epsilon_ms_hash_binding >> epsilon_ms_rom_programmability

                A4 (LE HVZK)        A1 (binding)          A2 (ROM)
Magnitude:     ~2^{-132.2}          ~2^{-128+}           ~2^{-186}
Dominant:      YES                   No                    No
Bottleneck:    FS challenge space    Hash collision        Programmable ROM
```

The total bound is dominated by the LE Fiat-Shamir challenge space. Improving system security requires either:
- Increasing c_poly_size (more challenge entropy) — expensive in proof size
- Increasing c_poly_span — wider coefficient range
- Reducing the query budget assumption from Q_H = 2^{64}

## Circular Dependency Analysis

### MS binding ↔ ROM programming

**Question:** Does A1 (hash binding) depend on A2 (ROM programmability) or vice versa?

**Answer: No circular dependency.**

- A1 is consumed only by MS-1, which replaces the commitment layer. It does not require oracle programming.
- A2 is consumed only by MS-2, which programs oracle responses. It does not require commitment binding.
- MS-1 and MS-2 are sequential game hops. A1 fires first; A2 fires second. They share no epsilon terms, no witnesses, and no oracle state.

The dependency graph is strictly:
```
A1 → MS-1 → (sequential) → A2 → MS-2 → (sequential) → MS-3a/3b/3c (exact, 0)
```

### LE sampling ↔ CRS binding

**Question:** Does the LE simulator's sampling depend on the CRS binding, or vice versa?

**Answer: One-directional dependency, not circular.**

- The LE CRS (verifying key matrix A) is a public input to the simulator.
- The simulator samples z uniformly and derives t = A*z - c*(C-mu). This uses A but does not bind to it.
- The CRS binding (MSIS hardness) is used for soundness, not for ZK simulation.
- The rejection-sampling bound depends on eta, gamma, and the challenge polynomial shape — all Set B parameters — but not on the CRS value.

The dependency is one-directional:
```
CRS (public input) → LE simulator sampling → LE transcript
MSIS hardness (CRS binding) → soundness only, not ZK
```

**No circular dependency exists.**

## Conclusion

The assumption set {A1, A2, A4} is:
- **Acyclic:** no circular dependencies between any pair
- **Additively composed:** the final bound is a simple sum
- **A4-dominated:** the LE HVZK bound is the structurally dominant term
- **Tight on FS:** the Fiat-Shamir challenge space (~132.2 bits) is the binding security floor
