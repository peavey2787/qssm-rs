# External Reviewer Simulation

**Version:** QSSM-PROOF-FROZEN-v2.0
**Date:** 2026-04-25

A skeptical cryptographer reviews the QSSM ZK theorem. These are the top 5 attack points they would raise, ranked by severity.

---

## Critique 1: "Your LE HVZK bound is not a proven theorem — it's a parameterized template"

**Severity:** HIGH

**The attack:** A4 (epsilon_le) is stated as a parameterized proof obligation tied to specific Set B constants (eta=196,608, gamma=199,680, beta=8, c_poly_size=48, c_poly_span=8). It is not derived from an externally published, peer-reviewed HVZK theorem for these exact parameters. The crate encodes the inequalities, but the actual proof that rejection sampling with these parameters yields negligible statistical distance is self-referential.

**Classification: REAL VULNERABILITY (moderate).**

The formal content is correct — the inequalities encode the standard Lyubashevsky HVZK conditions. But a reviewer would note that:
- No published paper proves HVZK for exactly these parameter choices.
- The rejection-sampling gap depends on the ratio eta/(eta + ||cr||_inf), which is tight (gamma - eta = 3,072 vs worst-case ||cr||_inf ≈ 3,072).
- A numerical error in the worst-case norm computation would silently invalidate the bound.

**Mitigation status:** PARTIALLY MITIGATED. The crate has parameter feasibility checks and CI floor tests. But there is no external estimator cross-validation for the HVZK gap specifically.

**Recommended action:** Commission an independent parameter validation (e.g., SageMath script) that confirms the rejection-sampling statistical distance for Set B.

---

## Critique 2: "The MS exact simulation argument is not machine-checked"

**Severity:** MEDIUM

**The attack:** MS-3a, MS-3b, and MS-3c claim zero advantage "by construction." But the construction is a pen-and-paper Schnorr reparameterization argument embedded in Rust string constants. No formal verifier (Lean, Coq, EasyCrypt) has checked the bijection `z ↔ alpha = z - c*w` in the context of the actual MS transcript structure with OR-proofs and clause sharing.

**Classification: MODELING ARTIFACT.**

The algebraic content is standard and well-understood (Schnorr simulation is textbook). The risk is not that the math is wrong, but that the encoding in the proof crate might not perfectly match the actual MS protocol implementation. Specifically:
- The OR-proof challenge-splitting equation `c0 + c1 = e` must be verified to be exactly what the code computes.
- The announcement-only query digest contract must be verified against the actual `qssm_ms` crate's hash inputs.

**Mitigation status:** PARTIALLY MITIGATED. The proof crate has adversarial tests that reject query digests hashing responses. But there is no end-to-end verified link between the `qssm_ms` implementation and the proof's premise contracts.

**Recommended action:** Add integration tests that extract the actual hash inputs from `qssm_ms::prove_predicate_only_v2` and verify they match the announcement-only contracts stated in the proof.

---

## Critique 3: "The composition argument relies entirely on the ROM"

**Severity:** MEDIUM

**The attack:** The MS↔LE independence claim holds under the ROM because domain-separated hashing produces independent outputs. In any non-ROM model, the seed derivation `hash("ms_label" || seed || ...)` and `hash("le_label" || seed || ...)` could exhibit correlation if the hash function has structural weaknesses (related-key attacks, internal state leakage).

**Classification: ALREADY MITIGATED (standard limitation).**

Every Fiat-Shamir-based composed ZK system has this dependency. Dilithium, Falcon, and every post-quantum signature scheme share it. The ROM is the accepted model for this class of protocols.

**Mitigation status:** FULLY MITIGATED within the standard model choice. The system is honest about its ROM dependency (explicitly stated in the theorem).

**Recommended action:** None beyond clearly stating the ROM scope in any publication.

---

## Critique 4: "The simulator's witness-independence is a code audit, not a formal proof"

**Severity:** MEDIUM-LOW

**The attack:** The witness-independence claim ("the global simulator never touches witness data") is verified by code-structure audit and runtime tests. But there is no type-level or information-flow guarantee. A future code change could accidentally thread a witness value through a public-input struct field, and the audit would not automatically catch it.

**Classification: REAL VULNERABILITY (low severity).**

The current code is correct — the simulator call chain was manually audited and tested. But the property is fragile: it depends on the simulator function signatures not changing in a witness-leaking way.

**Mitigation status:** PARTIALLY MITIGATED. The verification checklist checks for "forbidden inputs" in the simulator definition. But this is a runtime string check, not a compile-time guarantee.

**Recommended action:** Consider adding a `#[must_not_contain_witness]` marker trait or newtype wrapper that makes witness data structurally impossible to pass to the simulator. This would be a compile-time enforcement.

---

## Critique 5: "The binding term A1 is instantiated through Blake3, not a generic commitment scheme"

**Severity:** LOW

**The attack:** A1 is stated as "ValueCommitmentV2 and the statement digest are binding," but this is instantiated through Blake3 hashing rather than a generic Pedersen/lattice commitment with a provable binding reduction to a standard problem (DLP, SIS, etc.). A reviewer might object that Blake3 binding is heuristic rather than provably reducible.

**Classification: MODELING ARTIFACT (standard for hash-based commitments).**

Blake3 is a 256-bit hash with no known collision attacks. The binding property reduces to collision resistance, which is a standard assumption for hash functions. No practical system proves collision resistance from first principles — it is always an assumption about the specific hash function.

**Mitigation status:** FULLY MITIGATED within standard practice. The system explicitly names Blake3 as the instantiation and does not claim generic commitment binding.

**Recommended action:** In any publication, explicitly state that A1 is CR-based (collision resistance of Blake3) rather than algebraic binding. This is standard practice for hash-based commitments.

---

## Summary Table

| # | Critique | Classification | Severity | Mitigated? |
|---|----------|---------------|----------|------------|
| 1 | LE HVZK is parameterized, not externally proven | Real vulnerability | High | Partially |
| 2 | MS exact simulation not machine-checked | Modeling artifact | Medium | Partially |
| 3 | Composition relies on ROM | Already mitigated | Medium | Fully |
| 4 | Witness-independence is code audit only | Real vulnerability | Med-Low | Partially |
| 5 | A1 is hash-based, not algebraically binding | Modeling artifact | Low | Fully |

## What a Reviewer Would Recommend

1. Independent parameter validation for LE Set B (SageMath or similar)
2. Integration tests linking qssm_ms implementation to proof premise contracts
3. Consider a type-level witness isolation mechanism for the simulator
4. These are standard-quality improvements, not fundamental objections
