# Assumption Compression Attempt

**Version:** QSSM-PROOF-FROZEN-v2.0
**Date:** 2026-04-25

## Question

Can the assumption set {A1, A2, A4} be reduced? Can A1 + A2 be merged? Can the whole system be expressed in terms of a standard assumption family?

## Current Assumption Set

```
A1: epsilon_ms_hash_binding         — Blake3 collision resistance for MS commitments
A2: epsilon_ms_rom_programmability  — Programmable random oracle for MS Fiat-Shamir
A4: epsilon_le                      — LE HVZK bound (rejection sampling + FS in ROM)
```

## Compression Attempt 1: Merge A1 + A2 into "ROM"

**Idea:** Both A1 and A2 concern the hash function (Blake3). If we model Blake3 as a random oracle, then collision resistance is automatic (birthday bound). So A1 is implied by the ROM.

**Analysis:**

This works. In the ROM:
- Collision resistance is implied: CR advantage ≤ Q_H^2 / 2^{257} ≈ 2^{-129} for Q_H = 2^{64}.
- Programmability is a definitional property of the ROM.

So A1 and A2 collapse to a single assumption: **"Blake3 is modeled as a random oracle."**

**Result: A1 + A2 → ROM (single assumption).**

The merged bound becomes:
```
Adv_QSSM(D) <= epsilon_ROM_MS + epsilon_le
```
where epsilon_ROM_MS = epsilon_ms_hash_binding + epsilon_ms_rom_programmability, both implied by the ROM.

**Why the crate keeps them separate:** Separating A1 and A2 is a proof engineering choice, not a logical necessity. It makes the game-hopping structure cleaner (MS-1 uses binding, MS-2 uses programmability). If the proof were rewritten as a single ROM reduction, the two steps could merge into one.

**Publication recommendation:** State the theorem with "random oracle model for Blake3" as the single MS assumption. The internal decomposition into binding + programmability is a proof-internal detail.

## Compression Attempt 2: Merge A4 into ROM + LWE

**Idea:** A4 (LE HVZK) combines rejection sampling and Fiat-Shamir. Can it be stated purely as ROM + module-LWE?

**Analysis:**

Partially. The LE HVZK argument has two components:

1. **Rejection sampling:** This is information-theoretic. The statistical distance between the real (rejection-sampled) distribution and the simulated (uniform) distribution depends only on eta, gamma, and the challenge norm. It does NOT require the ROM or any computational assumption. It is a pure parameter condition.

2. **Fiat-Shamir:** The challenge derivation is modeled in the ROM, same as the MS component.

The module-LWE / module-SIS hardness is used for **soundness**, not for ZK simulation. The ZK simulator does not need to break LWE — it programs the oracle and samples freely.

So A4 decomposes into:
- ROM (for Fiat-Shamir) — same assumption class as A1+A2
- Parameter condition (for rejection sampling) — not a hardness assumption at all

**Result: A4 → ROM + parameter condition.**

## Compression Attempt 3: The Minimal Set

After compression:

```
Standard assumptions:
  1. ROM (random oracle model for Blake3)
     — implies A1 (collision resistance)
     — implies A2 (programmability)
     — implies A4's Fiat-Shamir component

Non-assumption conditions:
  2. LE Set B parameter condition
     — eta >= required_eta_for_hvzk
     — gamma >= eta + ||cr||_inf
     — These are concrete numerical inequalities, not hardness assumptions.
     — They are either true or false for the committed parameters.
```

**The minimal assumption set is: ROM alone.**

Everything else is either:
- Implied by the ROM (collision resistance, programmability, Fiat-Shamir security)
- A verifiable parameter condition (LE Set B inequalities)
- An algebraic identity (Schnorr reparameterization, true-clause characterization)

## Can A1 + A2 be fully merged in the proof artifact?

**Yes, but at a cost.**

The current game-hopping structure uses separate games for binding and programmability because it makes the proof modular. A merged proof would:
- Combine MS-1 and MS-2 into a single "switch to programmed simulator" step
- Lose the intermediate hybrid D_MS_hyb1
- Make the proof shorter but harder to audit at each step

**Recommendation:** Keep the decomposition in the code artifact for auditability. State the theorem in publications with "ROM" as the single MS assumption.

## Standard Assumption Family Classification

The QSSM ZK theorem reduces to:

```
ROM (random oracle model)
+ verifiable parameter conditions (LE Set B)
```

In standard terminology:
- **ROM** is a well-studied, widely-accepted model assumption.
- **Parameter conditions** are not assumptions — they are checkable facts.
- **No LWE/SIS assumption is needed for ZK** (only for soundness, which is a separate theorem).

This places the ZK theorem in the same assumption class as:
- Dilithium's ZK argument
- Any Fiat-Shamir-transformed Schnorr-style ZK proof
- Standard lattice-based sigma protocol ZK

## Publishability Assessment

```
Assumption class: ROM only (for ZK)
Novelty:         Composed MS + LE protocol with exact MS simulation lemmas
Standard:        Yes — same assumption class as Dilithium, Crystals-Dilithium
Overparameterized: No — the three named assumptions (A1, A2, A4) compress to ROM alone
```

The system is publishable as a ROM-model ZK theorem with an explicit parameter condition. The assumption set is not bespoke — it is exactly the standard family used by every Fiat-Shamir-based ZK protocol.

## Final Answer

**Can A1 + A2 be merged?** Yes. Both are implied by the ROM.

**Can the assumption set be reduced to a standard family?** Yes. The minimal set is ROM + parameter condition. No novel or bespoke assumptions remain.

**Is the system overparameterized?** No. The three named assumptions exist for proof engineering clarity, not because they represent distinct hardness classes.
