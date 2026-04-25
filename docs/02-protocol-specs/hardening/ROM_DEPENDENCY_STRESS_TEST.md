# ROM Dependency Stress Test

**Version:** QSSM-PROOF-FROZEN-v2.0
**Date:** 2026-04-25

## Question

What breaks if the Random Oracle Model is weakened or replaced?

## Method

Systematically remove ROM programmability and trace exactly which lemmas fail and why.

## Lemma-by-Lemma Impact Analysis

### MS-1 (hash binding): A1

**ROM dependency:** NONE.
MS-1 replaces witness-bound commitment handling with a boundary-consistent abstraction. This is a standard commitment-binding argument. It requires collision resistance of Blake3, not oracle programmability.

**Under ROM removal:** SURVIVES. This step works in the standard model assuming collision resistance.

### MS-2 (ROM programmability): A2

**ROM dependency:** FUNDAMENTAL.
MS-2 replaces real Fiat-Shamir challenge derivation with programmed oracle answers. The simulator needs to choose the oracle response at the query point `bitness_query_digest(statement_digest, bit_index, announcements)` and `comparison_query_digest(clause_announcements)` BEFORE the distinguisher queries those points.

**Under ROM removal:** FAILS COMPLETELY.
Without programmability, the simulator cannot set challenges to be consistent with pre-chosen announcements and responses. The Fiat-Shamir transform becomes non-simulatable in the standard model.

**Failure class: CATASTROPHIC for MS.**

### MS-3a (exact bitness simulation)

**ROM dependency:** INDIRECT but CRITICAL.
MS-3a's premise is: "once the bitness Fiat-Shamir query is programmed." The exact Schnorr reparameterization (z ↔ alpha = z - c*w) is algebraic and ROM-independent. But the premise that challenges ARE programmed comes from MS-2.

**Under ROM removal:** MS-3a's algebraic content survives, but it has no applicable input. Without programmed challenges, there is no "programmed hybrid" to apply the reparameterization to.

**Failure class: CASCADING (depends on MS-2 which fails).**

### MS-3b (true-clause P = r*H characterization)

**ROM dependency:** NONE.
This is a purely algebraic fact about Pedersen commitments at the highest differing bit position. It does not use any oracle property.

**Under ROM removal:** SURVIVES. This is a structural property of the commitment scheme.

### MS-3c (exact comparison simulation)

**ROM dependency:** INDIRECT but CRITICAL.
Same structure as MS-3a. The exact simulation works algebraically, but the premise "comparison challenges are programmed from announcement-only query material" requires MS-2.

**Under ROM removal:** CASCADING failure (depends on MS-2).

### H0→H1 (composed MS replacement)

**ROM dependency:** FUNDAMENTAL.
This transition composes MS-1, MS-2, and MS-3a/b/c. Since MS-2 fails without ROM, the entire G0→G1 transition collapses.

**Under ROM removal:** FAILS. The MS simulator cannot produce indistinguishable transcripts.

### H1→H2 (LE replacement): A4

**ROM dependency:** FUNDAMENTAL.
The LE simulator also uses Fiat-Shamir programming. `simulate_le_transcript` programs `fs_challenge_bytes(binding_context, vk, public, commitment, t)` to return the chosen challenge_seed. Without this, the simulator-chosen (z, t) pair cannot be made consistent with an honestly derived challenge.

**Under ROM removal:** FAILS. The LE HVZK argument is ROM-dependent.

## Failure Severity Classification

| Lemma | ROM Dependency | Failure Class |
|-------|---------------|---------------|
| MS-1  | None          | Survives      |
| MS-2  | Fundamental   | Catastrophic  |
| MS-3a | Indirect      | Cascading     |
| MS-3b | None          | Survives      |
| MS-3c | Indirect      | Cascading     |
| H0→H1 | Fundamental  | Catastrophic  |
| H1→H2 | Fundamental  | Catastrophic  |

## Overall Assessment

**The proof is ROM-dependent in a fundamental way.**

Both the MS and LE components require oracle programmability for their simulation arguments. This is not a local dependency — it is structural.

### What survives without ROM:
- MS-1 (commitment binding) — standard model
- MS-3b (algebraic true-clause characterization) — unconditional
- The algebraic content of MS-3a and MS-3c — the Schnorr bijection is information-theoretic

### What collapses without ROM:
- The entire Fiat-Shamir simulation chain
- Both component simulators
- The composed global simulator

### Is this surprising?

No. This is the expected outcome for any Fiat-Shamir-based sigma protocol ZK proof. The Goldwasser-Kalai impossibility results [GK03] show that Fiat-Shamir is not generally zero-knowledge in the standard model. Standard-model ZK for lattice-based protocols requires different techniques (e.g., CRS-based commitments, or Peikert-Vaikuntanathan style arguments).

## ROM-Robustness Classification

```
QSSM is ROM-DEPENDENT, not ROM-robust.
```

This is the normal and expected classification for Fiat-Shamir-transformed sigma protocols. The system is not weaker than comparable published schemes (Dilithium, Crystals-Dilithium, etc.) which share exactly this dependency.

## What Would Be Needed for Standard-Model ZK

1. Replace Fiat-Shamir with a CRS-based commitment + challenge mechanism
2. Replace announcement-only query digests with interaction or trapdoor commitments
3. The MS Schnorr-style proofs would need a trapdoor sigma protocol variant
4. The LE rejection sampling argument would need a different masking technique

This would be a complete protocol redesign, not a proof-layer change.
