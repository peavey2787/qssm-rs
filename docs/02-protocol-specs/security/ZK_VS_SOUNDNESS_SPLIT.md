# ZK vs Soundness: Explicit Split-Form

**Version:** QSSM-PROOF-FROZEN-v2.0
**Date:** 2026-04-25

## Purpose

The proof crate mixes ZK and soundness in adjacent modules. This document explicitly separates them.

---

## ZERO-KNOWLEDGE THEOREM

### Statement

For every PPT distinguisher D over the joint QSSM transcript:
```
Adv^zk_QSSM(D) ≤ epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le
```

### Model
Programmable Random Oracle Model (ROM).

### Assumptions Used
| ID | Name | What It Provides | Where It Acts |
|----|------|-----------------|---------------|
| A1 | Hash binding | Commitment/digest CR | MS-1 game hop |
| A2 | ROM programmability | Challenge simulation | MS-2 game hop |
| A4 | LE HVZK bound | Rejection-sampling + FS | H1→H2 transition |

### Proof Technique
Game-based: G0 (real) → G1 (MS simulated, LE real) → G2 (fully simulated).

### What ZK Does NOT Need
- Module-LWE / module-SIS hardness (only needed for soundness)
- Lattice parameter security estimates (those are soundness)
- Merkle tree collision resistance beyond Blake3 CR (that's soundness)
- Any witness-dependent structural argument (MS-3a/3b/3c are algebraic identities)

---

## SOUNDNESS THEOREM

### Statement

For every PPT adversary A trying to forge a proof for a false statement (value ≤ target):
```
Adv^snd_QSSM(A) ≤ epsilon_ms_soundness + epsilon_le_soundness
```

### Model
Random Oracle Model (observability sufficient; programmability not needed for soundness).

### Assumptions Used
| ID | Name | What It Provides | Where It Acts |
|----|------|-----------------|---------------|
| S1 | Blake3 collision resistance | Merkle forgery prevention | MS soundness |
| S2 | Fiat-Shamir FS challenge | Challenge unpredictability | MS + LE soundness |
| S3 | Module-SIS hardness | Commitment binding (LE) | LE extraction |
| S4 | Special soundness extraction | Knowledge error | LE sigma protocol |

### Proof Technique
Reduction-based: any soundness-breaking adversary implies either a hash collision (S1), FS forgery (S2), a short-vector finder (S3), or a knowledge extractor failure (S4).

### What Soundness Does NOT Need
- Oracle programmability (the verifier does not simulate)
- Rejection sampling bounds (those are ZK)
- Simulator independence (that's ZK composition)
- MS-3a/3b/3c (those are ZK simulation lemmas)

### Concrete Soundness Numbers (from reduction_lattice.rs and reduction_ms.rs)

**MS soundness:**
```
epsilon_ms_snd ≤ 256 × (Q_H² / 2^{257} + 2^{-256})
              ≈ 2^{-121}  (collision-dominated for Q_H = 2^{64})
```

**LE commitment soundness:**
```
MSIS classical bits: ∞  (rank-1 ring-SIS with invertible CRS → perfectly binding)
FS soundness bits: 132.2  (challenge space / query budget)
Combined: min(∞, 132.2) = 132.2 bits
```

**LE extraction knowledge error:**
```
knowledge_error = 1 / |C_eff| ≈ 2^{-196.2}
```

---

## THE BOUNDARY

| Property | ZK | Soundness |
|----------|:--:|:---------:|
| ROM programmability | ✓ REQUIRED | ✗ not needed |
| Blake3 collision resistance | ✓ (for A1) | ✓ (for S1) |
| Module-SIS hardness | ✗ not needed | ✓ REQUIRED |
| Rejection sampling bounds | ✓ (for A4) | ✗ not needed |
| MS-3a/3b/3c exact simulation | ✓ REQUIRED | ✗ not needed |
| Lattice BKZ estimates | ✗ not needed | ✓ REQUIRED |
| Witness independence | ✓ REQUIRED | ✗ not needed |
| Challenge unpredictability | ✗ (uses programming) | ✓ REQUIRED |

### Where They Share

Only ONE assumption appears in both:
- **Blake3 collision resistance** — used for MS-1 in ZK and for Merkle forgery in soundness

The ROM provides this for free, so in the ROM model the shared dependency is trivially satisfied.

### Where They Diverge

The critical divergence:
```
ZK needs ROM programmability          →  standard-model ZK would be a different protocol
Soundness needs module-SIS hardness   →  standard-model soundness is lattice-based
```

These are **independent assumption families**. ZK and soundness rest on different pillars.

---

## IMPLEMENTATION GUARANTEES (Third Layer)

Neither ZK nor soundness covers:
- Constant-time execution (side-channel defense)
- Memory zeroization (witness isolation at runtime)
- API misuse prevention (wrong parameter combinations)
- Serialization correctness (wire format fidelity)

These are **implementation guarantees**, enforced by:
- `subtle::ConstantTimeEq` / `ConstantTimeLess` for CT comparisons
- `zeroize::ZeroizeOnDrop` for witness memory
- Type-level restrictions (`pub(crate)` on `prove_with_witness`)
- Deterministic RNG (`Blake3Rng`, no OS entropy)

---

## Summary

```
QSSM Security = ZK (ROM + parameters) ⊕ Soundness (CR + SIS + FS) ⊕ Implementation (CT + zeroize + types)
```

These three layers are independent. A failure in one does not imply failure in another. Specifically:
- A side-channel leak does not break ZK or soundness mathematically
- A lattice algorithm advance (weakening SIS) does not break ZK
- ROM weakness does not break soundness (soundness only needs CR + challenge unpredictability)
