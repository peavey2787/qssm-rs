# Security Model Map

**Version:** QSSM-PROOF-FROZEN-v2.0
**Date:** 2026-04-25

## What Protects What

```
┌──────────────────────────────────────────────────────────────────────┐
│                        QSSM SECURITY MODEL                          │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ZERO-KNOWLEDGE LAYER                                                │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ ROM ──→ MS Fiat-Shamir simulation (A2: ~66 programmed queries)│  │
│  │ ROM ──→ LE Fiat-Shamir simulation (A4-FS component)           │  │
│  │ ROM ──→ Commitment hiding (implicit d-MLWE under ROM curtain) │  │
│  │ CR  ──→ MS commitment binding (A1: Blake3 collision res.)     │  │
│  │ ALG ──→ MS exact simulation (MS-3a/3b/3c: Schnorr bijection)  │  │
│  │ PAR ──→ LE rejection sampling (η,γ parameter condition)       │  │
│  └────────────────────────────────────────────────────────────────┘  │
│  Bound: epsilon_ms_bind + epsilon_ms_rom + epsilon_le               │
│  Floor: ~2^{-132.2} (LE FS challenge space is binding constraint)   │
│                                                                      │
│  SOUNDNESS LAYER                                                     │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ CR  ──→ Merkle forgery prevention (Blake3: ~2^{-121} per MS)  │  │
│  │ FS  ──→ Challenge unpredictability (256-bit FS: ~2^{-256})    │  │
│  │ SIS ──→ LE commitment binding (rank-1 ring-SIS: ∞ bits)       │  │
│  │ EXT ──→ Knowledge extraction (1/|C_eff| ≈ 2^{-196.2})        │  │
│  └────────────────────────────────────────────────────────────────┘  │
│  Bound: epsilon_ms_snd + epsilon_le_snd                             │
│  Floor: ~2^{-121} (MS collision term is binding constraint)         │
│                                                                      │
│  IMPLEMENTATION LAYER                                                │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ CT  ──→ Constant-time comparisons (subtle crate)              │  │
│  │ ZER ──→ Witness memory zeroization (zeroize crate)            │  │
│  │ DET ──→ Deterministic RNG (Blake3-XOF, no OS entropy)         │  │
│  │ TYP ──→ Witness isolation (pub(crate), non-Serialize types)   │  │
│  │ DOM ──→ Domain separation (7 distinct domain strings)         │  │
│  └────────────────────────────────────────────────────────────────┘  │
│  Not formally bounded. Enforced by code discipline.                  │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

## Assumption → Mechanism → Protection

| Assumption | Mechanism | What It Protects | Breaks If... |
|------------|-----------|-----------------|-------------|
| ROM | FS programmability | ZK simulation (MS + LE) | Standard-model instantiation attempted |
| CR(Blake3) | Collision resistance | MS commitment binding (ZK + Soundness) | Blake3 collision found |
| d-MLWE | Commitment hiding | LE commitment indistinguishability | Lattice algorithms advance (hidden by ROM) |
| ring-SIS | Commitment binding | LE extraction / soundness | Short vector found in rank-1 lattice |
| Set B params | Rejection sampling | LE HVZK statistical distance | η, γ, β changed without re-derivation |
| Schnorr algebra | Exact bijection | MS transcript simulation (MS-3a/b/c) | Challenge-response structure changes |
| Announcement-only | Hash input discipline | MS simulatability premise | Query digests hash responses |
| Domain separation | Hash prefix hygiene | MS ↔ LE independence | Domain strings collide |

## Security Floor Summary

| Layer | Binding Constraint | Bits | What Dominates |
|-------|-------------------|------|---------------|
| ZK | LE FS challenge space | 132.2 | c_poly_size × log2(2·c_poly_span+1) |
| Soundness | MS collision bound | 121 | 256 nonces × Blake3 birthday |
| Combined | Soundness floor | 121 | MS collision resistance |

## What Is Actually Doing the Security Work

### Real work (non-eliminable, carries security weight):
1. **ROM** — enables both Fiat-Shamir simulation chains and commitment hiding
2. **LE parameter conditions** — the 132.2-bit FS floor is the tightest ZK constraint
3. **Blake3 collision resistance** — the 121-bit MS soundness floor
4. **ring-SIS infeasibility** — LE commitment is perfectly binding (infinite bits)

### Proof scaffolding (structurally necessary but not security-carrying):
1. **A1/A2 naming** — engineering decomposition of "ROM"
2. **Game-hopping structure** — proof presentation, not security mechanism
3. **MS-3a/3b/3c** — algebraic identities, not assumptions
4. **Domain separation constants** — hygiene, not hardness

### Verification infrastructure (catches regressions, not security itself):
1. **Closure checker** — validates proof structure
2. **Verification checklist** — auditor-facing summary
3. **Adversarial tests** — regression guards
4. **Freeze seal** — version tracking

## The One-Sentence Security Model

> QSSM security rests on the Random Oracle Model (for simulation), Blake3 collision resistance (for binding), and ring-SIS infeasibility (for extraction), with the zero-knowledge floor set by the LE Fiat-Shamir challenge space at 132.2 bits and the soundness floor set by the MS collision bound at 121 bits.
