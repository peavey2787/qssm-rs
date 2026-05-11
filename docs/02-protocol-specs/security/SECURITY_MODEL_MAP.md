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

Coverage boundary:
- EasyCrypt currently proves the ZK/composition theorem surfaces and their documented companions only.
- The soundness layer and concrete soundness floors shown in this document are security-analysis scope, not current EasyCrypt theorem claims.
- Soundness remains outside the current EasyCrypt theorem surface unless a separate EasyCrypt soundness theorem family is added later.

## Formal Route Coverage Note

The three-term ZK bound shown above is the exact-zero theorem skeleton for:
- `qssm_main_theorem`

It is not the full statement for the live charged companion routes:
- `qssm_main_theorem_parameterized_budget`
- `qssm_main_theorem_realworld_budget`
- `qssm_main_theorem_realworld_concrete_128`
- `qssm_main_theorem_realworld_concrete_128_with_all_reductions`

For those charged routes:
- public AfterRom remains budget-close to canonical AfterRom, not zero-equal
- the duplicate MS2 charge remains explicit
- the theorem-facing additive form is `epsilon_top = epsilon_MS1 + epsilon_MS2 + epsilon_MS2 + epsilon_LE`

The concrete all-reductions sibling route and its closed-form companion exist as:
- `qssm_main_theorem_realworld_concrete_128_with_all_reductions`
- `qssm_main_theorem_realworld_concrete_128_with_all_reductions_5_over_2_98`

Current concrete route status:
- component epsilon = `1 / 2^98`
- top epsilon = `5 / 2^98`
- effective bit level ≈ `95.67807190511263`
- LE rejection, LE FS, MS1, and MS2 each enter through explicit external reduction obligations
- those obligations are theorem premises, not axioms
- the current theorem surface does not model weighted or non-uniform sampler internals
- the frozen toy `3%r / 64%r` lower masses do not instantiate `1 / 2^98`, and no theorem claims the toy actuals are `<= 2^-98`

Refinement boundary:
- exact domain strings, seed schedules, query-digest functions, byte order, serialization order, seam digest preimage order, and layout/version-lock equality remain Rust-authoritative conformance points
- EasyCrypt currently models abstract observables and theorem-level consequences rather than a byte-for-byte refinement from Rust surfaces
- LE constants, challenge expansion details, attempt bounds, and numeric floor statements in this document are Rust/spec/security-analysis facts, not current EasyCrypt embedded constants

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

These floor summaries are system/security-analysis summaries. They should not be read as current EasyCrypt machine-checked outputs for the deployed Rust constants.

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
