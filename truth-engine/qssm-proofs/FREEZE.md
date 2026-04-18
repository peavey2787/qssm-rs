# FREEZE.md — qssm-proofs Claim Inventory

> This file tracks the frozen formal claims in `qssm-proofs`.
> It is NOT an institutional document (`publish = false`).

## Frozen Parameters (from qssm-le)

| Parameter | Value | Source |
|-----------|-------|--------|
| N | 256 | `qssm_le::N` |
| Q | 8,380,417 | `qssm_le::Q` |
| BETA | 8 | `qssm_le::BETA` |
| ETA | 2,048 | `qssm_le::ETA` |
| GAMMA | 4,096 | `qssm_le::GAMMA` |
| C_POLY_SIZE | 64 | `qssm_le::C_POLY_SIZE` |
| C_POLY_SPAN | 16 | `qssm_le::C_POLY_SPAN` |

## Claim Inventory

### We prove (formal reduction)

1. **LE Commitment Soundness** — `LeCommitmentSoundnessTheorem`
   - ε_forge ≤ ε_MSIS + ε_FS
   - MSIS: perfectly binding (rank-1, invertible CRS, δ* < 1)
   - FS: ε_FS = Q_H / |C_eff| = 2^64 / 33^64 → −258.8 bits

2. **Special Soundness / Extraction** — `LyubashevskyExtractionClaim`
   - Knowledge error κ = 1/33^64 → −322.8 bits
   - Extraction via (c₁−c₂)⁻¹ in R_q ≅ F_q^256

3. **BLAKE3 Cross-Engine Binding** — `Blake3BindingReduction`
   - ε_bind ≤ Q_H² / 2^257 (birthday on 256-bit hash)
   - advantage ≈ −129 bits for Q_H = 2^64

4. **MS Inequality Soundness** — `MsSoundnessClaim`
   - ε_ms ≤ 256 · (ε_coll + 2^{-256}) ≈ 2^{-248}

### We bound (numeric estimate)

5. **BKZ Hardness Estimate** — `SecurityEstimate`
   - min(MSIS-APS15, FS-KLS18) ≈ 259 classical bits
   - FS-dominated (MSIS = ∞ for rank-1)

### We claim (non-simulation property)

6. **Witness-Hiding** — `WitnessHidingClaim`
   - Gap ratio γ/β = 512
   - Per-coefficient leakage ≈ 2^{-10} bits

### We do NOT claim

- **Full HVZK / simulation-based ZK** — η = 2,048 does not meet η ≥ 483,000
  required by [Lyu12] Lemma 3.2 for ε = 2^{-128}.
- **Post-quantum ROM analysis** — quantum bits are heuristic (0.265·b model).

## Invariants

- `CI_FLOOR_BITS = 112` — CI test fails below this.
- `TARGET_BITS = 128` — design target.
- All claim structs carry `claim_type: ClaimType` field.
- `tests/parameter_sync.rs` asserts every claim struct uses upstream constants.
