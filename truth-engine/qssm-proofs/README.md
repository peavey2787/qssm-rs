# qssm-proofs

> **Internal analysis crate.** Formal reduction claims and hardness gates for
> the QSSM Truth Engine.  Not published (`publish = false`).

## What this crate proves, bounds, and does not claim

| Primitive | Property | Assumption | Bits | Claim Type | File / Struct |
|-----------|----------|------------|------|------------|---------------|
| LE commitment | Soundness | MSIS(256, q, 8) — rank-1, perfectly binding | ∞ (FS-dominated) | `Soundness` | `reduction_lattice.rs` / `LeCommitmentSoundnessTheorem` |
| LE commitment | Composed soundness | min(MSIS, FS-ROM) | ≈259 classical | `Soundness` | `reduction_lattice.rs` / `LeCommitmentSoundnessTheorem` |
| LE Σ-protocol | Extraction | Special soundness (Lyu12 §3) | 322.8 | `Soundness` | `reduction_lattice.rs` / `LyubashevskyExtractionClaim` |
| LE Σ-protocol | Witness-hiding | Gap ratio γ/β = 512 | — | `WitnessHiding` | `reduction_witness_hiding.rs` / `WitnessHidingClaim` |
| LE Σ-protocol | **Not claimed** | **Full HVZK** (η too small) | — | — | `reduction_rejection.rs` / `RejectionSamplingClaim` |
| Rejection sampling | Abort probability | Deterministic worst-case | 1.0 (certain abort for worst cr) | `WitnessHiding` | `reduction_rejection.rs` / `RejectionSamplingClaim` |
| MS inequality | Soundness | BLAKE3-ROM + FS challenge | ≈248 | `Soundness` | `reduction_ms.rs` / `MsSoundnessClaim` |
| Cross-engine binding | Binding | BLAKE3 collision resistance (birthday) | ≥129 | `Binding` | `reduction_blake3.rs` / `Blake3BindingReduction` |
| BKZ hardness | Estimation | APS15 core-SVP + KLS18 FS-ROM | ≈259 | `Estimation` | `lib.rs` / `SecurityEstimate` |

### Key observation: rank-1 ring-SIS is perfectly binding

The LE commitment uses a **single** invertible ring element A ∈ R_q as the CRS.
Since q ≡ 1 (mod 512), the ring R_q = Z_q[X]/(X^256+1) splits completely into
256 copies of F_q.  A random A is invertible with probability ≈ 1 − 3×10⁻⁵.
When A is invertible, the kernel lattice is qZ^N — its shortest vector has
norm q ≈ 8.4M, far exceeding β√N = 128.  No BKZ algorithm can find such a
short kernel vector (target δ* ≈ 0.96 < 1).

Security is therefore **Fiat-Shamir dominated**: ≈259 classical bits from the
challenge space |C_eff| = 33^64 with Q_H = 2^64 hash queries.

### What we do NOT claim

- **Full HVZK / simulation-based ZK.**  Our η = 2048 does not meet the
  Lyubashevsky simulation requirement η ≥ 11·‖cr‖_∞·√(ln(2N/ε)/π) ≈ 483,000.
  We claim **witness-hiding** only (gap ratio γ/β = 512).
- **Post-quantum security.**  The formal quantum bits use the core-SVP quantum
  model (0.265·b) but no quantum ROM analysis is performed.

## Security gate policy

- Target class: 128-bit security.
- CI enforcement floor: 112 bits (`CI_FLOOR_BITS`).
- Structural preconditions: `C_POLY_SIZE ≥ 64`, digest coefficient vector size ≥ 64.
- `cargo test -p qssm-proofs` fails when effective security drops below the floor.

## Testing

```
cargo test -p qssm-proofs           # unit tests (30)
cargo test -p qssm-proofs --test parameter_sync  # parameter drift guardrail (11)
```

## Modules

| Module | Purpose |
|--------|---------|
| `reduction_lattice` | MSIS bound, FS bound, composed LE soundness theorem, extraction claim |
| `reduction_blake3` | BLAKE3 collision/binding reduction (birthday bound) |
| `reduction_ms` | Mirror-Shift inequality soundness claim |
| `reduction_rejection` | Rejection sampling correctness, HVZK non-claim |
| `reduction_witness_hiding` | Witness-hiding claim (gap ratio, leakage bound) |
| `benchmarks` | Sub-1ms verification target checks |

## References

- \[APS15\] Albrecht, Player, Scott. "On the concrete hardness of Learning with Errors." J. Math. Crypt., 2015.
- \[KLS18\] Kiltz, Lyubashevsky, Schaffner. "A concrete treatment of Fiat-Shamir signatures in the quantum random-oracle model." EUROCRYPT, 2018.
- \[Lyu12\] Lyubashevsky. "Lattice signatures without trapdoors." EUROCRYPT, 2012.
- \[DDLL13\] Ducas, Durmus, Lepoint, Lyubashevsky. "Lattice signatures and bimodal Gaussians." CRYPTO, 2013.

This turns sovereign security policy into a compiler/test-enforced invariant.

