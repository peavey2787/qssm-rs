# Assumption Analysis

This file is the canonical assumption analysis for the current frozen QSSM ZK theorem.
Rust code remains the source of truth.

## Theorem-Level Additive Bound

```text
Adv_QSSM(D) <= epsilon_ms_hash_binding
             + epsilon_ms_rom_programmability
             + epsilon_le
```

Mapped assumptions:
- `A1` -> `epsilon_ms_hash_binding`
- `A2` -> `epsilon_ms_rom_programmability`
- `A4` -> `epsilon_le`

## Compression Interpretation

Within the programmable ROM framing used by the theorem:
- `A1` and `A2` can be discussed under ROM umbrella language
- `A4` combines ROM-programmed FS behavior plus concrete LE parameter conditions

For audit clarity, the proof artifact keeps `A1`, `A2`, and `A4` separate.

## Dominance / Security Floor

Practical floor remains controlled by LE FS entropy and Set B constraints:
- LE FS floor: about `132.2` bits
- Soundness floor target in docs/checklists: `121` bits

MS hash-binding and MS-ROM terms stay lower-order under normal query budgets.

## Parameter-Condition Obligations

Set B verification relies on executable numeric checks, including:
- `gamma == eta + ||cr||_inf` style relationship checks in proof crate tests
- independent LE Set B recomputation and external fixture validation
- fixed schema version and explicit float tolerance (`2^-64`) for external validation artifacts

## What Is and Is Not Claimed

- This analysis describes the current code-backed theorem surface.
- It does not claim a standard-model replacement for programmed Fiat-Shamir steps.
- It does not collapse simulator exactness lemmas (`MS-3a/3b/3c`) into new assumptions.

## Source Mapping

- theorem object and assumption table:
  - `truth-engine/qssm-proofs/src/reduction_zk/core/theorem_core.rs`
  - `truth-engine/qssm-proofs/src/reduction_zk/core/theorem_graph.rs`
- LE external validation artifacts/tests:
  - `truth-engine/qssm-proofs/src/lattice/external_validation.rs`
  - `truth-engine/qssm-proofs/tests/external_le_validation.rs`
  - `truth-engine/qssm-proofs/tests/parameter_sync.rs`
