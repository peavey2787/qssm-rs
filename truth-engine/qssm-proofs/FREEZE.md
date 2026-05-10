# FREEZE.md — qssm-proofs Claim Inventory

This file records frozen security-model assumptions and parameterized claims for `qssm-proofs`.

## Authoritative Parameters

All Set B parameters are authoritative in `qssm_le::protocol::params` (`truth-engine/qssm-le/src/protocol/params.rs`).

| Parameter | Value |
|---|---|
| `N` | `256` |
| `Q` | `8,380,417` |
| `BETA` | `8` |
| `ETA` | `196,608` |
| `GAMMA` | `199,680` |
| `C_POLY_SIZE` | `48` |
| `C_POLY_SPAN` | `8` |

## Frozen Theorem Posture

`qssm-proofs` carries the composed ZK theorem in programmable ROM with additive bound:

`Adv_QSSM(D) <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le`

with the frozen boundary contracts and Set B parameter conditions.

The wording-modernization sweep is strictly non-semantic: no FS domain tags,
transcript labels, or public API symbols are changed by documentation-only edits.

## Security Floors

- ZK floor (Fiat-Shamir challenge-space margin): **132.2 bits**
- Soundness floor (collision-dominated MS bound): **121 bits**
- CI enforcement floor (`CI_FLOOR_BITS` in crate): `112`

## Invariants

- Parameter values are sourced from `qssm_le::protocol::params` only.
- `gamma == eta + ||cr||_inf` is checked by executable tests.
- Independent LE Set B recomputation is checked against the production artifact and external fixture schema `1`.
- External numeric reports must match exact integer fields and floating fields within `2^-64` absolute tolerance.
- Frozen theorem audit paths must preserve `PROOF_STRUCTURE_VERSION` and `run_audit_validation`.
- `src/reduction_zk/` remains nested (`core/`, `simulate/`, `transcript/`, `audit/`, `tests/`) with no flat duplicate source copies.
