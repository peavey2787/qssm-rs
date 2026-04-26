# qssm-proofs

Internal analysis crate for QSSM reductions, theorem/audit artifacts, and security-floor enforcement.

## Module Layout

- `shared/`: simulator-safety wrappers and Fiat-Shamir/hash utilities.
- `ms/`: MS reductions/binding surfaces.
- `lattice/`: LE/lattice soundness, extraction, witness-hiding/rejection analysis.
- `zk/`: composed ZK theorem layer, simulators, closure and audit checks.

`zk::core` is implemented by `src/reduction_zk/` with this canonical nested layout:

- `core/`: theorem/core type layers.
- `simulate/`: simulator paths and helper math/oracle glue.
- `transcript/`: transcript model and transcript lemmas.
- `audit/`: closure checker, audit export, and empirical alignment utilities.
- `tests/`: unit/audit/theorem invariant tests.

## Parameter Authority

All Set B parameters are authoritative in `qssm_le::protocol::params`:

- `ETA=196_608`
- `GAMMA=199_680`
- `C_POLY_SIZE=48`
- `C_POLY_SPAN=8`
- `N=256`, `Q=8_380_417`, `BETA=8`

`qssm-proofs` must not duplicate these constants.

## ZK Theorem Framing

The composed theorem is stated in programmable ROM with explicit assumptions:

`Adv_QSSM(D) <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le`

This crate focuses on correctness-aligned reduction/audit structure and executable checks around that statement.

## Security Floors

- ZK floor: **132.2 bits**
- Soundness floor: **121 bits**
- CI floor: **112 bits** (`CI_FLOOR_BITS`)

## Testing

```
cargo test -p qssm-proofs
cargo test -p qssm-proofs --test parameter_sync
cargo test -p qssm-proofs audit_mode_tests --features audit-mode -- --nocapture
```
