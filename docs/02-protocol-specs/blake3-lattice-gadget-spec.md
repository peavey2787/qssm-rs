# BLAKE3-Lattice Gadget Spec

Rust implementation is authoritative. This spec mirrors `truth-engine/qssm-gadget` and bridge usage with `qssm-ms` and `qssm-le`.

## Scope

This layer binds verified Engine B outputs into Engine A public binding/seam artifacts.
It is a composition/bridge spec, not a replacement for either engine’s standalone spec.

Current bridge path note:
- The active bridge binds the canonical MS v2 predicate-only path.
- Legacy GhostMirror verification material is removed from active seam binding.

## Normative Bridge Interfaces

### MS Verification Adapter

`MsPredicateOnlyV2BridgeOp` input fields:
- `statement: PredicateOnlyStatementV2`
- `proof: PredicateOnlyProofV2`

`MsPredicateOnlyV2BridgeOp` output fields:
- `ms_v2_statement_digest: [u8; 32]`
- `ms_v2_result_bit: u8`
- `ms_v2_bitness_global_challenges_digest: [u8; 32]`
- `ms_v2_comparison_global_challenge: [u8; 32]`
- `ms_v2_transcript_digest: [u8; 32]`

Bridge rule:
- `verify_predicate_only_v2(statement, proof)` MUST succeed before bridge output is accepted.

### Engine A Seam Binding

`EngineABindingInput` fields:
- `state_root`
- `ms_v2_statement_digest`
- `ms_v2_result_bit`
- `ms_v2_bitness_global_challenges_digest`
- `ms_v2_comparison_global_challenge`
- `ms_v2_transcript_digest`
- `binding_context`
- `device_entropy_link`
- `truth_digest`
- `entropy_anchor`
- `claimed_seam_commitment`
- `require_ms_verified`

`EngineABindingOutput` fields:
- `seam_commitment_digest`
- `seam_open_digest`
- `seam_binding_digest`

All-zero checks and commit-then-open equality are enforced before output.

## Domain-Separated Hash Inputs (Explicit)

### Seam commitment

`EngineABindingOp::commitment_digest`:
- domain `QSSM-SEAM-MS-V2-COMMIT-v1`
- `state_root`
- `ms_v2_statement_digest`
- `ms_v2_result_bit`
- `ms_v2_bitness_global_challenges_digest`
- `ms_v2_comparison_global_challenge`
- `ms_v2_transcript_digest`
- `device_entropy_link`
- `binding_context`
- `truth_digest`
- `entropy_anchor`

### Seam open

`EngineABindingOp::open_digest`:
- domain `QSSM-SEAM-MS-V2-OPEN-v1`
- `seam_commitment`
- `ms_v2_statement_digest`
- `ms_v2_result_bit`
- `ms_v2_comparison_global_challenge`
- `binding_context`

### Seam binding

`EngineABindingOp::binding_digest`:
- domain `QSSM-SEAM-MS-V2-BINDING-v1`
- `seam_open`
- `ms_v2_transcript_digest`
- `state_root`

## Transcript Layout Synchronization

- `TRANSCRIPT_MAP_LAYOUT_VERSION` in gadget must match:
  - `qssm_utils::LE_FS_PUBLIC_BINDING_LAYOUT_VERSION`
- `EngineAPublicJson` canonical key order:
  - `message_limb_u30`
  - `digest_coeff_vector_u4`

This alignment is the bridge contract to Engine A `public_binding_fs_bytes`.

FS boundary note:
- Engine A prover/verifier FS is defined in `qssm-le` (`fs_challenge_bytes`).
- `qssm-proofs` simulator/programmed-oracle FS uses `DOMAIN_ZK_SIM` and simulator labels for theorem composition.
- This boundary is modeling/plumbing separation, not a cryptographic protocol change.

## Constants and Authority

- LE modulus authority is `qssm-le` (`Q = 8_380_417`)
- Bridge constant `BRIDGE_Q` must equal `qssm_le::Q`
- Legacy 30-bit limb compatibility bound is `MAX_LIMB_EXCLUSIVE = 2^30`

Do not introduce independent copies of Engine A constants outside enforced sync points.

## Code Mapping

- Bridge lattice constants and checks:
  - `truth-engine/qssm-gadget/src/lattice/lattice_bridge.rs`
- MS adapter poly-op:
  - `truth-engine/qssm-gadget/src/circuit/operators/ms_predicate_v2_bridge.rs`
- Engine A seam poly-op:
  - `truth-engine/qssm-gadget/src/circuit/operators/engine_a_binding.rs`
- Handshake artifact structures and transcript-map version lock:
  - `truth-engine/qssm-gadget/src/circuit/handshake.rs`
- Binding contract surface:
  - `truth-engine/qssm-gadget/src/circuit/binding_contract.rs`
