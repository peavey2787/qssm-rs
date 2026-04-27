# QSSM ZK Concrete Execution Spec

Rust code is canonical. This document is a byte-accurate execution spec for the current implementation and is intended as a future formalization input.

## Scope

This document specifies:
- exact Fiat-Shamir / oracle constructions (domains, labels, ordering)
- exact simulator execution path and ordering
- exact transcript field layouts used in `qssm-proofs`
- exact hash/XOF transformation surfaces used by MS/LE execution paths

API boundary note:
- `qssm-ms` is an internal implementation crate.
- `qssm-api` is the only user-facing product API boundary.

This document does not restate game-based theorem abstraction; see `qssm-zk-theorem-spec.md`.

## Canonical Domains and Labels

### ZK composition domains (`qssm-proofs`)

- `DOMAIN_ZK_SIM = "QSSM-ZK-SIM-v1.0"`
- `DOMAIN_MS` (imported from `qssm_utils`)

Global simulator seed labels:
- `b"qssm_global_sim_ms_seed"`
- `b"qssm_global_sim_le_seed"`

LE simulator core labels (global path):
- `b"le_global_sim_commitment_short"`
- `b"le_global_sim_z"`
- `b"le_global_sim_challenge_seed"`

LE programmed digest tag:
- `b"le_programmed_query_digest"`

### Engine A FS constants (`qssm-le`)

- `DOMAIN_LE_FS = "QSSM-LE-FS-LYU-v1.0"`
- `DOMAIN_LE_CHALLENGE_POLY = "QSSM-LE-CHALLENGE-POLY-v1.0"`
- `CROSS_PROTOCOL_BINDING_LABEL = b"cross_protocol_digest_v1"`
- `DST_LE_COMMIT = b"QSSM-LE-V1-COMMIT..............."` (32 bytes)
- `DST_MS_VERIFY = b"QSSM-MS-V1-VERIFY..............."` (32 bytes)
- literal tag `b"fs_v2"`

### Engine B v2 FS labels (`qssm-ms`)

- `b"predicate_only_v2_statement"`
- `b"predicate_only_v2_bitness_query"`
- `b"predicate_only_v2_comparison_query"`
- `b"predicate_only_v2_query_scalar"`
- `b"predicate_only_v2_proof"`

### Gadget bridge seam domains (`qssm-gadget`)

- `QSSM-SEAM-MS-V2-COMMIT-v1`
- `QSSM-SEAM-MS-V2-OPEN-v1`
- `QSSM-SEAM-MS-V2-BINDING-v1`

## FS Construction Appendix (Exact)

## A. Global simulator seed derivation (qssm-proofs)

`simulate_qssm_transcript(SimulatorOnly<&QssmPublicInput>, simulator_seed)` derives:

1) `ms_seed = hash_domain(DOMAIN_ZK_SIM, [`
- `b"qssm_global_sim_ms_seed"`,
- `simulator_seed`,
- `ms_statement.statement_digest()`,
`])`

2) `le_seed = hash_domain(DOMAIN_ZK_SIM, [`
- `b"qssm_global_sim_le_seed"`,
- `simulator_seed`,
- `public_input.le.binding_context`,
- `public_input.le.vk.crs_seed`,
`])`

Order is fixed exactly as above.

## B. LE simulator challenge seed in qssm-proofs

`FiatShamirOracle::le_challenge_seed(domain_sim, label, simulator_seed?, binding_context, vk, public_fs_bytes, commitment)`:

When simulator seed is present:
- `domain_hash(domain_sim, [`
  - `label`,
  - `simulator_seed`,
  - `binding_context`,
  - `vk.crs_seed`,
  - `public_fs_bytes`,
  - `encode_rq_coeffs_le(commitment.0)`,
`])`

When simulator seed is absent:
- same list, minus `simulator_seed`.

No LE `t` bytes are included in this particular seed derivation path.

## C. LE programmed oracle query digest in qssm-proofs

`FiatShamirOracle::le_programmed_query_digest(DOMAIN_ZK_SIM, ...)`:
- `domain_hash(DOMAIN_ZK_SIM, [`
  - `b"le_programmed_query_digest"`,
  - `binding_context`,
  - `vk.crs_seed`,
  - `public_fs_bytes`,
  - `encode_rq_coeffs_le(commitment.0)`,
  - `encode_rq_coeffs_le(t)`,
`])`

## D. Engine A verifier/prover FS challenge bytes (`qssm-le`)

`fs_challenge_bytes(binding_context, vk, public, commitment, t)` hashes with BLAKE3 in this exact order:
1. `DOMAIN_LE_FS.as_bytes()`
2. `DST_LE_COMMIT`
3. `DST_MS_VERIFY`
4. `CROSS_PROTOCOL_BINDING_LABEL`
5. `DOMAIN_MS.as_bytes()`
6. `b"fs_v2"`
7. `binding_context`
8. `vk.crs_seed`
9. `public_binding_fs_bytes(public)`
10. `encode_rq_coeffs_le(commitment.0)`
11. `encode_rq_coeffs_le(t)`

Output: 32-byte challenge seed.

## E. Engine A challenge polynomial expansion (`qssm-le` and `qssm-proofs`)

Domain: `"QSSM-LE-CHALLENGE-POLY-v1.0"`

For counter `ctr = 0,1,...` until filled:
- hash `[seed, ctr.to_le_bytes()]`
- parse into 4-byte `u32` words
- coefficient mapping:
  - `coeff = (word % (2*C_POLY_SPAN + 1)) - C_POLY_SPAN`
- stop at `C_POLY_SIZE`

## F. Engine B v2 query/challenge path (`qssm-ms`)

Bitness query digest:
- `hash_domain(DOMAIN_MS, [`
  - `b"predicate_only_v2_bitness_query"`,
  - `statement_digest`,
  - `bit_index (u32 LE)`,
  - `announce_zero`,
  - `announce_one`,
`])`

Comparison query digest:
- BLAKE3 hasher update sequence:
  - `DOMAIN_MS`
  - `b"predicate_only_v2_comparison_query"`
  - `statement_digest`
  - each `subproof.announcement` in clause/subproof order

Query -> scalar:
- `hash_to_scalar(b"predicate_only_v2_query_scalar", [query_digest])`
- internally uses `v2_xof` framing:
  - hasher updates `DOMAIN_MS`, then `label`
  - each chunk as `(len_u32_le, chunk_bytes)` (length-prefixed)
  - reads 64-byte XOF output
  - `Scalar::from_bytes_mod_order_wide`

## G. MS v2 bridge -> Engine A seam path (`qssm-gadget`)

Bridge-side verification precondition:
- `verify_predicate_only_v2(statement, proof)` must return `Ok(true)` before seam material is accepted.

Seam material bound into `EngineABindingInput`:
1. `ms_v2_statement_digest` (`proof.statement_digest()`)
2. `ms_v2_result_bit` (`u8::from(proof.result())`)
3. `ms_v2_bitness_global_challenges_digest` (domain-hash digest over ordered bitness global challenges)
4. `ms_v2_comparison_global_challenge` (`proof.comparison_global_challenge()`)
5. `ms_v2_transcript_digest` (`proof.transcript_digest()`)

Commit digest preimage order:
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

## Exact Simulator Execution (qssm-proofs)

`simulate_qssm_transcript`:
1. unwrap `SimulatorOnly<&QssmPublicInput>`
2. reconstruct MS v2 statement from public input
3. derive `ms_seed` (as above)
4. derive `le_seed` (as above)
5. call `simulate_ms_v2_transcript(SimulatorOnly(&public_input.ms), ms_seed)`
6. call `simulate_le_transcript(SimulatorOnly(&public_input.le), le_seed)`
7. return `SimulatedQssmTranscript { ms, le }`

`simulate_le_transcript`:
1. delegates to `simulate_le_core(..., Some(simulator_seed), labels...)`
2. returns `.transcript`

`simulate_le_core`:
1. verify Set B HVZK precondition through rejection claim check
2. sample commitment short vector from label/binding_context/(optional seed)
3. compute commitment `C = A*r + mu(public)`
4. sample `z` from label/binding_context/(optional seed)
5. derive LE challenge seed via `FiatShamirOracle::le_challenge_seed`
6. derive `c_poly`, `c_rq`
7. compute `u = C - mu`, `az`, `cu`, then `t = az - cu`
8. derive programmed query digest via `le_fs_programmed_query_digest(..., t)`
9. assert algebraic relation and norm bound
10. emit `SimulatedLeTranscript`

## Exact Transcript Structs (Code Names and Order)

`SimulatedMsV2Transcript`:
1. `statement_digest: [u8; 32]`
2. `result: bool`
3. `bitness_global_challenges: Vec<[u8; 32]>`
4. `comparison_global_challenge: [u8; 32]`
5. `transcript_digest: [u8; 32]`

`SimulatedLeTranscript`:
1. `commitment_coeffs: Vec<u32>`
2. `t_coeffs: Vec<u32>`
3. `z_coeffs: Vec<u32>`
4. `challenge_seed: [u8; 32]`
5. `programmed_oracle_query_digest: [u8; 32]`

`SimulatedQssmTranscript`:
1. `ms: SimulatedMsV2Transcript`
2. `le: SimulatedLeTranscript`

Canonical wrapper model:
- `MsTranscript` fields follow the same 5-field order as MS v2 above.
- `LeTranscript` fields:
  1. `commitment_coeffs`
  2. `t_coeffs`
  3. `z_coeffs`
  4. `challenge_seed`
- `QssmTranscript` fields:
  1. `ms`
  2. `le`

## Transcript Naming Mapping (Spec -> Code)

| Spec Name | Code Name |
|---|---|
| `proof_t` | `t_coeffs` |
| `proof_z` | `z_coeffs` |
| `commitment` | `commitment_coeffs` |

## EasyCrypt formalization surface

First-pass EasyCrypt modeling should treat the following as the canonical execution surface:

- `SimulatedMsV2Transcript` observable fields:
  - `statement_digest`
  - `result`
  - `bitness_global_challenges`
  - `comparison_global_challenge`
  - `transcript_digest`
- `SimulatedLeTranscript` observable fields:
  - `commitment_coeffs`
  - `t_coeffs`
  - `z_coeffs`
  - `challenge_seed`
  - `programmed_oracle_query_digest`
- `SimulatedQssmTranscript` as the composed output object.
- `simulate_qssm_transcript` as the canonical composed simulator entry point.

The following code surfaces are implementation diagnostics and are not first-pass EasyCrypt model objects:

- `Real*` transcript structs and sampling helpers.
- witness-free simulator attempt structs.
- audit/diagnostic report structs and attempt logs.

## Code Mapping

- Global simulator composition:
  - `truth-engine/qssm-proofs/src/reduction_zk/simulate/simulators.rs`
- LE core simulator and MS v2 simulator:
  - `truth-engine/qssm-proofs/src/reduction_zk/simulate/simulators_extra.rs`
- FS helper surface in proofs:
  - `truth-engine/qssm-proofs/src/shared/fiat_shamir.rs`
- Transcript structs:
  - `truth-engine/qssm-proofs/src/reduction_zk/core/types_core.rs`
  - `truth-engine/qssm-proofs/src/reduction_zk/transcript/lemmas_a.rs`
  - `truth-engine/qssm-proofs/src/reduction_zk/transcript/transcript_model.rs`
- Engine A FS construction:
  - `truth-engine/qssm-le/src/protocol/commit.rs`
- Engine B v2 query/XOF construction:
  - `truth-engine/qssm-ms/src/v2/mod.rs`
  - `truth-engine/qssm-ms/src/v2/types.rs`
  - `truth-engine/qssm-ms/src/v2/protocol.rs`
  - `truth-engine/qssm-ms/src/v2/internals.rs`
  - `truth-engine/qssm-ms/src/v2/wire_constructors.rs`
