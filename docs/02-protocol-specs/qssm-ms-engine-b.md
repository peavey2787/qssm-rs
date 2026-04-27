# QSSM-MS (Engine B) Spec

Rust implementation is authoritative. This spec mirrors current code in `truth-engine/qssm-ms`.

## Scope

Engine B provides:
- canonical predicate-only v2 transcript (`PredicateOnlyStatementV2`, `PredicateOnlyProofV2`, simulator API)

## Constants and Domains

- Value width: `u64` (`V2_BIT_COUNT = 64`)
- Domain string: `DOMAIN_MS` from `qssm_utils`

No constants are duplicated here beyond descriptive values; code values come from `qssm-ms` and `qssm-utils`.

## Predicate-Only v2 Interface (Canonical)

### Public API

- `commit_value_v2(value, seed, binding_entropy) -> Result<(ValueCommitmentV2, PredicateWitnessV2), MsError>`
- `prove_predicate_only_v2(statement, witness, prover_seed) -> Result<PredicateOnlyProofV2, MsError>`
- `verify_predicate_only_v2(statement, proof) -> Result<bool, MsError>`
- `simulate_predicate_only_v2(statement, simulator_seed) -> Result<PredicateOnlySimulationV2, MsError>`
- `verify_predicate_only_v2_with_programming(statement, simulation) -> Result<bool, MsError>`

### Statement Fields

`PredicateOnlyStatementV2`:
- `commitment: ValueCommitmentV2` (64 compressed points)
- `target: u64`
- `binding_entropy: [u8; 32]`
- `binding_context: [u8; 32]`
- `context: Vec<u8>`

### Proof Fields

`PredicateOnlyProofV2`:
- `result: bool`
- `statement_digest: [u8; 32]`
- `bitness_proofs: Vec<BitnessProofV2>` (64 entries)
- `comparison_proof: ComparisonProofV2`

`BitnessProofV2`:
- `announce_zero`, `announce_one`
- `challenge_zero`, `challenge_one`
- `response_zero`, `response_one`

`ComparisonProofV2`:
- `clauses: Vec<ComparisonClauseProofV2>`

`ComparisonClauseProofV2`:
- `challenge_share`
- `subproofs: Vec<EqualitySubproofV2>`

`EqualitySubproofV2`:
- `announcement`
- `response`

### Programmed Oracle Transcript Fields

`PredicateOnlySimulationV2`:
- `proof: PredicateOnlyProofV2`
- `programmed_queries: Vec<ProgrammedOracleQueryV2>`

`ProgrammedOracleQueryV2`:
- `query_digest: [u8; 32]`
- `challenge: [u8; 32]`

### Fiat-Shamir / Query Inputs (v2, Explicit)

`bitness_query_digest(statement_digest, bit_index, announce_zero, announce_one)`

`comparison_query_digest(statement_digest, clauses)` where each clause contributes:
- all `subproof.announcement` bytes only

`hash_query_to_scalar(query_digest)` maps digest to scalar challenge.

These inputs are announcement-only by construction for query digests.

## Security Model Notes (Code-Accurate)

- `verify_predicate_only_v2_with_programming` validates simulator output against programmed query/challenge pairs.
- `verify_predicate_only_v2` is the non-programmed verifier path.
- No claim in this file changes FS domains or transcript label semantics.
- `qssm-ms` is an internal implementation crate; product-facing API boundary is `qssm-api`.

## Code Mapping

- Module root and exports:
  - `truth-engine/qssm-ms/src/lib.rs`
- Predicate-only v2 transcript, query digests, simulator:
  - `truth-engine/qssm-ms/src/v2/`
- Merkle and domain hashing primitives used by Engine B:
  - `truth-engine/qssm-utils/src/hashing.rs`
