# qssm-ms

Internal MS implementation crate for the truth-engine workspace.

## Scope

`qssm-ms` is **v2-only**:

- commitment construction for predicate proofs (`commit_value_v2`)
- predicate-only prove/verify (`prove_predicate_only_v2`, `verify_predicate_only_v2`)
- simulator + programmed-oracle verification (`simulate_predicate_only_v2`, `verify_predicate_only_v2_with_programming`)
- wire reconstruction helpers under `wire_constructors`

This crate is **not** the product boundary. The user-facing API boundary is `qssm-api`.

## Public Surface

Re-exported from `src/lib.rs`:

- `ValueCommitmentV2`
- `PredicateWitnessV2`
- `PredicateOnlyStatementV2`
- `PredicateOnlyProofV2`
- `PredicateOnlySimulationV2`
- `BitnessProofV2`
- `ComparisonProofV2`
- `ComparisonClauseProofV2`
- `EqualitySubproofV2`
- `ProgrammedOracleQueryV2`
- `commit_value_v2`
- `predicate_relation_holds_v2`
- `prove_predicate_only_v2`
- `verify_predicate_only_v2`
- `simulate_predicate_only_v2`
- `verify_predicate_only_v2_with_programming`
- `wire_constructors`
- `MsError`

## Internal Layout

- `src/lib.rs` — facade
- `src/v2/mod.rs` — v2 module wiring and exports
- `src/v2/types.rs` — v2 data types and digest helpers
- `src/v2/protocol.rs` — commit/prove/verify/simulate paths
- `src/v2/internals.rs` — shared crypto/query helpers and challenge oracles
- `src/v2/wire_constructors.rs` — wire reconstruction constructors
- `src/v2/tests.rs` — v2 unit tests
- `src/error.rs` — error types

## Invariants

Do not change cryptographic semantics, domain labels, XOF framing, or wire layout without a security review.