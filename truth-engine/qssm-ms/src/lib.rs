//! QSSM-MS: MS v2 predicate-only commitments and inequality proofs.
#![forbid(unsafe_code)]

mod error;
mod v2;

pub use error::MsError;
pub use v2::{
    commit_value_v2, predicate_relation_holds_v2, prove_predicate_only_v2,
    simulate_predicate_only_v2, verify_predicate_only_v2,
    verify_predicate_only_v2_with_programming, BitnessProofV2, ComparisonClauseProofV2,
    ComparisonProofV2, EqualitySubproofV2, PredicateOnlyProofV2, PredicateOnlySimulationV2,
    PredicateOnlyStatementV2, PredicateWitnessV2, ProgrammedOracleQueryV2, ValueCommitmentV2,
    V2_BIT_COUNT,
};
pub use v2::wire_constructors;
