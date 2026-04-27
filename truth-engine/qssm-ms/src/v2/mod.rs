mod internals;
mod protocol;
mod types;
#[cfg(test)]
mod tests;
pub mod wire_constructors;

pub use protocol::{
    commit_value_v2, predicate_relation_holds_v2, prove_predicate_only_v2, simulate_predicate_only_v2,
    verify_predicate_only_v2, verify_predicate_only_v2_with_programming,
};
pub use types::{
    BitnessProofV2, ComparisonClauseProofV2, ComparisonProofV2, EqualitySubproofV2, PredicateOnlyProofV2,
    PredicateOnlySimulationV2, PredicateOnlyStatementV2, PredicateWitnessV2, ProgrammedOracleQueryV2,
    ValueCommitmentV2, V2_BIT_COUNT,
};
