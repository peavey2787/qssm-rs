use super::{
    commit_value_v2, predicate_relation_holds_v2, prove_predicate_only_v2,
    simulate_predicate_only_v2, verify_predicate_only_v2,
    verify_predicate_only_v2_with_programming, PredicateOnlyStatementV2, PredicateWitnessV2,
};

fn sample_statement(
    value: u64,
    target: u64,
    seed: [u8; 32],
    binding_entropy: [u8; 32],
    binding_context: [u8; 32],
    context: &[u8],
) -> (PredicateOnlyStatementV2, PredicateWitnessV2) {
    let (commitment, witness) = commit_value_v2(value, seed, binding_entropy).unwrap();
    (
        PredicateOnlyStatementV2::new(
            commitment,
            target,
            binding_entropy,
            binding_context,
            context.to_vec(),
        ),
        witness,
    )
}

#[test]
fn relation_check_rejects_mismatched_witness() {
    let (statement, mut witness) =
        sample_statement(30, 21, [1u8; 32], [7u8; 32], [9u8; 32], b"age_gate_21");
    witness.value = 18;
    assert!(!predicate_relation_holds_v2(&statement, &witness).unwrap());
}

#[test]
fn real_proof_roundtrip_verifies_under_hash_oracle() {
    let (statement, witness) =
        sample_statement(30, 21, [1u8; 32], [7u8; 32], [9u8; 32], b"age_gate_21");
    let proof = prove_predicate_only_v2(&statement, &witness, [3u8; 32]).unwrap();
    assert!(verify_predicate_only_v2(&statement, &proof).unwrap());
}

#[test]
fn simulated_proof_verifies_only_with_programmed_oracle() {
    let (statement, _witness) =
        sample_statement(30, 21, [1u8; 32], [7u8; 32], [9u8; 32], b"age_gate_21");
    let simulation = simulate_predicate_only_v2(&statement, [5u8; 32]).unwrap();
    assert!(verify_predicate_only_v2_with_programming(&statement, &simulation).unwrap());
    assert!(verify_predicate_only_v2(&statement, simulation.proof()).is_err());
}

#[test]
fn proof_observables_are_accessible_for_distribution_checks() {
    let (statement, witness) =
        sample_statement(45, 21, [6u8; 32], [7u8; 32], [9u8; 32], b"age_gate_21");
    let proof = prove_predicate_only_v2(&statement, &witness, [8u8; 32]).unwrap();
    assert_eq!(proof.bitness_global_challenges().unwrap().len(), 64);
    assert_ne!(proof.comparison_global_challenge().unwrap(), [0u8; 32]);
    assert_ne!(proof.transcript_digest(), [0u8; 32]);
}
