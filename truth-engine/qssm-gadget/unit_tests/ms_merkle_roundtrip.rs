//! MS v2 truth-metadata binding roundtrip (replaces legacy Merkle root vs `qssm-ms::commit`).

use qssm_gadget::{
    encode_ms_v2_truth_metadata_from_statement_proof, GadgetError, MerklePathWitness,
    TruthWitnessMsV2, MERKLE_DEPTH_MS,
};
use qssm_ms::{commit_value_v2, prove_predicate_only_v2, PredicateOnlyStatementV2};

#[test]
fn ms_v2_truth_witness_bind_validate_roundtrip() {
    let seed = [0x42u8; 32];
    let binding_entropy = [0x11u8; 32];
    let binding_ctx = [0x55u8; 32];
    let context = b"gadget-ms-v2-roundtrip".to_vec();

    let (commitment, witness) =
        commit_value_v2(100u64, seed, binding_entropy).expect("commit v2");
    let statement = PredicateOnlyStatementV2::new(
        commitment,
        50u64,
        binding_entropy,
        binding_ctx,
        context,
    );
    let proof =
        prove_predicate_only_v2(&statement, &witness, [0x33u8; 32]).expect("prove v2");

    let ext = [0x99u8; 32];
    let metadata = encode_ms_v2_truth_metadata_from_statement_proof(&statement, &proof, &ext, false)
        .expect("encode metadata");
    let cd = statement.commitment().digest();
    let tw = TruthWitnessMsV2::bind(cd, binding_ctx, metadata);
    tw.validate().expect("truth witness validates");
}

#[test]
fn ms_v2_truth_witness_rejects_bad_metadata_length() {
    let seed = [0x42u8; 32];
    let binding_entropy = [0x11u8; 32];
    let binding_ctx = [0x55u8; 32];
    let (commitment, witness) =
        commit_value_v2(100u64, seed, binding_entropy).expect("commit v2");
    let statement = PredicateOnlyStatementV2::new(
        commitment,
        50u64,
        binding_entropy,
        binding_ctx,
        b"x".to_vec(),
    );
    let proof =
        prove_predicate_only_v2(&statement, &witness, [0x33u8; 32]).expect("prove v2");
    let mut metadata = encode_ms_v2_truth_metadata_from_statement_proof(&statement, &proof, &[0u8; 32], false)
        .expect("encode");
    metadata.push(0);
    let cd = statement.commitment().digest();
    let tw = TruthWitnessMsV2::bind(cd, binding_ctx, metadata);
    assert!(tw.validate().is_err());
}

#[test]
fn phase0_rejects_leaf_index_out_of_range() {
    let w = MerklePathWitness {
        leaf: [0u8; 32],
        siblings: [[0u8; 32]; MERKLE_DEPTH_MS],
        leaf_index: 128,
    };
    assert!(matches!(
        w.recompute_root(),
        Err(GadgetError::LeafIndexOutOfRange { .. })
    ));
}
