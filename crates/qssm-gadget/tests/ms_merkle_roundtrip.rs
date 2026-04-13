//! Merkle `recompute_root` matches `qssm-ms` commit root (Phase 0 + hash chain).

use qssm_gadget::merkle::{
    assert_ms_leaf_index_matches_opening, MerklePathWitness, MERKLE_DEPTH_MS,
};
use qssm_gadget::GadgetError;
use qssm_ms::{commit, prove, Root};
use qssm_utils::hashing::{hash_domain, DOMAIN_MS};

fn ms_leaf(i: u8, bit: u8, salt: &[u8; 32], ledger: &[u8; 32]) -> [u8; 32] {
    hash_domain(DOMAIN_MS, &[b"leaf", &[i], &[bit], salt.as_slice(), ledger])
}

#[test]
fn merkle_witness_matches_qssm_ms_root() {
    let seed = [0x42u8; 32];
    let ledger = [0x11u8; 32];
    let ctx = b"ctx";
    let rollup = [0x55u8; 32];

    let (Root(expected_root), salts) = commit(0, seed, ledger).expect("commit");
    let proof = prove(
        100u64,
        50u64,
        &salts,
        ledger,
        ctx,
        &rollup,
    )
    .expect("prove");

    let leaf_index = (2usize * (proof.k as usize) + (proof.bit_at_k as usize)) as u8;
    assert_ms_leaf_index_matches_opening(proof.k, proof.bit_at_k, leaf_index).expect("opening");

    let leaf = ms_leaf(
        proof.k,
        proof.bit_at_k,
        &proof.opened_salt,
        &ledger,
    );
    assert_eq!(proof.path.len(), MERKLE_DEPTH_MS);

    let mut siblings = [[0u8; 32]; MERKLE_DEPTH_MS];
    for i in 0..MERKLE_DEPTH_MS {
        siblings[i] = proof.path[i];
    }

    let w = MerklePathWitness {
        leaf,
        siblings,
        leaf_index,
    };

    let got = w.recompute_root().expect("recompute");
    assert_eq!(got, expected_root);
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
