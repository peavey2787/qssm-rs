//! Adversarial Merkle path tests: sibling reorder, truncation, off-by-one, leaf substitution.

use qssm_gadget::{
    assert_ms_leaf_index_matches_opening, GadgetError, MerklePathWitness, MERKLE_DEPTH_MS,
};

fn build_valid_witness() -> (MerklePathWitness, [u8; 32]) {
    let leaf = [0x42u8; 32];
    let siblings: [[u8; 32]; MERKLE_DEPTH_MS] = {
        let mut s = [[0u8; 32]; MERKLE_DEPTH_MS];
        for (i, sib) in s.iter_mut().enumerate() {
            sib[0] = (i + 1) as u8;
        }
        s
    };
    let w = MerklePathWitness {
        leaf,
        siblings,
        leaf_index: 0,
    };
    let root = w.recompute_root().expect("baseline must succeed");
    (w, root)
}

#[test]
fn valid_witness_computes_deterministic_root() {
    let (w, root1) = build_valid_witness();
    let root2 = w.recompute_root().unwrap();
    assert_eq!(root1, root2, "deterministic recomputation");
}

#[test]
fn sibling_swap_produces_wrong_root() {
    let (mut w, expected) = build_valid_witness();
    w.siblings.swap(0, 1);
    let got = w.recompute_root().unwrap();
    assert_ne!(got, expected, "swapped siblings must produce different root");
}

#[test]
fn duplicate_siblings_produce_wrong_root() {
    let (mut w, expected) = build_valid_witness();
    let dup = w.siblings[0];
    for s in w.siblings.iter_mut() {
        *s = dup;
    }
    let got = w.recompute_root().unwrap();
    assert_ne!(got, expected, "duplicate siblings must produce different root");
}

#[test]
fn leaf_substitution_produces_wrong_root() {
    let (mut w, expected) = build_valid_witness();
    w.leaf[0] ^= 0xff;
    let got = w.recompute_root().unwrap();
    assert_ne!(got, expected, "tampered leaf must produce different root");
}

#[test]
fn leaf_index_off_by_one_fails_or_wrong_root() {
    let (_w, expected) = build_valid_witness();
    let w0 = build_valid_witness().0;
    let w1 = MerklePathWitness {
        leaf: w0.leaf,
        siblings: w0.siblings,
        leaf_index: 1,
    };
    match w1.recompute_root() {
        Ok(root) => assert_ne!(root, expected, "off-by-one index must differ"),
        Err(_) => {}
    }
}

#[test]
fn leaf_index_out_of_range_rejected() {
    let (mut w, _) = build_valid_witness();
    w.leaf_index = 128;
    let err = w.recompute_root().unwrap_err();
    assert!(matches!(err, GadgetError::LeafIndexOutOfRange { .. }));
}

#[test]
fn ms_leaf_index_mismatch_rejected() {
    let err = assert_ms_leaf_index_matches_opening(5, 0, 11).unwrap_err();
    assert!(matches!(err, GadgetError::MsOpeningMismatch { .. }));
}

#[test]
fn ms_leaf_index_correct_accepted() {
    assert_ms_leaf_index_matches_opening(5, 1, 11).unwrap();
}

#[test]
fn all_zero_leaf_still_recomputes() {
    let w = MerklePathWitness {
        leaf: [0u8; 32],
        siblings: [[0u8; 32]; MERKLE_DEPTH_MS],
        leaf_index: 0,
    };
    let _ = w.recompute_root().unwrap();
}
