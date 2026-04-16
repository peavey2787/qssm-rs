//! Phase 5 golden: Merkle parent digest from **`CompressionWitness`** matches **`qssm_utils::merkle_parent`** bit-for-bit; prints full **MockProver** chain cost.

use qssm_gadget::blake3_compress::hash_merkle_parent_witness;
use qssm_gadget::r1cs::{Blake3Gadget, MockProver};
use qssm_utils::merkle::merkle_parent;

#[test]
fn test_full_merkle_parent_parity() {
    let left = std::array::from_fn(|i| (i as u8).wrapping_mul(17));
    let right = std::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(1));

    let expected = merkle_parent(&left, &right);
    let witness = hash_merkle_parent_witness(&left, &right);
    assert!(
        witness.validate(),
        "MerkleParentHashWitness must validate (56 G × 2 compress + schedule)"
    );
    let got = witness.digest();
    assert_eq!(got, expected, "digest bytes must match merkle_parent");

    for bi in 0..32 {
        for bit in 0..8 {
            assert_eq!(
                (got[bi] >> bit) & 1,
                (expected[bi] >> bit) & 1,
                "bit {bit} of byte {bi}"
            );
        }
    }

    let mut prover = MockProver::new();
    Blake3Gadget::synthesize_merkle_parent_hash(&mut prover, &witness);
    let n = prover.constraint_count();
    println!("sovereign_machine_merkle_parent_constraint_count={n}");
    assert_eq!(
        n, 65_184,
        "regression: 2 × (56×518 G + 6×512 permute + 16×32 finalize XOR hooks)"
    );
}
