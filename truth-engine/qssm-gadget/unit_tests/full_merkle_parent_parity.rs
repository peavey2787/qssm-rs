//! Phase 5 golden: Merkle parent digest from `CompressionWitness` matches `qssm_utils::merkle_parent` bit-for-bit.

use qssm_gadget::hash_merkle_parent_witness;
use qssm_gadget::{Blake3Gadget, ConstraintSystem, VarId, VarKind};
use qssm_utils::merkle::merkle_parent;

#[derive(Debug, Default)]
struct CountingConstraintSystem {
    next_var: u32,
    constraint_count: u64,
}

impl CountingConstraintSystem {
    fn constraint_count(&self) -> u64 {
        self.constraint_count
    }
}

impl ConstraintSystem for CountingConstraintSystem {
    fn allocate_variable(&mut self, _kind: VarKind) -> VarId {
        let id = VarId(self.next_var);
        self.next_var = self.next_var.saturating_add(1);
        id
    }

    fn enforce_xor(&mut self, _x: VarId, _y: VarId, _and_xy: VarId, _z: VarId) {
        self.constraint_count = self.constraint_count.saturating_add(1);
    }

    fn enforce_full_adder(&mut self, _a: VarId, _b: VarId, _cin: VarId, _sum: VarId, _cout: VarId) {
        self.constraint_count = self.constraint_count.saturating_add(1);
    }

    fn enforce_equal(&mut self, _a: VarId, _b: VarId) {
        self.constraint_count = self.constraint_count.saturating_add(1);
    }
}

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

    let mut prover = CountingConstraintSystem::default();
    Blake3Gadget::synthesize_merkle_parent_hash(&mut prover, &witness);
    let n = prover.constraint_count();
    println!("sovereign_machine_merkle_parent_constraint_count={n}");
    assert_eq!(
        n, 65_184,
        "regression: 2 × (56×518 G + 6×512 permute + 16×32 finalize XOR hooks)"
    );
}
