//! Phase 4 — R1CS IR surface and `Blake3Gadget` emission over [`GWitness`](crate::primitives::blake3_native::GWitness).
//!
//! `bits.rs` stays witness-only; this module reads witness fields and issues IR hooks.

use crate::primitives::bits::{RippleCarryWitness, XorWitness};
use crate::primitives::blake3_compress::{
    CompressionWitness, MerkleParentHashWitness, MSG_PERMUTATION,
};
use crate::primitives::blake3_native::{Add32ChainedWitness, BitRotateWitness, GWitness};

/// Handle to one R1CS variable (witness or public input).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct VarId(pub u32);

/// Classification for [`ConstraintSystem::allocate_variable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarKind {
    Public,
    Private,
}

/// Minimal constraint-system API for gadget synthesis (proving backend implements this later).
pub trait ConstraintSystem {
    fn allocate_variable(&mut self, kind: VarKind) -> VarId;

    /// Boolean XOR with explicit AND wire: **`and_xy = x · y`**, **`z = x + y - 2·and_xy`** (matches [`XorWitness`]).
    fn enforce_xor(&mut self, x: VarId, y: VarId, and_xy: VarId, z: VarId);

    /// One [`crate::primitives::bits::FullAdder`] stage: **`sum`**, **`cout`** from **`a`**, **`b`**, **`cin`**.
    fn enforce_full_adder(&mut self, a: VarId, b: VarId, cin: VarId, sum: VarId, cout: VarId);

    /// **`a = b`** (copy / permutation edge).
    fn enforce_equal(&mut self, a: VarId, b: VarId);
}

/// BLAKE3 **G**-step synthesis: walks a [`GWitness`] in the same order as [`crate::primitives::blake3_native::g_function`].
pub struct Blake3Gadget;

impl Blake3Gadget {
    /// One **`compress`**: **56 × `synthesize_g`**, **6** message word permutations (**512** `enforce_equal` each), **16 × 32** XOR bit hooks for feed-forward (see **`synth_xor_bits`**).
    pub fn synthesize_compress<C: ConstraintSystem>(cs: &mut C, witness: &CompressionWitness) {
        for round in 0..7 {
            for step in 0..8 {
                Self::synthesize_g(cs, &witness.g_steps[round][step].g);
            }
            if round < 6 {
                Self::synth_msg_block_permute(cs);
            }
        }
        for _ in 0..16 {
            Self::synth_xor_bits(cs);
        }
    }

    /// **`hash_merkle_parent_witness`**: two full **`synthesize_compress`** chains (**chunk start** + **root**).
    pub fn synthesize_merkle_parent_hash<C: ConstraintSystem>(
        cs: &mut C,
        witness: &MerkleParentHashWitness,
    ) {
        Self::synthesize_compress(cs, &witness.compress_chunk_start);
        Self::synthesize_compress(cs, &witness.compress_root);
    }

    fn synth_msg_block_permute<C: ConstraintSystem>(cs: &mut C) {
        let in_ids: [[VarId; 32]; 16] = std::array::from_fn(|_| {
            std::array::from_fn(|_| cs.allocate_variable(VarKind::Private))
        });
        let out_ids: [[VarId; 32]; 16] = std::array::from_fn(|_| {
            std::array::from_fn(|_| cs.allocate_variable(VarKind::Private))
        });
        for i in 0..16 {
            let src = MSG_PERMUTATION[i];
            for j in 0..32 {
                cs.enforce_equal(out_ids[i][j], in_ids[src][j]);
            }
        }
    }

    fn synth_xor_bits<C: ConstraintSystem>(cs: &mut C) {
        for _ in 0..32 {
            let x = cs.allocate_variable(VarKind::Private);
            let y = cs.allocate_variable(VarKind::Private);
            let and_xy = cs.allocate_variable(VarKind::Private);
            let z = cs.allocate_variable(VarKind::Private);
            cs.enforce_xor(x, y, and_xy, z);
        }
    }

    pub fn synthesize_g<C: ConstraintSystem>(cs: &mut C, witness: &GWitness) {
        Self::synth_add32_chained(cs, &witness.add_ab_mx);
        Self::synth_xor(cs, &witness.xor_d_a);
        Self::synth_rotate(cs, &witness.rot16);
        Self::synth_ripple(cs, &witness.add_c_d);
        Self::synth_xor(cs, &witness.xor_b_c);
        Self::synth_rotate(cs, &witness.rot12);
        Self::synth_add32_chained(cs, &witness.add_ab_my);
        Self::synth_xor(cs, &witness.xor_d_a2);
        Self::synth_rotate(cs, &witness.rot8);
        Self::synth_ripple(cs, &witness.add_c_d2);
        Self::synth_xor(cs, &witness.xor_b_c2);
        Self::synth_rotate(cs, &witness.rot7);
    }

    fn synth_xor<C: ConstraintSystem>(cs: &mut C, _w: &XorWitness) {
        Self::synth_xor_bits(cs);
    }

    /// Returns **sum** wire ids and the **final carry-out** wire (after bit 31).
    fn synth_ripple<C: ConstraintSystem>(
        cs: &mut C,
        rw: &RippleCarryWitness,
    ) -> ([VarId; 32], VarId) {
        synth_ripple_with_a(cs, rw, |_, c| c.allocate_variable(VarKind::Private))
    }

    fn synth_add32_chained<C: ConstraintSystem>(cs: &mut C, w: &Add32ChainedWitness) {
        let (sum1, _cout1) = Self::synth_ripple(cs, &w.first);
        let a2: [VarId; 32] = std::array::from_fn(|i| {
            let v = cs.allocate_variable(VarKind::Private);
            cs.enforce_equal(sum1[i], v);
            v
        });
        let _ = synth_ripple_with_a(cs, &w.second, |i, _c| a2[i]);
    }

    fn synth_rotate<C: ConstraintSystem>(cs: &mut C, br: &BitRotateWitness) {
        let in_ids: [VarId; 32] = std::array::from_fn(|_| cs.allocate_variable(VarKind::Private));
        let r = (br.offset % 32) as usize;
        for i in 0..32 {
            let src = (i + r) % 32;
            let out_id = cs.allocate_variable(VarKind::Private);
            cs.enforce_equal(out_id, in_ids[src]);
        }
    }
}

fn synth_ripple_with_a<C, F>(
    cs: &mut C,
    _rw: &RippleCarryWitness,
    mut a_var: F,
) -> ([VarId; 32], VarId)
where
    C: ConstraintSystem,
    F: FnMut(usize, &mut C) -> VarId,
{
    let mut sum_ids = [VarId(0); 32];
    let mut vcin = cs.allocate_variable(VarKind::Private);
    for i in 0..32 {
        let va = a_var(i, cs);
        let vb = cs.allocate_variable(VarKind::Private);
        let vsum = cs.allocate_variable(VarKind::Private);
        let vcout = cs.allocate_variable(VarKind::Private);
        cs.enforce_full_adder(va, vb, vcin, vsum, vcout);
        sum_ids[i] = vsum;
        vcin = vcout;
    }
    let vcout_final = cs.allocate_variable(VarKind::Private);
    cs.enforce_equal(vcin, vcout_final);
    (sum_ids, vcout_final)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::blake3_native::g_function;

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

        fn enforce_full_adder(
            &mut self,
            _a: VarId,
            _b: VarId,
            _cin: VarId,
            _sum: VarId,
            _cout: VarId,
        ) {
            self.constraint_count = self.constraint_count.saturating_add(1);
        }

        fn enforce_equal(&mut self, _a: VarId, _b: VarId) {
            self.constraint_count = self.constraint_count.saturating_add(1);
        }
    }

    #[derive(Debug, Default)]
    struct LineCountingConstraintSystem {
        next_var: u32,
        line_count: usize,
    }

    impl ConstraintSystem for LineCountingConstraintSystem {
        fn allocate_variable(&mut self, _kind: VarKind) -> VarId {
            let id = VarId(self.next_var);
            self.next_var = self.next_var.saturating_add(1);
            id
        }

        fn enforce_xor(&mut self, _x: VarId, _y: VarId, _and_xy: VarId, _z: VarId) {
            self.line_count = self.line_count.saturating_add(1);
        }

        fn enforce_full_adder(
            &mut self,
            _a: VarId,
            _b: VarId,
            _cin: VarId,
            _sum: VarId,
            _cout: VarId,
        ) {
            self.line_count = self.line_count.saturating_add(1);
        }

        fn enforce_equal(&mut self, _a: VarId, _b: VarId) {
            self.line_count = self.line_count.saturating_add(1);
        }
    }

    #[test]
    fn test_blake3_g_constraint_cost() {
        let g = g_function(
            0x1111_1111,
            0x2222_2222,
            0x3333_3333,
            0x4444_4444,
            0x_0505_0505,
            0x0a0a_0a0a,
        );
        let mut m = CountingConstraintSystem::default();
        Blake3Gadget::synthesize_g(&mut m, &g.witness);
        let n = m.constraint_count();
        println!("blake3_g_constraint_count={n}");
        assert!(n > 0, "expected non-zero constraint count");
        assert_eq!(
            n, 518,
            "regression: G witness synthesis cost (constraint count)"
        );
    }

    #[test]
    fn merkle_constraint_line_count_matches_total_constraints() {
        use crate::primitives::blake3_compress::hash_merkle_parent_witness;

        let left = [1u8; 32];
        let right = [2u8; 32];
        let w = hash_merkle_parent_witness(&left, &right);
        let mut m = CountingConstraintSystem::default();
        Blake3Gadget::synthesize_merkle_parent_hash(&mut m, &w);
        let mut lines = LineCountingConstraintSystem::default();
        Blake3Gadget::synthesize_merkle_parent_hash(&mut lines, &w);
        assert_eq!(lines.line_count as u64, m.constraint_count());
        assert_eq!(lines.line_count, 65_184);
    }
}
