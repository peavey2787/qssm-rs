//! Merkle parent BLAKE3 compression operator.

#![forbid(unsafe_code)]

use super::super::binding_contract::{
    BindingLabel, BindingPhase, Nomination, PublicBindingContract,
};
use super::super::context::{PolyOpContext, PolyOpError};
use super::super::cs_tracing::PolyOpTracingCs;
use super::super::handshake::{MerkleParentBlake3Output, StateRoot32};
use super::super::lattice_polyop::LatticePolyOp;
use super::super::r1cs::{Blake3Gadget, ConstraintSystem};
use crate::primitives::blake3_compress::hash_merkle_parent_witness;

#[derive(Debug, Clone)]
pub struct MerkleParentBlake3Op {
    pub leaf_left: [u8; 32],
    pub leaf_right: [u8; 32],
}

impl MerkleParentBlake3Op {
    #[must_use]
    pub fn new(leaf_left: [u8; 32], leaf_right: [u8; 32]) -> Self {
        Self {
            leaf_left,
            leaf_right,
        }
    }

    /// Convenience: Merkle compress then truth limb (see [`MerkleTruthPipe`](super::MerkleTruthPipe)).
    #[must_use]
    pub fn pipe_truth(self, truth_params: super::TruthLimbV2Params) -> super::MerkleTruthPipe {
        super::merkle_truth_pipe(self, truth_params)
    }

    pub fn public_binding_contract(&self) -> PublicBindingContract {
        let witness = hash_merkle_parent_witness(&self.leaf_left, &self.leaf_right);
        let root = witness.digest();
        let mut c = PublicBindingContract::default();
        c.nominations.push((
            BindingPhase::PublicBinding,
            BindingLabel("merkle_state_root".into()),
            Nomination {
                bytes: root.to_vec(),
            },
        ));
        c
    }
}

impl LatticePolyOp for MerkleParentBlake3Op {
    type Input = ();
    type Output = MerkleParentBlake3Output;

    fn get_public_binding_requirements(&self) -> Result<PublicBindingContract, PolyOpError> {
        Ok(self.public_binding_contract())
    }

    fn public_binding_requirements_for_input(
        &self,
        _input: &Self::Input,
    ) -> Result<PublicBindingContract, PolyOpError> {
        Ok(self.public_binding_contract())
    }

    fn synthesize_with_context(
        &self,
        _input: Self::Input,
        cs: &mut impl ConstraintSystem,
        ctx: &mut PolyOpContext,
    ) -> Result<Self::Output, PolyOpError> {
        ctx.set_segment("merkle_parent_blake3");
        let witness = hash_merkle_parent_witness(&self.leaf_left, &self.leaf_right);
        if !witness.validate() {
            return Err(PolyOpError::Binding(
                "invalid MerkleParentHashWitness".into(),
            ));
        }
        let state_root = StateRoot32(witness.digest());
        {
            let mut trace = PolyOpTracingCs { inner: cs, ctx };
            Blake3Gadget::synthesize_merkle_parent_hash(&mut trace, &witness);
        }
        if let Some(e) = ctx.take_degree_violation() {
            return Err(PolyOpError::Degree(e));
        }
        let contract = self.public_binding_contract();
        Ok(MerkleParentBlake3Output {
            witness,
            state_root,
            contract,
        })
    }
}
