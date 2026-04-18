//! Ghost-Mirror (`qssm-ms`) verification adapter — wraps [`qssm_ms::verify`]
//! as a [`LatticePolyOp`] for composition with the gadget operator pipeline.
//!
//! This adapter was relocated from `qssm-local-verifier` (Layer 4) into `qssm-gadget`
//! (Layer 3) at v1.1.0 to enforce the architectural rule that all `LatticePolyOp`
//! implementations live alongside the trait definition.

#![forbid(unsafe_code)]

use super::super::binding_contract::{BindingLabel, BindingPhase, Nomination, PublicBindingContract};
use super::super::context::{PolyOpContext, PolyOpError};
use super::super::lattice_polyop::LatticePolyOp;
use super::super::r1cs::ConstraintSystem;

use qssm_ms::{verify as ms_verify, GhostMirrorProof, Root as MsRoot};

use super::super::operators::truth_limb::TruthLimbV2Params;

#[derive(Debug, Clone, Copy, Default)]
pub struct MsGhostMirrorOp;

#[derive(Debug, Clone)]
pub struct MsGhostMirrorInput {
    pub root: MsRoot,
    pub proof: GhostMirrorProof,
    pub binding_entropy: [u8; 32],
    pub value: u64,
    pub target: u64,
    pub context: Vec<u8>,
    pub binding_context: [u8; 32],
}

impl MsGhostMirrorInput {
    #[must_use]
    pub fn binding_entropy_from_truth(params: &TruthLimbV2Params, fallback: [u8; 32]) -> [u8; 32] {
        params.ms_binding_entropy_digest(fallback)
    }
}

#[derive(Debug, Clone)]
pub struct MsGhostMirrorOutput {
    pub fs_v2_challenge: [u8; 32],
    pub root: [u8; 32],
}

impl LatticePolyOp for MsGhostMirrorOp {
    type Input = MsGhostMirrorInput;
    type Output = MsGhostMirrorOutput;

    fn public_binding_requirements_for_input(&self, input: &Self::Input) -> Result<PublicBindingContract, PolyOpError> {
        let mut contract = PublicBindingContract::default();
        contract.nominations.push((
            BindingPhase::PublicBinding,
            BindingLabel("ms_fs_v2_challenge".into()),
            Nomination {
                bytes: input.proof.challenge().to_vec(),
            },
        ));
        Ok(contract)
    }

    fn synthesize_with_context(
        &self,
        input: Self::Input,
        _cs: &mut impl ConstraintSystem,
        ctx: &mut PolyOpContext,
    ) -> Result<Self::Output, PolyOpError> {
        ctx.set_segment("ms_ghost_mirror");
        let ok = ms_verify(
            input.root,
            &input.proof,
            input.binding_entropy,
            input.value,
            input.target,
            &input.context,
            &input.binding_context,
        );
        if !ok {
            return Err(PolyOpError::Binding(
                "qssm_ms::verify returned false for GhostMirrorProof".into(),
            ));
        }
        Ok(MsGhostMirrorOutput {
            fs_v2_challenge: *input.proof.challenge(),
            root: *input.root.as_bytes(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConstraintSystem, VarId, VarKind};
    use qssm_ms::{commit, prove};

    #[derive(Debug, Default)]
    struct NoopConstraintSystem {
        next_var: u32,
    }

    impl ConstraintSystem for NoopConstraintSystem {
        fn allocate_variable(&mut self, _kind: VarKind) -> VarId {
            let id = VarId(self.next_var);
            self.next_var = self.next_var.saturating_add(1);
            id
        }

        fn enforce_xor(&mut self, _x: VarId, _y: VarId, _and_xy: VarId, _z: VarId) {}

        fn enforce_full_adder(
            &mut self,
            _a: VarId,
            _b: VarId,
            _cin: VarId,
            _sum: VarId,
            _cout: VarId,
        ) {
        }

        fn enforce_equal(&mut self, _a: VarId, _b: VarId) {}
    }

    #[test]
    fn ms_ghost_mirror_polyop_synthesize_after_prove() {
        let seed = [3u8; 32];
        let ledger = [4u8; 32];
        let rollup = [5u8; 32];
        let (root, salts) = commit(seed, ledger).expect("commit");
        let proof = prove(100, 50, &salts, ledger, b"ctx", &rollup).expect("prove");
        let op = MsGhostMirrorOp;
        let mut ctx = PolyOpContext::new("ms");
        let mut cs = NoopConstraintSystem::default();
        let out = op
            .synthesize_with_context(
                MsGhostMirrorInput {
                    root,
                    proof,
                    binding_entropy: ledger,
                    value: 100,
                    target: 50,
                    context: b"ctx".to_vec(),
                    binding_context: rollup,
                },
                &mut cs,
                &mut ctx,
            )
            .expect("synthesize");
        assert_eq!(out.fs_v2_challenge.len(), 32);
        assert_eq!(out.root, *root.as_bytes());
    }

    #[test]
    fn ms_ghost_mirror_rejects_invalid_proof() {
        let seed = [3u8; 32];
        let ledger = [4u8; 32];
        let rollup = [5u8; 32];
        let (root, salts) = commit(seed, ledger).expect("commit");
        let proof = prove(100, 50, &salts, ledger, b"ctx", &rollup).expect("prove");
        let op = MsGhostMirrorOp;
        let mut ctx = PolyOpContext::new("ms");
        let mut cs = NoopConstraintSystem::default();
        // Supply wrong binding_context — verification must fail.
        let err = op
            .synthesize_with_context(
                MsGhostMirrorInput {
                    root,
                    proof,
                    binding_entropy: ledger,
                    value: 100,
                    target: 50,
                    context: b"ctx".to_vec(),
                    binding_context: [0xFF; 32], // wrong
                },
                &mut cs,
                &mut ctx,
            )
            .unwrap_err();
        assert!(matches!(err, PolyOpError::Binding(_)));
    }

    #[test]
    fn ms_ghost_mirror_public_binding_contract() {
        let seed = [3u8; 32];
        let ledger = [4u8; 32];
        let rollup = [5u8; 32];
        let (root, salts) = commit(seed, ledger).expect("commit");
        let proof = prove(100, 50, &salts, ledger, b"ctx", &rollup).expect("prove");
        let expected_challenge = *proof.challenge();
        let op = MsGhostMirrorOp;
        let contract = op
            .public_binding_requirements_for_input(&MsGhostMirrorInput {
                root,
                proof,
                binding_entropy: ledger,
                value: 100,
                target: 50,
                context: b"ctx".to_vec(),
                binding_context: rollup,
            })
            .expect("contract");
        assert_eq!(contract.nominations.len(), 1);
        assert_eq!(contract.nominations[0].2.bytes, expected_challenge.to_vec());
    }
}
