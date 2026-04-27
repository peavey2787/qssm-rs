//! MS predicate-only v2 verification adapter for bridge composition.
//!
//! This operator verifies `PredicateOnlyProofV2` against `PredicateOnlyStatementV2`
//! and emits the public observables used by seam binding.

#![forbid(unsafe_code)]

use super::super::binding_contract::{
    BindingLabel, BindingPhase, Nomination, PublicBindingContract,
};
use super::super::context::{PolyOpContext, PolyOpError};
use super::super::lattice_polyop::LatticePolyOp;
use super::super::r1cs::ConstraintSystem;
use qssm_ms::{verify_predicate_only_v2, PredicateOnlyProofV2, PredicateOnlyStatementV2};
use qssm_utils::hashing::{hash_domain, DOMAIN_MS};

#[derive(Debug, Clone)]
pub struct MsPredicateOnlyV2BridgeInput {
    pub statement: PredicateOnlyStatementV2,
    pub proof: PredicateOnlyProofV2,
}

#[derive(Debug, Clone)]
pub struct MsPredicateOnlyV2BridgeOutput {
    pub ms_v2_statement_digest: [u8; 32],
    pub ms_v2_result_bit: u8,
    pub ms_v2_bitness_global_challenges_digest: [u8; 32],
    pub ms_v2_comparison_global_challenge: [u8; 32],
    pub ms_v2_transcript_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MsPredicateOnlyV2BridgeOp;

fn bitness_global_challenges_digest(challenges: &[[u8; 32]]) -> [u8; 32] {
    let len_bytes = (challenges.len() as u32).to_le_bytes();
    let mut chunks: Vec<&[u8]> = Vec::with_capacity(challenges.len() + 1);
    chunks.push(&len_bytes);
    for challenge in challenges {
        chunks.push(challenge.as_slice());
    }
    hash_domain(DOMAIN_MS, &chunks)
}

impl LatticePolyOp for MsPredicateOnlyV2BridgeOp {
    type Input = MsPredicateOnlyV2BridgeInput;
    type Output = MsPredicateOnlyV2BridgeOutput;

    fn public_binding_requirements_for_input(
        &self,
        input: &Self::Input,
    ) -> Result<PublicBindingContract, PolyOpError> {
        let bitness = input
            .proof
            .bitness_global_challenges()
            .map_err(|e| PolyOpError::Binding(format!("MS v2 bitness challenges: {e}")))?;
        let comparison = input
            .proof
            .comparison_global_challenge()
            .map_err(|e| PolyOpError::Binding(format!("MS v2 comparison challenge: {e}")))?;
        let mut c = PublicBindingContract::default();
        c.nominations.push((
            BindingPhase::PublicBinding,
            BindingLabel("ms_v2_statement_digest".into()),
            Nomination {
                bytes: input.statement.statement_digest().to_vec(),
            },
        ));
        c.nominations.push((
            BindingPhase::PublicBinding,
            BindingLabel("ms_v2_result_bit".into()),
            Nomination {
                bytes: vec![u8::from(input.proof.result())],
            },
        ));
        c.nominations.push((
            BindingPhase::PublicBinding,
            BindingLabel("ms_v2_bitness_global_challenges_digest".into()),
            Nomination {
                bytes: bitness_global_challenges_digest(&bitness).to_vec(),
            },
        ));
        c.nominations.push((
            BindingPhase::PublicBinding,
            BindingLabel("ms_v2_comparison_global_challenge".into()),
            Nomination {
                bytes: comparison.to_vec(),
            },
        ));
        c.nominations.push((
            BindingPhase::PublicBinding,
            BindingLabel("ms_v2_transcript_digest".into()),
            Nomination {
                bytes: input.proof.transcript_digest().to_vec(),
            },
        ));
        Ok(c)
    }

    fn synthesize_with_context(
        &self,
        input: Self::Input,
        _cs: &mut impl ConstraintSystem,
        ctx: &mut PolyOpContext,
    ) -> Result<Self::Output, PolyOpError> {
        ctx.set_segment("ms_predicate_v2_bridge");
        let verified = verify_predicate_only_v2(&input.statement, &input.proof)
            .map_err(|e| PolyOpError::Binding(format!("MS v2 verify error: {e}")))?;
        if !verified {
            return Err(PolyOpError::Binding(
                "MS v2 bridge: verify_predicate_only_v2 returned false".into(),
            ));
        }
        let bitness = input
            .proof
            .bitness_global_challenges()
            .map_err(|e| PolyOpError::Binding(format!("MS v2 bitness challenges: {e}")))?;
        let comparison = input
            .proof
            .comparison_global_challenge()
            .map_err(|e| PolyOpError::Binding(format!("MS v2 comparison challenge: {e}")))?;
        Ok(MsPredicateOnlyV2BridgeOutput {
            ms_v2_statement_digest: input.statement.statement_digest(),
            ms_v2_result_bit: u8::from(input.proof.result()),
            ms_v2_bitness_global_challenges_digest: bitness_global_challenges_digest(&bitness),
            ms_v2_comparison_global_challenge: comparison,
            ms_v2_transcript_digest: input.proof.transcript_digest(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConstraintSystem, VarId, VarKind};
    use qssm_ms::{commit_value_v2, prove_predicate_only_v2, PredicateOnlyStatementV2};

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

    fn sample_v2_input() -> MsPredicateOnlyV2BridgeInput {
        let binding_entropy = [7u8; 32];
        let binding_context = [9u8; 32];
        let context = b"age_gate_fast".to_vec();
        let (commitment, witness) =
            commit_value_v2(u64::MAX, [3u8; 32], binding_entropy).expect("commit v2");
        let statement = PredicateOnlyStatementV2::new(
            commitment,
            u64::MAX - 1,
            binding_entropy,
            binding_context,
            context,
        );
        let proof = prove_predicate_only_v2(&statement, &witness, [4u8; 32]).expect("prove v2");
        MsPredicateOnlyV2BridgeInput { statement, proof }
    }

    #[test]
    fn ms_predicate_v2_bridge_succeeds_on_valid_input() {
        let op = MsPredicateOnlyV2BridgeOp;
        let mut ctx = PolyOpContext::new("ms_v2");
        let mut cs = NoopConstraintSystem::default();
        let input = sample_v2_input();
        let out = op
            .synthesize_with_context(input, &mut cs, &mut ctx)
            .expect("synthesize");
        assert_ne!(out.ms_v2_statement_digest, [0u8; 32]);
        assert_ne!(out.ms_v2_bitness_global_challenges_digest, [0u8; 32]);
        assert_ne!(out.ms_v2_comparison_global_challenge, [0u8; 32]);
        assert_ne!(out.ms_v2_transcript_digest, [0u8; 32]);
    }
}
