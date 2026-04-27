//! # QSSM Local Verifier — Layer 5
//!
//! Offline proof verification: predicates → MS v2 verify → truth binding → LE lattice check.

#![forbid(unsafe_code)]

use qssm_gadget::{
    encode_ms_v2_truth_metadata_from_statement_proof, TruthWitnessMsV2,
};
use qssm_le::PublicInstance;
use qssm_local_prover::{Proof, ProofContext, ZkError, MS_CONTEXT_TAG};
use qssm_ms::verify_predicate_only_v2;
use qssm_templates::QssmTemplate;

pub fn verify(
    ctx: &ProofContext,
    template: &QssmTemplate,
    claim: &serde_json::Value,
    proof: &Proof,
    binding_ctx: [u8; 32],
) -> Result<bool, ZkError> {
    template.verify_public_claim(claim)?;

    if proof.ms_statement().binding_context() != &binding_ctx {
        return Err(ZkError::MsVerifyFailed);
    }
    if proof.ms_statement().context() != MS_CONTEXT_TAG {
        return Err(ZkError::MsVerifyFailed);
    }

    let ok_ms = verify_predicate_only_v2(proof.ms_statement(), proof.ms_proof())
        .map_err(|_| ZkError::MsVerifyFailed)?;
    if !ok_ms {
        return Err(ZkError::MsVerifyFailed);
    }

    let metadata = encode_ms_v2_truth_metadata_from_statement_proof(
        proof.ms_statement(),
        proof.ms_proof(),
        proof.external_entropy(),
        proof.external_entropy_included(),
    )
    .map_err(|_| ZkError::TruthWitnessInvalid)?;

    let tw = TruthWitnessMsV2::bind(*proof.ms_root(), binding_ctx, metadata);
    tw.validate().map_err(|_| ZkError::TruthWitnessInvalid)?;

    let public = PublicInstance::digest_coeffs(tw.digest_coeff_vector).map_err(ZkError::LeVerify)?;
    let ok = qssm_le::verify_lattice(
        ctx.vk(),
        &public,
        proof.le_commitment(),
        proof.le_proof(),
        &binding_ctx,
    )
    .map_err(ZkError::LeVerify)?;
    if !ok {
        return Err(ZkError::LeVerifyFailed);
    }

    Ok(true)
}

pub fn verify_proof_offline(
    ctx: &ProofContext,
    template_id: &str,
    claim: &serde_json::Value,
    proof: &Proof,
    binding_ctx: [u8; 32],
) -> Result<bool, VerifyError> {
    let template = qssm_templates::resolve(template_id)
        .ok_or_else(|| VerifyError::UnknownTemplate(template_id.to_owned()))?;
    verify(ctx, &template, claim, proof, binding_ctx).map_err(VerifyError::Zk)
}

pub fn verify_proof_with_template(
    ctx: &ProofContext,
    template: &QssmTemplate,
    claim: &serde_json::Value,
    proof: &Proof,
    binding_ctx: [u8; 32],
) -> Result<bool, ZkError> {
    verify(ctx, template, claim, proof, binding_ctx)
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    #[error("unknown template: {0}")]
    UnknownTemplate(String),
    #[error(transparent)]
    Zk(#[from] ZkError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use qssm_local_prover::{prove, ProofBundle};
    use qssm_utils::hashing::blake3_hash;
    use serde_json::json;

    fn test_seed() -> [u8; 32] {
        blake3_hash(b"QSSM-SDK-TEST-SEED")
    }

    fn test_entropy() -> [u8; 32] {
        blake3_hash(b"QSSM-SDK-TEST-ENTROPY")
    }

    fn test_ctx() -> ProofContext {
        ProofContext::new(test_seed())
    }

    fn test_template() -> QssmTemplate {
        QssmTemplate::proof_of_age("age-gate-21")
    }

    fn test_claim() -> serde_json::Value {
        json!({ "claim": { "age_years": 25 } })
    }

    fn test_binding() -> [u8; 32] {
        blake3_hash(b"test-binding-context")
    }

    fn make_proof(binding_ctx: [u8; 32]) -> Proof {
        prove(
            &test_ctx(),
            &test_template(),
            &test_claim(),
            100,
            50,
            binding_ctx,
            test_entropy(),
        )
        .expect("prove should succeed")
    }

    #[test]
    fn verify_round_trip() {
        let proof = make_proof(test_binding());
        let ok = verify(
            &test_ctx(),
            &test_template(),
            &test_claim(),
            &proof,
            test_binding(),
        )
        .expect("verify should succeed");
        assert!(ok);
    }

    #[test]
    fn offline_round_trip() {
        let binding_ctx = blake3_hash(b"test-offline-ctx");
        let proof = make_proof(binding_ctx);
        let ok = verify_proof_offline(
            &test_ctx(),
            "age-gate-21",
            &test_claim(),
            &proof,
            binding_ctx,
        )
        .expect("offline verify should succeed");
        assert!(ok);
    }

    #[test]
    fn verify_with_explicit_template_round_trip() {
        let binding_ctx = blake3_hash(b"test-explicit-template");
        let proof = make_proof(binding_ctx);
        let ok = verify_proof_with_template(
            &test_ctx(),
            &test_template(),
            &test_claim(),
            &proof,
            binding_ctx,
        )
        .expect("verify with template should succeed");
        assert!(ok);
    }

    #[test]
    fn unknown_template_rejected() {
        let proof = make_proof([0u8; 32]);
        let result = verify_proof_offline(
            &test_ctx(),
            "nonexistent-template",
            &test_claim(),
            &proof,
            [0u8; 32],
        );
        assert!(matches!(result, Err(VerifyError::UnknownTemplate(_))));
    }

    #[test]
    fn tampered_ms_proof_statement_digest_rejected() {
        let binding_ctx = blake3_hash(b"test-tampered-root");
        let proof = make_proof(binding_ctx);
        let mut bundle = ProofBundle::from_proof(&proof);
        let mut dig = hex::decode(&bundle.ms_v2_proof_statement_digest_hex).unwrap();
        dig[0] ^= 0x01;
        bundle.ms_v2_proof_statement_digest_hex = hex::encode(dig);
        let tampered = bundle.to_proof().unwrap();
        let result = verify(
            &test_ctx(),
            &test_template(),
            &test_claim(),
            &tampered,
            binding_ctx,
        );
        assert!(result.is_err());
    }

    #[test]
    fn wrong_binding_context_rejected() {
        let binding_ctx = blake3_hash(b"test-wrong-ctx-a");
        let wrong_ctx = blake3_hash(b"test-wrong-ctx-b");
        let proof = make_proof(binding_ctx);
        let result = verify(
            &test_ctx(),
            &test_template(),
            &test_claim(),
            &proof,
            wrong_ctx,
        );
        assert!(result.is_err());
    }

    #[test]
    fn wrong_claim_rejected() {
        let binding_ctx = blake3_hash(b"test-wrong-claim");
        let proof = make_proof(binding_ctx);
        let bad_claim = json!({ "claim": { "age_years": 17 } });
        let result = verify(
            &test_ctx(),
            &test_template(),
            &bad_claim,
            &proof,
            binding_ctx,
        );
        assert!(result.is_err());
    }

    #[test]
    fn tampered_binding_entropy_rejected() {
        let binding_ctx = blake3_hash(b"test-tampered-entropy");
        let proof = make_proof(binding_ctx);
        let mut bundle = ProofBundle::from_proof(&proof);
        let mut ent = hex::decode(&bundle.binding_entropy_hex).unwrap();
        ent[0] ^= 0xFF;
        let ent_hex = hex::encode(ent);
        bundle.binding_entropy_hex = ent_hex.clone();
        bundle.ms_v2_binding_entropy_hex = ent_hex;
        let tampered = bundle.to_proof().unwrap();
        let result = verify(
            &test_ctx(),
            &test_template(),
            &test_claim(),
            &tampered,
            binding_ctx,
        );
        assert!(result.is_err());
    }
}
