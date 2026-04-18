//! # QSSM Local Verifier — Layer 5
//!
//! Offline proof verification: the logic that says "Yes" or "No."
//!
//! This crate owns the cross-engine rebinding verification pipeline:
//! predicates → MS verify → truth rebinding → LE lattice check.

#![forbid(unsafe_code)]

use qssm_gadget::{
    digest_coeff_vector_from_truth_digest, encode_proof_metadata_v2, truth_digest,
};
use qssm_le::PublicInstance;
use qssm_ms::{self, Root};
use qssm_local_prover::{Proof, ProofContext, ZkError, MS_CONTEXT_TAG};
use qssm_templates::QssmTemplate;

/// Verify a proof against a template and context.
///
/// **Cross-engine rebinding:** the verifier independently recomputes the
/// truth digest from the MS transcript and derives the LE public instance.
/// The LE proof is verified against this *recomputed* instance — never against
/// a value the prover claims.
pub fn verify(
    ctx: &ProofContext,
    template: &QssmTemplate,
    claim: &serde_json::Value,
    proof: &Proof,
    binding_ctx: [u8; 32],
) -> Result<bool, ZkError> {
    // 1. Check predicates against the public claim.
    template.verify_public_claim(claim)?;

    // 2. MS: verify the inequality proof.
    let context = MS_CONTEXT_TAG.to_vec();
    let root = Root::new(*proof.ms_root());
    if !qssm_ms::verify(
        root,
        proof.ms_proof(),
        *proof.binding_entropy(),
        proof.value(),
        proof.target(),
        &context,
        &binding_ctx,
    ) {
        return Err(ZkError::MsVerifyFailed);
    }

    // 3. CROSS-ENGINE REBINDING — Math is Law.
    let metadata = encode_proof_metadata_v2(
        proof.ms_proof().n(),
        proof.ms_proof().k(),
        proof.ms_proof().bit_at_k(),
        proof.ms_proof().challenge(),
        proof.external_entropy(),
        proof.external_entropy_included(),
    );
    let recomputed_digest = truth_digest(proof.ms_root(), &binding_ctx, &metadata);
    let recomputed_coeffs = digest_coeff_vector_from_truth_digest(&recomputed_digest);

    // 4. LE: verify the lattice proof against the RECOMPUTED public instance.
    let public = PublicInstance::digest_coeffs(recomputed_coeffs)
        .map_err(ZkError::LeVerify)?;
    let ok = qssm_le::verify_lattice(
        ctx.vk(), &public, proof.le_commitment(), proof.le_proof(), &binding_ctx,
    ).map_err(ZkError::LeVerify)?;
    if !ok {
        return Err(ZkError::LeVerifyFailed);
    }

    Ok(true)
}

/// Verify a proof offline using the standard template gallery.
///
/// Resolves the template by `template_id`, then delegates to [`verify`].
///
/// # Errors
///
/// Returns [`VerifyError::UnknownTemplate`] if the template ID is not found,
/// or [`VerifyError::Zk`] if the underlying proof verification fails.
pub fn verify_proof_offline(
    ctx: &ProofContext,
    template_id: &str,
    claim: &serde_json::Value,
    proof: &Proof,
    binding_ctx: [u8; 32],
) -> Result<bool, VerifyError> {
    let template = qssm_templates::resolve(template_id)
        .ok_or_else(|| VerifyError::UnknownTemplate(template_id.to_owned()))?;
    verify(ctx, &template, claim, proof, binding_ctx)
        .map_err(VerifyError::Zk)
}

/// Verify a proof offline with an explicit template.
pub fn verify_proof_with_template(
    ctx: &ProofContext,
    template: &QssmTemplate,
    claim: &serde_json::Value,
    proof: &Proof,
    binding_ctx: [u8; 32],
) -> Result<bool, ZkError> {
    verify(ctx, template, claim, proof, binding_ctx)
}

/// Errors from offline verification.
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
        prove(&test_ctx(), &test_template(), &test_claim(), 100, 50, binding_ctx, test_entropy())
            .expect("prove should succeed")
    }

    // ── Round-trip ───────────────────────────────────────────────────

    #[test]
    fn verify_round_trip() {
        let proof = make_proof(test_binding());
        let ok = verify(&test_ctx(), &test_template(), &test_claim(), &proof, test_binding())
            .expect("verify should succeed");
        assert!(ok);
    }

    #[test]
    fn offline_round_trip() {
        let binding_ctx = blake3_hash(b"test-offline-ctx");
        let proof = make_proof(binding_ctx);
        let ok = verify_proof_offline(&test_ctx(), "age-gate-21", &test_claim(), &proof, binding_ctx)
            .expect("offline verify should succeed");
        assert!(ok);
    }

    #[test]
    fn verify_with_explicit_template_round_trip() {
        let binding_ctx = blake3_hash(b"test-explicit-template");
        let proof = make_proof(binding_ctx);
        let ok = verify_proof_with_template(&test_ctx(), &test_template(), &test_claim(), &proof, binding_ctx)
            .expect("verify with template should succeed");
        assert!(ok);
    }

    // ── Adversarial ──────────────────────────────────────────────────

    #[test]
    fn unknown_template_rejected() {
        let proof = make_proof([0u8; 32]);
        let result = verify_proof_offline(&test_ctx(), "nonexistent-template", &test_claim(), &proof, [0u8; 32]);
        assert!(matches!(result, Err(VerifyError::UnknownTemplate(_))));
    }

    #[test]
    fn tampered_ms_root_rejected() {
        let binding_ctx = blake3_hash(b"test-tampered-root");
        let proof = make_proof(binding_ctx);
        let mut bundle = ProofBundle::from_proof(&proof);
        let mut root = hex::decode(&bundle.ms_root_hex).unwrap();
        root[0] ^= 0x01;
        bundle.ms_root_hex = hex::encode(root);
        let tampered = bundle.to_proof().unwrap();
        let result = verify(&test_ctx(), &test_template(), &test_claim(), &tampered, binding_ctx);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_binding_context_rejected() {
        let binding_ctx = blake3_hash(b"test-wrong-ctx-a");
        let wrong_ctx = blake3_hash(b"test-wrong-ctx-b");
        let proof = make_proof(binding_ctx);
        let result = verify(&test_ctx(), &test_template(), &test_claim(), &proof, wrong_ctx);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_claim_rejected() {
        let binding_ctx = blake3_hash(b"test-wrong-claim");
        let proof = make_proof(binding_ctx);
        let bad_claim = json!({ "claim": { "age_years": 17 } });
        let result = verify(&test_ctx(), &test_template(), &bad_claim, &proof, binding_ctx);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_binding_entropy_rejected() {
        let binding_ctx = blake3_hash(b"test-tampered-entropy");
        let proof = make_proof(binding_ctx);
        let mut bundle = ProofBundle::from_proof(&proof);
        let mut ent = hex::decode(&bundle.binding_entropy_hex).unwrap();
        ent[0] ^= 0xFF;
        bundle.binding_entropy_hex = hex::encode(ent);
        let tampered = bundle.to_proof().unwrap();
        let result = verify(&test_ctx(), &test_template(), &test_claim(), &tampered, binding_ctx);
        assert!(result.is_err());
    }
}

