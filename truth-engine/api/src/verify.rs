//! Cross-engine rebinding verification: MS → truth digest → LE lattice check.

use qssm_gadget::{
    digest_coeff_vector_from_truth_digest, encode_proof_metadata_v2, truth_digest,
};
use qssm_le::PublicInstance;
use qssm_ms::{self, Root};
use template_lib::QssmTemplate;

use crate::context::{Proof, ProofContext};
use crate::error::ZkError;

/// Verify a proof against a template and public claim.
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
    let context = b"qssm-sdk-v1".to_vec();
    let root = Root::new(proof.ms_root);
    if !qssm_ms::verify(
        root,
        &proof.ms_proof,
        proof.binding_entropy,
        proof.value,
        proof.target,
        &context,
        &binding_ctx,
    ) {
        return Err(ZkError::MsVerifyFailed);
    }

    // 3. CROSS-ENGINE REBINDING — Math is Law.
    //    Recompute truth digest from MS proof metadata + external entropy.
    //    The prover CANNOT lie about the LE public instance.
    let metadata = encode_proof_metadata_v2(
        proof.ms_proof.n(),
        proof.ms_proof.k(),
        proof.ms_proof.bit_at_k(),
        proof.ms_proof.challenge(),
        &proof.external_entropy,
        proof.external_entropy_included,
    );
    let recomputed_digest = truth_digest(&proof.ms_root, &binding_ctx, &metadata);
    let recomputed_coeffs = digest_coeff_vector_from_truth_digest(&recomputed_digest);

    // 4. LE: verify the lattice proof against the RECOMPUTED public instance.
    let public = PublicInstance::digest_coeffs(recomputed_coeffs)
        .map_err(ZkError::LeVerify)?;
    let ok = qssm_le::verify_lattice(
        &ctx.vk, &public, &proof.le_commitment, &proof.le_proof, &binding_ctx,
    ).map_err(ZkError::LeVerify)?;
    if !ok {
        return Err(ZkError::LeVerifyFailed);
    }

    Ok(true)
}
