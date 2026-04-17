//! # Local Verifier
//!
//! Offline proof verification for QSSM proofs.
//!
//! This crate wraps [`zk_api::verify`] and [`template_lib::resolve`] to provide
//! a single-call entry point that does not require network access.

pub use zk_api::{Proof, ProofContext, ZkError};
pub use template_lib::QssmTemplate;

/// Verify a proof offline using the standard template gallery.
///
/// Resolves the template by `template_id`, then delegates to [`zk_api::verify`].
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
    let template = template_lib::resolve(template_id)
        .ok_or_else(|| VerifyError::UnknownTemplate(template_id.to_owned()))?;
    zk_api::verify(ctx, &template, claim, proof, binding_ctx)
        .map_err(VerifyError::Zk)
}

/// Verify a proof offline with an explicit template.
///
/// Use this when the template was loaded from JSON or constructed manually
/// rather than resolved from the standard gallery.
pub fn verify_proof_with_template(
    ctx: &ProofContext,
    template: &QssmTemplate,
    claim: &serde_json::Value,
    proof: &Proof,
    binding_ctx: [u8; 32],
) -> Result<bool, ZkError> {
    zk_api::verify(ctx, template, claim, proof, binding_ctx)
}

/// Errors from offline verification.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("unknown template: {0}")]
    UnknownTemplate(String),

    #[error(transparent)]
    Zk(#[from] ZkError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use qssm_utils::hashing::blake3_hash;
    use serde_json::json;

    fn test_seed() -> [u8; 32] {
        blake3_hash(b"QSSM-SDK-TEST-SEED")
    }

    #[test]
    fn offline_round_trip() {
        let ctx = ProofContext::new(test_seed());
        let template = QssmTemplate::proof_of_age("age-gate-21");
        let claim = json!({ "claim": { "age_years": 25 } });
        let binding_ctx = blake3_hash(b"test-offline-ctx");

        let proof = zk_api::prove(&ctx, &template, &claim, 100, 50, binding_ctx)
            .expect("prove should succeed");
        let ok = verify_proof_offline(&ctx, "age-gate-21", &claim, &proof, binding_ctx)
            .expect("offline verify should succeed");
        assert!(ok);
    }

    #[test]
    fn unknown_template_rejected() {
        let ctx = ProofContext::new(test_seed());
        let claim = json!({ "claim": { "age_years": 25 } });
        let binding_ctx = [0u8; 32];

        // Create a dummy proof (won't be evaluated - template lookup fails first)
        let template = QssmTemplate::proof_of_age("age-gate-21");
        let proof = zk_api::prove(&ctx, &template, &claim, 100, 50, binding_ctx)
            .expect("prove should succeed");

        let result = verify_proof_offline(&ctx, "nonexistent-template", &claim, &proof, binding_ctx);
        assert!(matches!(result, Err(VerifyError::UnknownTemplate(_))));
    }
}

