//! # QSSM ZK API
//!
//! Stable 5-call SDK for zero-knowledge predicate proofs.
//!
//! ## Quick start
//!
//! ```no_run
//! use zk_api::{ProofContext, prove, verify};
//! use template_lib::QssmTemplate;
//! use serde_json::json;
//!
//! let ctx = ProofContext::new([0u8; 32]);
//! let template = QssmTemplate::proof_of_age("age-21");
//! let claim = json!({ "claim": { "age_years": 25 } });
//! let binding_ctx = [0u8; 32];
//!
//! let proof = prove(&ctx, &template, &claim, 100, 50, binding_ctx).unwrap();
//! assert!(verify(&ctx, &template, &claim, &proof, binding_ctx).unwrap());
//! ```

use qssm_gadget::binding::SovereignWitness;
use qssm_gadget::entropy::EntropyProvider;
use qssm_le::{
    Commitment, LatticeProof, PublicInstance, VerifyingKey, Witness, N,
};
use qssm_ms::{self, GhostMirrorProof, Root};
use qssm_utils::hashing::blake3_hash;
use template_lib::QssmTemplate;

pub use qssm_wrapper::{SovereignStreamManager, StreamError};
pub use template_lib;

/// Verification / proving context seeded from a 32-byte key.
#[derive(Debug, Clone)]
pub struct ProofContext {
    pub vk: VerifyingKey,
    seed: [u8; 32],
}

impl ProofContext {
    /// Create a new proof context from a 32-byte seed.
    ///
    /// Both prover and verifier must use the same seed.
    #[must_use]
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            vk: VerifyingKey::from_seed(seed),
            seed,
        }
    }

    /// The seed used to create this context.
    #[must_use]
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }
}

/// Bundle of all proof artifacts needed for verification.
#[derive(Debug, Clone)]
pub struct Proof {
    /// Ghost-Mirror inequality proof.
    pub ms_root: [u8; 32],
    pub ms_proof: GhostMirrorProof,
    /// Lattice proof over the sovereign digest.
    pub le_commitment: Commitment,
    pub le_proof: LatticeProof,
    /// Sovereign binding witness metadata (for recomputation during verify).
    pub sovereign_digest: [u8; 32],
    pub digest_coeff_vector: [u32; 64],
    pub message_limb: u64,
    /// MS inputs needed for verification.
    pub value: u64,
    pub target: u64,
    pub binding_entropy: [u8; 32],
}

/// Errors from the SDK prove/verify calls.
#[derive(Debug, thiserror::Error)]
pub enum ZkError {
    #[error("template predicate check failed: {0}")]
    PredicateFailed(#[from] template_lib::PredicateError),

    #[error("MS commit failed: {0}")]
    MsCommit(#[source] qssm_ms::MsError),

    #[error("MS prove failed (value={value}, target={target})")]
    MsProve {
        #[source]
        source: qssm_ms::MsError,
        value: u64,
        target: u64,
    },

    #[error("MS verification failed")]
    MsVerifyFailed,

    #[error("LE prove failed: {0}")]
    LeProve(#[source] qssm_le::LeError),

    #[error("LE verification failed: {0}")]
    LeVerify(#[source] qssm_le::LeError),

    #[error("LE verification returned false")]
    LeVerifyFailed,

    #[error("sovereign witness validation failed")]
    SovereignWitnessInvalid,
}

/// Prove a claim against a template.
///
/// - `value` / `target`: the MS inequality inputs (`value > target`).
/// - `binding_ctx`: 32-byte external binding context (e.g. hash of anchor, session, etc.).
///
/// Returns a [`Proof`] bundle that can be serialized and sent to a verifier.
pub fn prove(
    ctx: &ProofContext,
    template: &QssmTemplate,
    claim: &serde_json::Value,
    value: u64,
    target: u64,
    binding_ctx: [u8; 32],
) -> Result<Proof, ZkError> {
    // 1. Check predicates against the public claim.
    template.verify_public_claim(claim)?;

    // 2. MS: commit + prove inequality.
    let seed = blake3_hash(b"QSSM-SDK-MS-SEED-v1");
    let binding_entropy = blake3_hash(&binding_ctx);
    let (root, salts) = qssm_ms::commit(value, seed, binding_entropy)
        .map_err(ZkError::MsCommit)?;
    let context = b"qssm-sdk-v1".to_vec();
    let ms_proof = qssm_ms::prove(value, target, &salts, binding_entropy, &context, &binding_ctx)
        .map_err(|e| ZkError::MsProve { source: e, value, target })?;

    // 3. Sovereign binding: state_root from MS root, bind to context.
    let challenge = ms_proof.challenge;
    let entropy_provider = EntropyProvider::simulate_nist_down();
    let (sovereign_entropy, nist_included) = entropy_provider
        .generate_sovereign_entropy(binding_ctx, binding_entropy);
    let sw = SovereignWitness::bind(
        root.0,
        binding_ctx,
        ms_proof.n,
        ms_proof.k,
        ms_proof.bit_at_k,
        challenge,
        sovereign_entropy,
        nist_included,
    );
    if !sw.validate() {
        return Err(ZkError::SovereignWitnessInvalid);
    }

    // 4. LE: lattice proof over digest coefficients.
    let public = PublicInstance::digest_coeffs(sw.digest_coeff_vector);
    let mut r = [0i32; N];
    r[0] = 1;
    r[1] = -1;
    let witness = Witness { r };
    let (le_commitment, le_proof) = qssm_le::prove_arithmetic(
        &ctx.vk, &public, &witness, &binding_ctx,
    ).map_err(ZkError::LeProve)?;

    Ok(Proof {
        ms_root: root.0,
        ms_proof,
        le_commitment,
        le_proof,
        sovereign_digest: sw.digest,
        digest_coeff_vector: sw.digest_coeff_vector,
        message_limb: sw.message_limb,
        value,
        target,
        binding_entropy,
    })
}

/// Verify a proof against a template and public claim.
///
/// Returns `Ok(true)` if the proof is valid.
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
    let root = Root(proof.ms_root);
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

    // 3. LE: verify the lattice proof over digest coefficients.
    let public = PublicInstance::digest_coeffs(proof.digest_coeff_vector);
    let ok = qssm_le::verify_lattice(
        &ctx.vk, &public, &proof.le_commitment, &proof.le_proof, &binding_ctx,
    ).map_err(ZkError::LeVerify)?;
    if !ok {
        return Err(ZkError::LeVerifyFailed);
    }

    Ok(true)
}

/// Create a new proof stream for append-only proof accumulation.
///
/// Wraps [`SovereignStreamManager::create`] — see `qssm-wrapper` for details.
pub fn create_proof_stream(
    root_dir: impl AsRef<std::path::Path>,
    binding_ctx: [u8; 32],
) -> Result<SovereignStreamManager, StreamError> {
    SovereignStreamManager::create(root_dir, binding_ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_seed() -> [u8; 32] {
        blake3_hash(b"QSSM-SDK-TEST-SEED")
    }

    #[test]
    fn prove_and_verify_round_trip() {
        let ctx = ProofContext::new(test_seed());
        let template = QssmTemplate::proof_of_age("test-age");
        let claim = json!({ "claim": { "age_years": 25 } });
        let binding_ctx = blake3_hash(b"test-binding-context");

        let proof = prove(&ctx, &template, &claim, 100, 50, binding_ctx)
            .expect("prove should succeed");
        let ok = verify(&ctx, &template, &claim, &proof, binding_ctx)
            .expect("verify should succeed");
        assert!(ok);
    }

    #[test]
    fn verify_rejects_wrong_binding_context() {
        let ctx = ProofContext::new(test_seed());
        let template = QssmTemplate::proof_of_age("test-age");
        let claim = json!({ "claim": { "age_years": 25 } });
        let binding_ctx = blake3_hash(b"correct-ctx");

        let proof = prove(&ctx, &template, &claim, 100, 50, binding_ctx)
            .expect("prove should succeed");

        let wrong_ctx = blake3_hash(b"wrong-ctx");
        let result = verify(&ctx, &template, &claim, &proof, wrong_ctx);
        assert!(result.is_err());
    }

    #[test]
    fn predicate_failure_rejects_early() {
        let ctx = ProofContext::new(test_seed());
        let template = QssmTemplate::proof_of_age("test-age");
        let claim = json!({ "claim": { "age_years": 15 } });
        let binding_ctx = [0u8; 32];

        let result = prove(&ctx, &template, &claim, 100, 50, binding_ctx);
        assert!(result.is_err());
    }

    #[test]
    fn create_proof_stream_works() {
        let dir = tempfile::tempdir().unwrap();
        let binding_ctx = [0x42u8; 32];
        let mgr = create_proof_stream(dir.path(), binding_ctx);
        assert!(mgr.is_ok());
    }
}

