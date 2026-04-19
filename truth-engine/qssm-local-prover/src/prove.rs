//! Deterministic prove pipeline: predicates → MS commit → truth binding → LE proof.

use qssm_gadget::TruthWitness;
use qssm_le::{PublicInstance, Witness, BETA, N};
use qssm_templates::QssmTemplate;
use qssm_utils::hashing::{
    blake3_hash, hash_domain, DOMAIN_SDK_LE_MASK, DOMAIN_SDK_LE_WITNESS, DOMAIN_SDK_MS_SEED,
};

use crate::context::{Proof, ProofContext};
use crate::error::ZkError;
use zeroize::Zeroize;

/// Domain tag for deriving external entropy from caller-provided seed + binding context.
const DOMAIN_EXTERNAL_ENTROPY: &str = "QSSM-SDK-EXTERNAL-ENTROPY-v1";

/// Produce a complete ZK proof artifact.
///
/// - `ctx`: the proof context (seed + verifying key).
/// - `template`: the predicate template (rules to check the public claim against).
/// - `claim`: the public JSON claim (checked against template predicates).
/// - `value` / `target`: the MS inequality inputs (`value > target`).
/// - `binding_ctx`: 32-byte external binding context (e.g. hash of anchor,
///   session, etc.).
/// - `entropy_seed`: 32-byte verifiable entropy from the caller (device sensor
///   jitter, harvester output, etc.). **Never** generated internally — the SDK
///   is deterministic given the same inputs.
///
/// All internal secrets (MS commitment salt, LE witness, Lyubashevsky masking)
/// are derived from `BLAKE3(domain ‖ entropy_seed ‖ binding_ctx)`.
/// Two calls with identical arguments produce identical proofs.
pub fn prove(
    ctx: &ProofContext,
    template: &QssmTemplate,
    claim: &serde_json::Value,
    value: u64,
    target: u64,
    binding_ctx: [u8; 32],
    mut entropy_seed: [u8; 32],
) -> Result<Proof, ZkError> {
    // 1. Check predicates against the public claim.
    template.verify_public_claim(claim)?;

    // 2. Deterministic key schedule — everything derives from entropy_seed + binding_ctx.
    let mut ms_seed = hash_domain(
        DOMAIN_SDK_MS_SEED,
        &[entropy_seed.as_slice(), binding_ctx.as_slice()],
    );
    let binding_entropy = blake3_hash(&binding_ctx);

    // 3. MS: commit + prove inequality.
    let (root, salts) = qssm_ms::commit(ms_seed, binding_entropy).map_err(ZkError::MsCommit)?;
    ms_seed.zeroize();
    let context = crate::MS_CONTEXT_TAG.to_vec();
    let ms_proof = qssm_ms::prove(
        value,
        target,
        &salts,
        binding_entropy,
        &context,
        &binding_ctx,
    )
    .map_err(|e| ZkError::MsProve {
        source: e,
        value,
        target,
    })?;

    // 4. Truth binding: derive digest from MS root + proof metadata.
    let external_entropy = hash_domain(
        DOMAIN_EXTERNAL_ENTROPY,
        &[entropy_seed.as_slice(), binding_ctx.as_slice()],
    );
    let external_entropy_included = false;
    let tw = TruthWitness::bind(
        *root.as_bytes(),
        binding_ctx,
        ms_proof.n(),
        ms_proof.k(),
        ms_proof.bit_at_k(),
        *ms_proof.challenge(),
        external_entropy,
        external_entropy_included,
    );
    tw.validate().map_err(|_| ZkError::TruthWitnessInvalid)?;

    // 5. LE witness: deterministic short vector r ∈ [-BETA, BETA]^N.
    let public = PublicInstance::digest_coeffs(tw.digest_coeff_vector)
        .map_err(|_| ZkError::TruthWitnessInvalid)?;
    let witness = derive_le_witness(&entropy_seed, &binding_ctx);

    // 6. LE prove: deterministic Lyubashevsky masking from seeded CSPRNG.
    let mut le_mask_seed = hash_domain(
        DOMAIN_SDK_LE_MASK,
        &[entropy_seed.as_slice(), binding_ctx.as_slice()],
    );
    let (le_commitment, le_proof) =
        qssm_le::prove_arithmetic(ctx.vk(), &public, &witness, &binding_ctx, le_mask_seed)
            .map_err(ZkError::LeProve)?;
    le_mask_seed.zeroize();
    entropy_seed.zeroize();

    Ok(Proof::new(
        *root.as_bytes(),
        ms_proof,
        le_commitment,
        le_proof,
        external_entropy,
        external_entropy_included,
        value,
        target,
        binding_entropy,
    ))
}

/// Deterministic LE witness: `r[i] ∈ [-BETA, BETA]` from
/// `BLAKE3("QSSM-SDK-LE-WITNESS-v1" ‖ entropy_seed ‖ binding_ctx ‖ chunk_idx)`.
fn derive_le_witness(entropy_seed: &[u8; 32], binding_ctx: &[u8; 32]) -> Witness {
    let beta_i32 = BETA as i32;
    let modulus = 2 * BETA + 1; // 17
    let mut r = [0i32; N];
    for chunk_idx in 0u32..32 {
        let idx_bytes = chunk_idx.to_le_bytes();
        let h = hash_domain(
            DOMAIN_SDK_LE_WITNESS,
            &[entropy_seed.as_slice(), binding_ctx.as_slice(), &idx_bytes],
        );
        for j in 0..8 {
            let offset = j * 4;
            let raw = u32::from_le_bytes([h[offset], h[offset + 1], h[offset + 2], h[offset + 3]]);
            r[chunk_idx as usize * 8 + j] = (raw % modulus) as i32 - beta_i32;
        }
    }
    let witness = Witness::new(r);
    r.zeroize();
    witness
}
