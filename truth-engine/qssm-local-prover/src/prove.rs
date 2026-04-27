//! Deterministic prove pipeline: predicates → MS v2 commit → truth binding → LE proof.

use qssm_gadget::{encode_ms_v2_truth_metadata_from_statement_proof, TruthWitnessMsV2};
use qssm_le::{PublicInstance, Witness, BETA, N};
use qssm_ms::{commit_value_v2, prove_predicate_only_v2, PredicateOnlyStatementV2};
use qssm_templates::QssmTemplate;
use qssm_utils::hashing::{
    blake3_hash, hash_domain, DOMAIN_SDK_LE_MASK, DOMAIN_SDK_LE_WITNESS, DOMAIN_SDK_MS_SEED,
};

use crate::context::{Proof, ProofContext};
use crate::error::ZkError;
use zeroize::Zeroize;

const DOMAIN_EXTERNAL_ENTROPY: &str = "QSSM-SDK-EXTERNAL-ENTROPY-v1";
const DOMAIN_MS_V2_PROVER_SEED: &str = "QSSM-SDK-MS-V2-PROVER-SEED-v1";

pub fn prove(
    ctx: &ProofContext,
    template: &QssmTemplate,
    claim: &serde_json::Value,
    value: u64,
    target: u64,
    binding_ctx: [u8; 32],
    mut entropy_seed: [u8; 32],
) -> Result<Proof, ZkError> {
    template.verify_public_claim(claim)?;

    let mut ms_seed = hash_domain(
        DOMAIN_SDK_MS_SEED,
        &[entropy_seed.as_slice(), binding_ctx.as_slice()],
    );
    let binding_entropy = blake3_hash(&binding_ctx);

    let (commitment, witness) =
        commit_value_v2(value, ms_seed, binding_entropy).map_err(ZkError::MsCommit)?;
    ms_seed.zeroize();

    let context = crate::MS_CONTEXT_TAG.to_vec();
    let statement = PredicateOnlyStatementV2::new(
        commitment,
        target,
        binding_entropy,
        binding_ctx,
        context,
    );

    let mut prover_seed = hash_domain(
        DOMAIN_MS_V2_PROVER_SEED,
        &[entropy_seed.as_slice(), binding_ctx.as_slice()],
    );
    let ms_proof = prove_predicate_only_v2(&statement, &witness, prover_seed).map_err(|e| {
        ZkError::MsProve {
            source: e,
            value,
            target,
        }
    })?;
    prover_seed.zeroize();

    let external_entropy = hash_domain(
        DOMAIN_EXTERNAL_ENTROPY,
        &[entropy_seed.as_slice(), binding_ctx.as_slice()],
    );
    let external_entropy_included = false;

    let metadata = encode_ms_v2_truth_metadata_from_statement_proof(
        &statement,
        &ms_proof,
        &external_entropy,
        external_entropy_included,
    )
    .map_err(|_| ZkError::TruthWitnessInvalid)?;

    let commitment_digest = statement.commitment().digest();
    let tw = TruthWitnessMsV2::bind(commitment_digest, binding_ctx, metadata);
    tw.validate().map_err(|_| ZkError::TruthWitnessInvalid)?;

    let public = PublicInstance::digest_coeffs(tw.digest_coeff_vector)
        .map_err(|_| ZkError::TruthWitnessInvalid)?;
    let witness_le = derive_le_witness(&entropy_seed, &binding_ctx);

    let mut le_mask_seed = hash_domain(
        DOMAIN_SDK_LE_MASK,
        &[entropy_seed.as_slice(), binding_ctx.as_slice()],
    );
    let (le_commitment, le_proof) =
        qssm_le::prove_arithmetic(ctx.vk(), &public, &witness_le, &binding_ctx, le_mask_seed)
            .map_err(ZkError::LeProve)?;
    le_mask_seed.zeroize();
    entropy_seed.zeroize();

    Ok(Proof::new(
        commitment_digest,
        statement,
        ms_proof,
        le_commitment,
        le_proof,
        external_entropy,
        external_entropy_included,
        value,
    ))
}

fn derive_le_witness(entropy_seed: &[u8; 32], binding_ctx: &[u8; 32]) -> Witness {
    let beta_i32 = BETA as i32;
    let modulus = 2 * BETA + 1;
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
