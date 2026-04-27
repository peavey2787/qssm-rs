//! Predicate-only MS v2 truth limb: sovereign digest over verifier-visible observables only.
//!
//! Legacy [`super::binding::TruthWitness`] / `encode_proof_metadata_v2` bind GhostMirror (v1)
//! coordinates. This module is the **only** supported path for MS v2 → LE truth binding.

use qssm_ms::{PredicateOnlyProofV2, PredicateOnlyStatementV2};
use qssm_utils::hashing::{hash_domain, DOMAIN_MS};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::circuit::binding::{
    digest_coeff_vector_from_truth_digest, message_limb_from_truth_digest_normative, TruthDigest,
    DIGEST_COEFF_VECTOR_SIZE,
};
use crate::error::GadgetError;

/// Domain tag for the MS v2 predicate-only sovereign limb (distinct from v1 coordinate metadata).
pub const DOMAIN_TRUTH_LIMB_MS_V2: &str = "QSSM-SOVEREIGN-LIMB-MS-V2-v1.0";

/// Fixed width of [`encode_ms_v2_truth_metadata`] output (concat layout, normative).
pub const MS_V2_TRUTH_METADATA_LEN: usize = 32 + 1 + 32 + 32 + 32 + 32 + 1; // statement, result, bitness dig, comp, transcript, extropy, flag

/// Bitness digest matches gadget seam / engine-b tests: `DOMAIN_MS` over `‖len‖‖c0‖…‖c63‖`.
#[must_use]
pub fn digest_bitness_global_challenges_v2(challenges: &[[u8; 32]]) -> [u8; 32] {
    let len_bytes = (challenges.len() as u32).to_le_bytes();
    let mut chunks: Vec<&[u8]> = Vec::with_capacity(1 + challenges.len());
    chunks.push(&len_bytes);
    for challenge in challenges {
        chunks.push(challenge.as_slice());
    }
    hash_domain(DOMAIN_MS, &chunks)
}

/// Canonical MS v2 truth metadata preimage (no coordinates, no witness/blinders).
#[must_use]
pub fn encode_ms_v2_truth_metadata(
    statement_digest: &[u8; 32],
    result_bit: u8,
    bitness_global_challenges_digest: &[u8; 32],
    comparison_global_challenge: &[u8; 32],
    transcript_digest: &[u8; 32],
    external_entropy: &[u8; 32],
    external_entropy_included: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(MS_V2_TRUTH_METADATA_LEN);
    out.extend_from_slice(statement_digest);
    out.push(result_bit & 1);
    out.extend_from_slice(bitness_global_challenges_digest);
    out.extend_from_slice(comparison_global_challenge);
    out.extend_from_slice(transcript_digest);
    out.extend_from_slice(external_entropy);
    out.push(u8::from(external_entropy_included));
    debug_assert_eq!(out.len(), MS_V2_TRUTH_METADATA_LEN);
    out
}

#[must_use]
pub fn truth_digest_ms_v2(
    commitment_digest: &[u8; 32],
    binding_context: &[u8; 32],
    proof_metadata: &[u8],
) -> TruthDigest {
    hash_domain(
        DOMAIN_TRUTH_LIMB_MS_V2,
        &[
            commitment_digest.as_slice(),
            binding_context.as_slice(),
            proof_metadata,
        ],
    )
}

/// Encode metadata from a verified statement + proof (prover and verifier must call this).
pub fn encode_ms_v2_truth_metadata_from_statement_proof(
    statement: &PredicateOnlyStatementV2,
    proof: &PredicateOnlyProofV2,
    external_entropy: &[u8; 32],
    external_entropy_included: bool,
) -> Result<Vec<u8>, GadgetError> {
    let sd = statement.statement_digest();
    if sd != *proof.statement_digest() {
        return Err(GadgetError::TruthWitnessInvalid {
            reason: "statement digest mismatch (statement vs proof)",
        });
    }
    let bitness =
        proof
            .bitness_global_challenges()
            .map_err(|_| GadgetError::TruthWitnessInvalid {
                reason: "bitness global challenges",
            })?;
    let bitness_digest = digest_bitness_global_challenges_v2(&bitness);
    let comparison =
        proof
            .comparison_global_challenge()
            .map_err(|_| GadgetError::TruthWitnessInvalid {
                reason: "comparison global challenge",
            })?;
    let transcript = proof.transcript_digest();
    Ok(encode_ms_v2_truth_metadata(
        &sd,
        u8::from(proof.result()),
        &bitness_digest,
        &comparison,
        &transcript,
        external_entropy,
        external_entropy_included,
    ))
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct TruthWitnessMsV2 {
    /// Value-commitment digest (first sovereign limb chunk).
    pub commitment_digest: [u8; 32],
    pub binding_context: [u8; 32],
    pub proof_metadata: Vec<u8>,
    #[zeroize(skip)]
    pub domain_tag: &'static str,
    pub digest: TruthDigest,
    pub digest_coeff_vector: [u32; DIGEST_COEFF_VECTOR_SIZE],
    #[zeroize(skip)]
    pub limb_bits: [bool; 32],
    #[zeroize(skip)]
    pub message_limb: u64,
}

impl std::fmt::Debug for TruthWitnessMsV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TruthWitnessMsV2")
            .field("commitment_digest", &"[REDACTED]")
            .field("domain_tag", &self.domain_tag)
            .field("message_limb", &self.message_limb)
            .finish()
    }
}

impl TruthWitnessMsV2 {
    #[must_use]
    pub fn bind(
        commitment_digest: [u8; 32],
        binding_context: [u8; 32],
        proof_metadata: Vec<u8>,
    ) -> Self {
        let digest = truth_digest_ms_v2(&commitment_digest, &binding_context, &proof_metadata);
        let digest_coeff_vector = digest_coeff_vector_from_truth_digest(&digest);
        let (limb_bits, message_limb) = message_limb_from_truth_digest_normative(&digest);
        Self {
            commitment_digest,
            binding_context,
            proof_metadata,
            domain_tag: DOMAIN_TRUTH_LIMB_MS_V2,
            digest,
            digest_coeff_vector,
            limb_bits,
            message_limb,
        }
    }

    pub fn validate(&self) -> Result<(), GadgetError> {
        if self.domain_tag != DOMAIN_TRUTH_LIMB_MS_V2 {
            return Err(GadgetError::TruthWitnessInvalid {
                reason: "domain tag mismatch",
            });
        }
        if self.proof_metadata.len() != MS_V2_TRUTH_METADATA_LEN {
            return Err(GadgetError::TruthWitnessInvalid {
                reason: "ms v2 proof metadata length",
            });
        }
        let digest = truth_digest_ms_v2(
            &self.commitment_digest,
            &self.binding_context,
            &self.proof_metadata,
        );
        if !bool::from(digest.ct_eq(&self.digest)) {
            return Err(GadgetError::TruthWitnessInvalid {
                reason: "digest mismatch",
            });
        }
        let coeffs = digest_coeff_vector_from_truth_digest(&self.digest);
        let (limb_bits, message_limb) = message_limb_from_truth_digest_normative(&self.digest);
        let coeffs_ok = coeffs
            .iter()
            .zip(self.digest_coeff_vector.iter())
            .all(|(a, b)| a == b);
        let limb_bits_ok = limb_bits == self.limb_bits;
        let limb_ok = message_limb == self.message_limb;
        if !(coeffs_ok && limb_bits_ok && limb_ok) {
            return Err(GadgetError::TruthWitnessInvalid {
                reason: "coefficient vector or limb mismatch",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qssm_ms::{commit_value_v2, prove_predicate_only_v2};

    #[test]
    fn encode_metadata_len_and_bind_round_trip() {
        let seed = [1u8; 32];
        let binding_entropy = [2u8; 32];
        let binding_ctx = [3u8; 32];
        let (commitment, witness) = commit_value_v2(100, seed, binding_entropy).expect("commit v2");
        let statement = PredicateOnlyStatementV2::new(
            commitment,
            50,
            binding_entropy,
            binding_ctx,
            b"ctx".to_vec(),
        );
        let proof = prove_predicate_only_v2(&statement, &witness, [9u8; 32]).expect("prove v2");
        let ext = [7u8; 32];
        let md = encode_ms_v2_truth_metadata_from_statement_proof(&statement, &proof, &ext, false)
            .expect("encode");
        assert_eq!(md.len(), MS_V2_TRUTH_METADATA_LEN);
        let cd = statement.commitment().digest();
        let tw = TruthWitnessMsV2::bind(cd, binding_ctx, md);
        tw.validate().expect("validate");
    }
}
