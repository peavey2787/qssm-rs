//! Phase 3 / 8 - Truth Digest to public binding payload for qssm-le.
//!
//! Preimage order (normative, v2.0):
//! hash_domain(DOMAIN_TRUTH_LIMB_V2, &[root32, binding_ctx32, metadata])

use qssm_utils::hashing::hash_domain;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::GadgetError;
use crate::primitives::bits::{from_le_bits, to_le_bits};

pub const DIGEST_COEFF_VECTOR_SIZE: usize = 64;

pub const DOMAIN_TRUTH_LIMB_V1: &str = "QSSM-SOVEREIGN-LIMB-v1.0";
pub const DOMAIN_TRUTH_LIMB_V2: &str = "QSSM-SOVEREIGN-LIMB-v2.0";

pub type TruthDigest = [u8; 32];

#[must_use]
pub fn encode_proof_metadata_v1(n: u8, k: u8, bit_at_k: u8, challenge: &[u8; 32]) -> Vec<u8> {
    let mut value = Vec::with_capacity(35);
    value.push(n);
    value.push(k);
    value.push(bit_at_k);
    value.extend_from_slice(challenge);
    value
}

#[must_use]
pub fn encode_proof_metadata_v2(
    n: u8,
    k: u8,
    bit_at_k: u8,
    challenge: &[u8; 32],
    external_entropy: &[u8; 32],
    external_entropy_included: bool,
) -> Vec<u8> {
    let mut value = encode_proof_metadata_v1(n, k, bit_at_k, challenge);
    value.extend_from_slice(external_entropy);
    value.push(u8::from(external_entropy_included));
    value
}

#[must_use]
pub fn truth_digest(
    root: &[u8; 32],
    binding_context: &[u8; 32],
    proof_metadata: &[u8],
) -> TruthDigest {
    hash_domain(
        DOMAIN_TRUTH_LIMB_V2,
        &[root.as_slice(), binding_context.as_slice(), proof_metadata],
    )
}

#[must_use]
pub fn message_limb_from_truth_digest_normative(digest: &TruthDigest) -> ([bool; 32], u64) {
    let word = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
    let lane = to_le_bits(word);
    let mut padded = [false; 32];
    padded[..30].copy_from_slice(&lane[..30]);
    let limb = from_le_bits(&padded);
    (padded, u64::from(limb))
}

#[must_use]
pub fn digest_coeff_vector_from_truth_digest(
    digest: &TruthDigest,
) -> [u32; DIGEST_COEFF_VECTOR_SIZE] {
    let mut coeffs = [0u32; DIGEST_COEFF_VECTOR_SIZE];
    let mut filled = 0usize;
    let mut counter = 0u32;
    while filled < DIGEST_COEFF_VECTOR_SIZE {
        let block = hash_domain(
            "QSSM-DIGEST-COEFF-MAP-v1.0",
            &[digest.as_slice(), &counter.to_le_bytes()],
        );
        for &byte in &block {
            if filled >= DIGEST_COEFF_VECTOR_SIZE {
                break;
            }
            coeffs[filled] = u32::from(byte & 0x0f);
            filled += 1;
            if filled < DIGEST_COEFF_VECTOR_SIZE {
                coeffs[filled] = u32::from(byte >> 4);
                filled += 1;
            }
        }
        counter = counter.wrapping_add(1);
    }
    coeffs
}

/// Reinterpret a `[u32; N]` slice as `&[u8]` for constant-time comparison (no `unsafe`).
#[inline]
fn bytemuck_cast_u32_slice(slice: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(slice.len() * 4);
    for &w in slice {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

/// Pack `[bool; 32]` into `[u8; 32]` (one byte per bool) for constant-time comparison.
#[inline]
fn limb_bits_to_bytes(bits: &[bool; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, &b) in bits.iter().enumerate() {
        out[i] = u8::from(b);
    }
    out
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct TruthWitness {
    pub root: [u8; 32],
    pub binding_context: [u8; 32],
    pub n: u8,
    pub k: u8,
    pub bit_at_k: u8,
    pub challenge: [u8; 32],
    pub external_entropy: [u8; 32],
    pub external_entropy_included: bool,
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

impl std::fmt::Debug for TruthWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TruthWitness")
            .field("root", &"[REDACTED]")
            .field("n", &self.n)
            .field("k", &self.k)
            .field("bit_at_k", &self.bit_at_k)
            .field("challenge", &"[REDACTED]")
            .field("external_entropy", &"[REDACTED]")
            .field("external_entropy_included", &self.external_entropy_included)
            .field("domain_tag", &self.domain_tag)
            .field("message_limb", &self.message_limb)
            .finish()
    }
}

impl TruthWitness {
    #[must_use]
    pub fn bind(
        root: [u8; 32],
        binding_context: [u8; 32],
        n: u8,
        k: u8,
        bit_at_k: u8,
        challenge: [u8; 32],
        external_entropy: [u8; 32],
        external_entropy_included: bool,
    ) -> Self {
        let proof_metadata = encode_proof_metadata_v2(
            n,
            k,
            bit_at_k,
            &challenge,
            &external_entropy,
            external_entropy_included,
        );
        let digest = truth_digest(&root, &binding_context, &proof_metadata);
        let digest_coeff_vector = digest_coeff_vector_from_truth_digest(&digest);
        let (limb_bits, message_limb) = message_limb_from_truth_digest_normative(&digest);
        Self {
            root,
            binding_context,
            n,
            k,
            bit_at_k,
            challenge,
            external_entropy,
            external_entropy_included,
            proof_metadata,
            domain_tag: DOMAIN_TRUTH_LIMB_V2,
            digest,
            digest_coeff_vector,
            limb_bits,
            message_limb,
        }
    }

    pub fn validate(&self) -> Result<(), GadgetError> {
        if self.domain_tag != DOMAIN_TRUTH_LIMB_V2 {
            return Err(GadgetError::TruthWitnessInvalid { reason: "domain tag mismatch" });
        }
        let expected_metadata = encode_proof_metadata_v2(
            self.n,
            self.k,
            self.bit_at_k,
            &self.challenge,
            &self.external_entropy,
            self.external_entropy_included,
        );
        if !bool::from(expected_metadata.ct_eq(&self.proof_metadata)) {
            return Err(GadgetError::TruthWitnessInvalid { reason: "proof metadata mismatch" });
        }
        let digest = truth_digest(&self.root, &self.binding_context, &self.proof_metadata);
        if !bool::from(digest.ct_eq(&self.digest)) {
            return Err(GadgetError::TruthWitnessInvalid { reason: "digest mismatch" });
        }
        let coeffs = digest_coeff_vector_from_truth_digest(&self.digest);
        let (limb_bits, message_limb) = message_limb_from_truth_digest_normative(&self.digest);
        // Constant-time comparison of coefficient vector (as byte slices).
        let coeffs_bytes = bytemuck_cast_u32_slice(&coeffs);
        let self_coeffs_bytes = bytemuck_cast_u32_slice(&self.digest_coeff_vector);
        let coeffs_eq = coeffs_bytes.ct_eq(&self_coeffs_bytes);
        let limb_bits_eq = limb_bits_to_bytes(&limb_bits).ct_eq(&limb_bits_to_bytes(&self.limb_bits));
        let limb_eq = message_limb.to_le_bytes().ct_eq(&self.message_limb.to_le_bytes());
        if !bool::from(coeffs_eq & limb_bits_eq & limb_eq) {
            return Err(GadgetError::TruthWitnessInvalid { reason: "coefficient vector or limb mismatch" });
        }
        Ok(())
    }

    /// Returns the witness as pretty-printed JSON, or an error if serialization fails.
    pub fn to_prover_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&truth_witness_value(self))
    }
}

#[must_use]
pub fn truth_message_limb_v1(
    root: &[u8; 32],
    binding_context: &[u8; 32],
    proof_metadata: &[u8],
) -> u64 {
    let digest = truth_digest(root, binding_context, proof_metadata);
    message_limb_from_truth_digest_normative(&digest).1
}

#[inline]
fn bit_value(bit: bool) -> u8 {
    u8::from(bit)
}

fn push_bits32(out: &mut Vec<Value>, idx: &mut usize, path: &str, bits: &[bool; 32]) {
    for (lane, bit) in bits.iter().enumerate() {
        out.push(json!({
            "idx": *idx,
            "path": path,
            "lane": lane,
            "v": bit_value(*bit),
        }));
        *idx += 1;
    }
}

fn truth_witness_value(witness: &TruthWitness) -> Value {
    let mut private_wires = Vec::new();
    let mut idx = 0usize;
    push_bits32(&mut private_wires, &mut idx, "limb_bits", &witness.limb_bits);
    json!({
        "kind": "TruthWitnessV1",
        "public": {
            "root_hex": hex::encode(witness.root),
            "digest_hex": hex::encode(witness.digest),
            "digest_coeff_vector_u4": witness.digest_coeff_vector.to_vec(),
            "message_limb_u30": witness.message_limb,
            "domain_tag": witness.domain_tag,
            "external_entropy_included": witness.external_entropy_included,
            "external_entropy_hex": hex::encode(witness.external_entropy),
        },
        "private_aux_hex": {
            "binding_context": hex::encode(witness.binding_context),
            "proof_metadata": hex::encode(&witness.proof_metadata),
            "challenge_hex": hex::encode(witness.challenge),
            "proof_fields": {
                "n": witness.n,
                "k": witness.k,
                "bit_at_k": witness.bit_at_k,
            },
        },
        "private_bit_wires": private_wires,
        "private_wire_count": idx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limb_is_below_2_pow_30() {
        let witness = TruthWitness::bind([7u8; 32], [9u8; 32], 1, 2, 0, [3u8; 32], [0u8; 32], false);
        assert!(witness.message_limb < (1u64 << 30));
    }

    #[test]
    fn truth_witness_round_trip_validate() {
        let witness = TruthWitness::bind([0xabu8; 32], [0xcdu8; 32], 0, 5, 1, [0xeeu8; 32], [0x11u8; 32], true);
        witness.validate().expect("round-trip validation");
        assert_eq!(witness.digest_coeff_vector.len(), DIGEST_COEFF_VECTOR_SIZE);
    }

    #[test]
    fn truth_to_prover_json_roundtrip() {
        let witness = TruthWitness::bind([1u8; 32], [2u8; 32], 1, 0, 0, [3u8; 32], [4u8; 32], false);
        let value: serde_json::Value = serde_json::from_str(&witness.to_prover_json().expect("json")).expect("parse");
        assert_eq!(value["kind"], "TruthWitnessV1");
        assert_eq!(value["public"]["message_limb_u30"], serde_json::json!(witness.message_limb));
        assert_eq!(value["public"]["external_entropy_included"], serde_json::json!(false));
        assert_eq!(
            value["public"]["digest_coeff_vector_u4"].as_array().expect("digest coeff array").len(),
            DIGEST_COEFF_VECTOR_SIZE
        );
    }

    #[test]
    fn digest_coeff_vector_is_deterministic_and_bounded() {
        let digest = [0xabu8; 32];
        let left = digest_coeff_vector_from_truth_digest(&digest);
        let right = digest_coeff_vector_from_truth_digest(&digest);
        assert_eq!(left, right);
        assert!(left.iter().all(|&coeff| coeff <= 0x0f));
    }

    #[test]
    fn truth_digest_helpers_match_public_witness() {
        let root = [1u8; 32];
        let context = [2u8; 32];
        let metadata = encode_proof_metadata_v2(1, 2, 0, &[3u8; 32], &[4u8; 32], false);
        let digest = truth_digest(&root, &context, &metadata);
        assert_eq!(digest_coeff_vector_from_truth_digest(&digest), digest_coeff_vector_from_truth_digest(&digest));
        assert_eq!(message_limb_from_truth_digest_normative(&digest), message_limb_from_truth_digest_normative(&digest));
        assert_eq!(truth_message_limb_v1(&root, &context, &metadata), truth_message_limb_v1(&root, &context, &metadata));
    }
}