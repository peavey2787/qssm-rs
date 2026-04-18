#![forbid(unsafe_code)]
//! # QSSM Local Prover
//!
//! Deterministic prove pipeline: predicates → MS commit → truth binding → LE proof.
//!
//! This crate contains the proving logic for QSSM zero-knowledge proofs.
//! For verification, see `qssm-api`.

use qssm_gadget::TruthWitness;
use qssm_le::{PublicInstance, Witness, BETA, N};
use qssm_ms;
use qssm_utils::hashing::{
    blake3_hash, hash_domain, DOMAIN_SDK_LE_MASK, DOMAIN_SDK_LE_WITNESS, DOMAIN_SDK_MS_SEED,
};
use qssm_templates::QssmTemplate;

use qssm_api::{Proof, ProofContext, ZkError};

/// Domain tag for deriving external entropy from caller-provided seed + binding context.
const DOMAIN_EXTERNAL_ENTROPY: &str = "QSSM-SDK-EXTERNAL-ENTROPY-v1";

/// Prove a claim against a template.
///
/// - `value` / `target`: the MS inequality inputs (`value > target`).
/// - `binding_ctx`: 32-byte external binding context (e.g. hash of anchor, session, etc.).
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
    entropy_seed: [u8; 32],
) -> Result<Proof, ZkError> {
    // 1. Check predicates against the public claim.
    template.verify_public_claim(claim)?;

    // 2. Deterministic key schedule — everything derives from entropy_seed + binding_ctx.
    let ms_seed = hash_domain(
        DOMAIN_SDK_MS_SEED,
        &[entropy_seed.as_slice(), binding_ctx.as_slice()],
    );
    let binding_entropy = blake3_hash(&binding_ctx);

    // 3. MS: commit + prove inequality.
    let (root, salts) = qssm_ms::commit(ms_seed, binding_entropy)
        .map_err(ZkError::MsCommit)?;
    let context = qssm_api::MS_CONTEXT_TAG.to_vec();
    let ms_proof = qssm_ms::prove(value, target, &salts, binding_entropy, &context, &binding_ctx)
        .map_err(|e| ZkError::MsProve { source: e, value, target })?;

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
    let le_mask_seed = hash_domain(
        DOMAIN_SDK_LE_MASK,
        &[entropy_seed.as_slice(), binding_ctx.as_slice()],
    );
    let (le_commitment, le_proof) = qssm_le::prove_arithmetic(
        ctx.vk(), &public, &witness, &binding_ctx, le_mask_seed,
    ).map_err(ZkError::LeProve)?;

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
    Witness::new(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qssm_utils::hashing::blake3_hash;
    use serde_json::json;
    use qssm_api::{ProofBundle, WireFormatError};

    fn test_seed() -> [u8; 32] {
        blake3_hash(b"QSSM-SDK-TEST-SEED")
    }

    fn test_entropy() -> [u8; 32] {
        blake3_hash(b"QSSM-SDK-TEST-ENTROPY")
    }

    fn test_binding_ctx() -> [u8; 32] {
        blake3_hash(b"test-binding-context")
    }

    fn test_template() -> qssm_templates::QssmTemplate {
        qssm_templates::QssmTemplate::proof_of_age("test-age")
    }

    fn test_claim() -> serde_json::Value {
        json!({ "claim": { "age_years": 25 } })
    }

    fn make_proof() -> Proof {
        let ctx = ProofContext::new(test_seed());
        prove(&ctx, &test_template(), &test_claim(), 100, 50, test_binding_ctx(), test_entropy())
            .expect("prove should succeed")
    }

    // ── Witness derivation ───────────────────────────────────────────

    #[test]
    fn derive_le_witness_deterministic_and_bounded() {
        let seed = test_entropy();
        let ctx = test_binding_ctx();
        let w1 = derive_le_witness(&seed, &ctx);
        let w2 = derive_le_witness(&seed, &ctx);
        let beta = BETA as i32;
        assert_eq!(w1.coeffs(), w2.coeffs());
        for (i, &c) in w1.coeffs().iter().enumerate() {
            assert!(
                (-beta..=beta).contains(&c),
                "coefficient {i} = {c} is outside [-{beta}, {beta}]"
            );
        }
        assert_eq!(w1.coeffs().len(), N);
    }

    // ── Round-trip ───────────────────────────────────────────────────

    #[test]
    fn prove_and_verify_round_trip() {
        let ctx = ProofContext::new(test_seed());
        let proof = make_proof();
        let ok = qssm_api::verify(&ctx, &test_template(), &test_claim(), &proof, test_binding_ctx())
            .expect("verify should succeed");
        assert!(ok);
    }

    // ── Adversarial verify tests ─────────────────────────────────────

    #[test]
    fn tampered_ms_root_rejected() {
        let ctx = ProofContext::new(test_seed());
        let proof = make_proof();
        let mut bundle = ProofBundle::from_proof(&proof);
        let mut root = hex::decode(&bundle.ms_root_hex).unwrap();
        root[0] ^= 0x01;
        bundle.ms_root_hex = hex::encode(root);
        let tampered = bundle.to_proof().unwrap();
        let err = qssm_api::verify(&ctx, &test_template(), &test_claim(), &tampered, test_binding_ctx())
            .unwrap_err();
        assert!(matches!(err, ZkError::MsVerifyFailed));
    }

    #[test]
    fn wrong_binding_context_rejected() {
        let ctx = ProofContext::new(test_seed());
        let proof = make_proof();
        let wrong_ctx = blake3_hash(b"WRONG-binding-context");
        let err = qssm_api::verify(&ctx, &test_template(), &test_claim(), &proof, wrong_ctx)
            .unwrap_err();
        assert!(matches!(err, ZkError::MsVerifyFailed));
    }

    #[test]
    fn tampered_external_entropy_rejected() {
        let ctx = ProofContext::new(test_seed());
        let proof = make_proof();
        let mut bundle = ProofBundle::from_proof(&proof);
        let mut ent = hex::decode(&bundle.external_entropy_hex).unwrap();
        ent[0] ^= 0xFF;
        bundle.external_entropy_hex = hex::encode(ent);
        let tampered = bundle.to_proof().unwrap();
        let err = qssm_api::verify(&ctx, &test_template(), &test_claim(), &tampered, test_binding_ctx())
            .unwrap_err();
        assert!(
            matches!(err, ZkError::LeVerify(_) | ZkError::LeVerifyFailed | ZkError::RebindingMismatch),
            "expected LE or rebinding failure, got: {err}"
        );
    }

    #[test]
    fn wrong_claim_rejected() {
        let ctx = ProofContext::new(test_seed());
        let proof = make_proof();
        let wrong_claim = json!({ "claim": { "age_years": 15 } });
        let err = qssm_api::verify(&ctx, &test_template(), &wrong_claim, &proof, test_binding_ctx())
            .unwrap_err();
        assert!(matches!(err, ZkError::PredicateFailed(_)));
    }

    #[test]
    fn wrong_value_target_rejected() {
        let ctx = ProofContext::new(test_seed());
        let proof = make_proof();
        // Tamper via wire round-trip: swap value and target.
        let mut bundle = ProofBundle::from_proof(&proof);
        std::mem::swap(&mut bundle.value, &mut bundle.target);
        let tampered = bundle.to_proof().unwrap();
        let err = qssm_api::verify(&ctx, &test_template(), &test_claim(), &tampered, test_binding_ctx())
            .unwrap_err();
        assert!(matches!(err, ZkError::MsVerifyFailed));
    }

    // ── Wire format round-trip ───────────────────────────────────────

    #[test]
    fn wire_round_trip_json() {
        let ctx = ProofContext::new(test_seed());
        let proof = make_proof();
        let bundle = ProofBundle::from_proof(&proof);
        let json = serde_json::to_string(&bundle).expect("serialize");
        let bundle2: ProofBundle = serde_json::from_str(&json).expect("deserialize");
        let proof2 = bundle2.to_proof().expect("to_proof");
        let ok = qssm_api::verify(&ctx, &test_template(), &test_claim(), &proof2, test_binding_ctx())
            .expect("verify should succeed");
        assert!(ok);
    }

    #[test]
    fn wire_format_forward_compat() {
        let proof = make_proof();
        let bundle = ProofBundle::from_proof(&proof);
        let json = serde_json::to_string(&bundle).expect("serialize");
        let parsed: ProofBundle = serde_json::from_str(&json).expect(
            "old bundle must remain parseable by current (and future) code",
        );
        let recovered = parsed.to_proof().expect("to_proof");
        assert_eq!(recovered.ms_root(), proof.ms_root());
        assert_eq!(recovered.value(), proof.value());
        assert_eq!(recovered.target(), proof.target());
    }

    // ── Wire format rejection tests ──────────────────────────────────

    #[test]
    fn wire_rejects_bad_version() {
        let proof = make_proof();
        let mut bundle = ProofBundle::from_proof(&proof);
        bundle.version = 99;
        let json = serde_json::to_string(&bundle).expect("serialize");
        let parsed: ProofBundle = serde_json::from_str(&json).expect("deserialize");
        let err = parsed.to_proof().unwrap_err();
        assert!(matches!(err, WireFormatError::UnsupportedVersion(99)));
    }

    #[test]
    fn wire_rejects_bad_hex() {
        let proof = make_proof();
        let mut bundle = ProofBundle::from_proof(&proof);
        bundle.ms_root_hex = "ZZZZ_not_hex".to_string();
        let json = serde_json::to_string(&bundle).expect("serialize");
        let parsed: ProofBundle = serde_json::from_str(&json).expect("deserialize");
        let err = parsed.to_proof().unwrap_err();
        assert!(matches!(err, WireFormatError::HexDecode { .. }));
    }

    #[test]
    fn wire_rejects_wrong_length() {
        let proof = make_proof();
        let mut bundle = ProofBundle::from_proof(&proof);
        bundle.ms_root_hex = hex::encode([0u8; 16]);
        let json = serde_json::to_string(&bundle).expect("serialize");
        let parsed: ProofBundle = serde_json::from_str(&json).expect("deserialize");
        let err = parsed.to_proof().unwrap_err();
        assert!(matches!(err, WireFormatError::BadLength { expected: 32, got: 16, .. }));
    }

    #[test]
    fn wire_rejects_wrong_coeff_count() {
        let proof = make_proof();
        let mut bundle = ProofBundle::from_proof(&proof);
        bundle.le_commitment_coeffs = vec![0u32; 10];
        let json = serde_json::to_string(&bundle).expect("serialize");
        let parsed: ProofBundle = serde_json::from_str(&json).expect("deserialize");
        let err = parsed.to_proof().unwrap_err();
        assert!(matches!(err, WireFormatError::BadCoeffCount { expected: 256, got: 10, .. }));
    }

    #[test]
    fn wire_rejects_unknown_fields() {
        let proof = make_proof();
        let bundle = ProofBundle::from_proof(&proof);
        let mut json_val: serde_json::Value =
            serde_json::to_value(&bundle).expect("to_value");
        json_val.as_object_mut().unwrap().insert(
            "smuggled_field".to_string(),
            serde_json::Value::Bool(true),
        );
        let json = serde_json::to_string(&json_val).expect("serialize");
        let result = serde_json::from_str::<ProofBundle>(&json);
        assert!(result.is_err(), "unknown fields must be rejected");
    }

    // ── Injectivity & preservation ───────────────────────────────────

    #[test]
    fn proof_bundle_from_proof_injective() {
        let proof_a = make_proof();
        let proof_b = {
            let ctx = ProofContext::new(test_seed());
            let different_entropy = blake3_hash(b"DIFFERENT-ENTROPY-SEED");
            prove(&ctx, &test_template(), &test_claim(), 100, 50, test_binding_ctx(), different_entropy)
                .expect("prove should succeed")
        };
        let json_a = serde_json::to_string(&ProofBundle::from_proof(&proof_a)).unwrap();
        let json_b = serde_json::to_string(&ProofBundle::from_proof(&proof_b)).unwrap();
        assert_ne!(json_a, json_b, "different proofs must produce different bundles");
    }

    #[test]
    fn proof_bundle_preserves_all_fields() {
        let proof = make_proof();
        let bundle1 = ProofBundle::from_proof(&proof);
        let recovered = bundle1.to_proof().expect("to_proof");
        let bundle2 = ProofBundle::from_proof(&recovered);
        let json1 = serde_json::to_string(&bundle1).unwrap();
        let json2 = serde_json::to_string(&bundle2).unwrap();
        assert_eq!(json1, json2, "round-trip must be lossless — no field drift");
    }

    #[test]
    fn proof_bundle_json_field_names_stable() {
        let proof = make_proof();
        let bundle = ProofBundle::from_proof(&proof);
        let val: serde_json::Value = serde_json::to_value(&bundle).expect("to_value");
        let obj = val.as_object().expect("must be JSON object");
        let mut keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
        keys.sort();
        let expected = vec![
            "binding_entropy_hex",
            "external_entropy_hex",
            "external_entropy_included",
            "le_challenge_seed_hex",
            "le_commitment_coeffs",
            "le_proof_t_coeffs",
            "le_proof_z_coeffs",
            "ms_bit_at_k",
            "ms_challenge_hex",
            "ms_k",
            "ms_n",
            "ms_opened_salt_hex",
            "ms_path_hex",
            "ms_root_hex",
            "protocol_version",
            "target",
            "value",
            "version",
        ];
        assert_eq!(keys, expected, "JSON field names must match frozen schema");
    }
}
