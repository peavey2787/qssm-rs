#![forbid(unsafe_code)]
//! # QSSM ZK API
//!
//! Stable SDK for zero-knowledge predicate proofs.
//! This crate is a **pure façade** — all logic lives in dedicated modules.
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
//! let entropy_seed = [1u8; 32]; // from device sensor / harvester
//!
//! let proof = prove(&ctx, &template, &claim, 100, 50, binding_ctx, entropy_seed).unwrap();
//! assert!(verify(&ctx, &template, &claim, &proof, binding_ctx).unwrap());
//! ```

mod context;
pub mod error;
mod prove;
mod verify;
pub mod wire;

// ── Shared constants ─────────────────────────────────────────────────
/// MS context tag shared between prove and verify pipelines.
pub(crate) const MS_CONTEXT_TAG: &[u8] = b"qssm-sdk-v1";

// ── Core types ───────────────────────────────────────────────────────
pub use context::{Proof, ProofContext};
pub use error::ZkError;
pub use wire::{ProofBundle, WireFormatError, PROTOCOL_VERSION};

// ── SDK entry points ─────────────────────────────────────────────────
pub use prove::prove;
pub use verify::verify;

// ── Template re-export ───────────────────────────────────────────────
pub use template_lib;

#[cfg(test)]
mod tests {
    use super::*;
    use qssm_le::{BETA, N};
    use qssm_utils::hashing::blake3_hash;
    use serde_json::json;

    fn test_seed() -> [u8; 32] {
        blake3_hash(b"QSSM-SDK-TEST-SEED")
    }

    fn test_entropy() -> [u8; 32] {
        blake3_hash(b"QSSM-SDK-TEST-ENTROPY")
    }

    fn test_binding_ctx() -> [u8; 32] {
        blake3_hash(b"test-binding-context")
    }

    fn test_template() -> template_lib::QssmTemplate {
        template_lib::QssmTemplate::proof_of_age("test-age")
    }

    fn test_claim() -> serde_json::Value {
        json!({ "claim": { "age_years": 25 } })
    }

    fn make_proof() -> Proof {
        let ctx = ProofContext::new(test_seed());
        prove(&ctx, &test_template(), &test_claim(), 100, 50, test_binding_ctx(), test_entropy())
            .expect("prove should succeed")
    }

    // ── Round-trip ───────────────────────────────────────────────────

    #[test]
    fn prove_and_verify_round_trip() {
        let ctx = ProofContext::new(test_seed());
        let proof = make_proof();
        let ok = verify(&ctx, &test_template(), &test_claim(), &proof, test_binding_ctx())
            .expect("verify should succeed");
        assert!(ok);
    }

    // ── Adversarial verify tests ─────────────────────────────────────

    #[test]
    fn tampered_ms_root_rejected() {
        let ctx = ProofContext::new(test_seed());
        let mut proof = make_proof();
        proof.ms_root[0] ^= 0x01;
        let err = verify(&ctx, &test_template(), &test_claim(), &proof, test_binding_ctx())
            .unwrap_err();
        assert!(matches!(err, ZkError::MsVerifyFailed));
    }

    #[test]
    fn wrong_binding_context_rejected() {
        let ctx = ProofContext::new(test_seed());
        let proof = make_proof();
        let wrong_ctx = blake3_hash(b"WRONG-binding-context");
        let err = verify(&ctx, &test_template(), &test_claim(), &proof, wrong_ctx)
            .unwrap_err();
        assert!(matches!(err, ZkError::MsVerifyFailed));
    }

    #[test]
    fn tampered_external_entropy_rejected() {
        let ctx = ProofContext::new(test_seed());
        let mut proof = make_proof();
        proof.external_entropy[0] ^= 0xFF;
        let err = verify(&ctx, &test_template(), &test_claim(), &proof, test_binding_ctx())
            .unwrap_err();
        // Tampering external_entropy changes the recomputed truth digest,
        // causing LE public instance mismatch → verification failure.
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
        let err = verify(&ctx, &test_template(), &wrong_claim, &proof, test_binding_ctx())
            .unwrap_err();
        assert!(matches!(err, ZkError::PredicateFailed(_)));
    }

    #[test]
    fn wrong_value_target_rejected() {
        let ctx = ProofContext::new(test_seed());
        let mut proof = make_proof();
        // Swap value and target so the inequality no longer holds for this proof.
        std::mem::swap(&mut proof.value, &mut proof.target);
        let err = verify(&ctx, &test_template(), &test_claim(), &proof, test_binding_ctx())
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
        let ok = verify(&ctx, &test_template(), &test_claim(), &proof2, test_binding_ctx())
            .expect("verify should succeed");
        assert!(ok);
    }

    #[test]
    fn wire_format_forward_compat() {
        // An "old" bundle (current schema, no extra fields) must parse
        // successfully with the current parser. This guards against future
        // additions breaking deserialization of existing proofs.
        let proof = make_proof();
        let bundle = ProofBundle::from_proof(&proof);
        let json = serde_json::to_string(&bundle).expect("serialize");
        // Deserialize the frozen JSON — must always succeed.
        let parsed: ProofBundle = serde_json::from_str(&json).expect(
            "old bundle must remain parseable by current (and future) code",
        );
        let recovered = parsed.to_proof().expect("to_proof");
        assert_eq!(recovered.ms_root, proof.ms_root);
        assert_eq!(recovered.value, proof.value);
        assert_eq!(recovered.target, proof.target);
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
        bundle.ms_root_hex = hex::encode([0u8; 16]); // 16 bytes, not 32
        let json = serde_json::to_string(&bundle).expect("serialize");
        let parsed: ProofBundle = serde_json::from_str(&json).expect("deserialize");
        let err = parsed.to_proof().unwrap_err();
        assert!(matches!(err, WireFormatError::BadLength { expected: 32, got: 16, .. }));
    }

    #[test]
    fn wire_rejects_wrong_coeff_count() {
        let proof = make_proof();
        let mut bundle = ProofBundle::from_proof(&proof);
        bundle.le_commitment_coeffs = vec![0u32; 10]; // wrong length
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
        // Two different proofs must produce different bundles.
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
        // proof → bundle → proof → bundle must be identical (no field drift).
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
        // Snapshot: the set of top-level JSON field names must not change.
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

    // ── Witness derivation ───────────────────────────────────────────

    #[test]
    fn derive_le_witness_deterministic_and_bounded() {
        let seed = test_entropy();
        let ctx = test_binding_ctx();
        let w1 = prove::derive_le_witness(&seed, &ctx);
        let w2 = prove::derive_le_witness(&seed, &ctx);
        let beta = BETA as i32;
        // Determinism: same inputs → same coefficients.
        assert_eq!(w1.coeffs(), w2.coeffs());
        // Bounds: every coefficient ∈ [-BETA, BETA].
        for (i, &c) in w1.coeffs().iter().enumerate() {
            assert!(
                (-beta..=beta).contains(&c),
                "coefficient {i} = {c} is outside [-{beta}, {beta}]"
            );
        }
        // Length: exactly N coefficients.
        assert_eq!(w1.coeffs().len(), N);
    }

    // ── API accessor ─────────────────────────────────────────────────

    #[test]
    fn proof_context_vk_accessor() {
        let seed = test_seed();
        let ctx = ProofContext::new(seed);
        // Accessor must return the same key that was derived at construction.
        let vk_ref = ctx.vk();
        let expected = qssm_le::VerifyingKey::from_seed(seed);
        assert_eq!(vk_ref.crs_seed, expected.crs_seed, "vk accessor must return the correct key");
    }
}
