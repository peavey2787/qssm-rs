#![forbid(unsafe_code)]
//! # QSSM Local Prover — Layer 4
//!
//! Consumes entropy and produces a complete ZK proof artifact.
//!
//! This crate owns:
//! - The deterministic prove pipeline (predicates → MS → truth binding → LE).
//! - Core proof types ([`Proof`], [`ProofContext`]).
//! - The error type ([`ZkError`]).
//! - The versioned wire format ([`ProofBundle`], [`WireFormatError`]).

pub mod context;
pub mod error;
mod prove;
pub mod wire;

/// MS context tag shared between prove and verify pipelines.
pub const MS_CONTEXT_TAG: &[u8] = b"qssm-sdk-v1";

// ── Public re-exports ────────────────────────────────────────────────
pub use context::{Proof, ProofContext};
pub use error::ZkError;
pub use prove::prove;
pub use wire::{ProofBundle, WireFormatError, PROTOCOL_VERSION};

#[cfg(test)]
mod tests {
    use super::*;
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

    fn test_template() -> qssm_templates::QssmTemplate {
        qssm_templates::QssmTemplate::proof_of_age("test-age")
    }

    fn test_claim() -> serde_json::Value {
        json!({ "claim": { "age_years": 25 } })
    }

    fn test_ctx() -> ProofContext {
        ProofContext::new(test_seed())
    }

    fn make_proof() -> Proof {
        prove(
            &test_ctx(),
            &test_template(),
            &test_claim(),
            100,
            50,
            test_binding_ctx(),
            test_entropy(),
        )
        .expect("prove should succeed")
    }

    // ── Prove ────────────────────────────────────────────────────────

    #[test]
    fn prove_succeeds() {
        let _proof = make_proof();
    }

    #[test]
    fn prove_rejects_bad_predicate() {
        let bad_claim = json!({ "claim": { "age_years": 15 } });
        let err = prove(
            &test_ctx(),
            &test_template(),
            &bad_claim,
            100,
            50,
            test_binding_ctx(),
            test_entropy(),
        )
        .unwrap_err();
        assert!(matches!(err, ZkError::PredicateFailed(_)));
    }

    #[test]
    fn prove_is_deterministic() {
        let p1 = make_proof();
        let p2 = make_proof();
        let j1 = serde_json::to_string(&ProofBundle::from_proof(&p1)).unwrap();
        let j2 = serde_json::to_string(&ProofBundle::from_proof(&p2)).unwrap();
        assert_eq!(j1, j2, "identical inputs must produce identical proofs");
    }

    // ── Wire format round-trip ───────────────────────────────────────

    #[test]
    fn wire_round_trip_json() {
        let proof = make_proof();
        let bundle = ProofBundle::from_proof(&proof);
        let json = serde_json::to_string(&bundle).expect("serialize");
        let bundle2: ProofBundle = serde_json::from_str(&json).expect("deserialize");
        let recovered = bundle2.to_proof().expect("to_proof");
        assert_eq!(recovered.ms_root(), proof.ms_root());
        assert_eq!(recovered.value(), proof.value());
        assert_eq!(recovered.target(), proof.target());
    }

    #[test]
    fn wire_format_forward_compat() {
        let proof = make_proof();
        let bundle = ProofBundle::from_proof(&proof);
        let json = serde_json::to_string(&bundle).expect("serialize");
        let parsed: ProofBundle = serde_json::from_str(&json)
            .expect("v2 bundle must remain parseable by current code");
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
        bundle.ms_v2_binding_context_hex = "ZZZZ_not_hex".to_string();
        let json = serde_json::to_string(&bundle).expect("serialize");
        let parsed: ProofBundle = serde_json::from_str(&json).expect("deserialize");
        let err = parsed.to_proof().unwrap_err();
        assert!(matches!(err, WireFormatError::HexDecode { .. }));
    }

    #[test]
    fn wire_rejects_wrong_length() {
        let proof = make_proof();
        let mut bundle = ProofBundle::from_proof(&proof);
        bundle.ms_v2_binding_context_hex = hex::encode([0u8; 16]);
        let json = serde_json::to_string(&bundle).expect("serialize");
        let parsed: ProofBundle = serde_json::from_str(&json).expect("deserialize");
        let err = parsed.to_proof().unwrap_err();
        assert!(matches!(
            err,
            WireFormatError::BadLength {
                expected: 32,
                got: 16,
                ..
            }
        ));
    }

    #[test]
    fn wire_rejects_wrong_coeff_count() {
        let proof = make_proof();
        let mut bundle = ProofBundle::from_proof(&proof);
        bundle.le_commitment_coeffs = vec![0u32; 10];
        let json = serde_json::to_string(&bundle).expect("serialize");
        let parsed: ProofBundle = serde_json::from_str(&json).expect("deserialize");
        let err = parsed.to_proof().unwrap_err();
        assert!(matches!(
            err,
            WireFormatError::BadCoeffCount {
                expected: 256,
                got: 10,
                ..
            }
        ));
    }

    #[test]
    fn wire_rejects_unknown_fields() {
        let proof = make_proof();
        let bundle = ProofBundle::from_proof(&proof);
        let mut json_val: serde_json::Value = serde_json::to_value(&bundle).expect("to_value");
        json_val
            .as_object_mut()
            .unwrap()
            .insert("smuggled_field".to_string(), serde_json::Value::Bool(true));
        let json = serde_json::to_string(&json_val).expect("serialize");
        let result = serde_json::from_str::<ProofBundle>(&json);
        assert!(result.is_err(), "unknown fields must be rejected");
    }

    // ── Injectivity & preservation ───────────────────────────────────

    #[test]
    fn proof_bundle_from_proof_injective() {
        let proof_a = make_proof();
        let proof_b = {
            let different_entropy = blake3_hash(b"DIFFERENT-ENTROPY-SEED");
            prove(
                &test_ctx(),
                &test_template(),
                &test_claim(),
                100,
                50,
                test_binding_ctx(),
                different_entropy,
            )
            .expect("prove should succeed")
        };
        let json_a = serde_json::to_string(&ProofBundle::from_proof(&proof_a)).unwrap();
        let json_b = serde_json::to_string(&ProofBundle::from_proof(&proof_b)).unwrap();
        assert_ne!(
            json_a, json_b,
            "different proofs must produce different bundles"
        );
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
            "ms_v2_binding_context_hex",
            "ms_v2_binding_entropy_hex",
            "ms_v2_bit_commitments_hex",
            "ms_v2_bitness_proofs",
            "ms_v2_comparison_clauses",
            "ms_v2_context_hex",
            "ms_v2_proof_result",
            "ms_v2_proof_statement_digest_hex",
            "ms_v2_target",
            "protocol_version",
            "value",
            "version",
        ];
        assert_eq!(keys, expected, "JSON field names must match frozen schema");
    }
}
