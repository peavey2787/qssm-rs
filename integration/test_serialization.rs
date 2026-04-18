//! Serialization / wire-format integration tests.
//!
//! These tests verify that `ProofBundle` serialization is stable, round-trips
//! correctly, and rejects malformed input at the boundary.

use qssm_api::{ProofBundle, ProofContext, WireFormatError, PROTOCOL_VERSION};
use qssm_local_prover::prove;
use qssm_templates::QssmTemplate;
use qssm_utils::hashing::blake3_hash;
use serde_json::json;

fn seed() -> [u8; 32] {
    blake3_hash(b"E2E-SERIAL-SEED")
}

fn entropy() -> [u8; 32] {
    blake3_hash(b"E2E-SERIAL-ENTROPY")
}

fn binding() -> [u8; 32] {
    blake3_hash(b"E2E-SERIAL-BINDING")
}

fn make_bundle() -> ProofBundle {
    let ctx = ProofContext::new(seed());
    let template = QssmTemplate::proof_of_age("age-gate-21");
    let claim = json!({ "claim": { "age_years": 30 } });
    let proof = prove(&ctx, &template, &claim, 100, 50, binding(), entropy())
        .expect("prove");
    ProofBundle::from_proof(&proof)
}

// ── JSON round-trip ──────────────────────────────────────────────────

#[test]
fn json_round_trip_lossless() {
    let bundle = make_bundle();
    let json1 = serde_json::to_string(&bundle).expect("serialize");
    let recovered: ProofBundle = serde_json::from_str(&json1).expect("deserialize");
    let json2 = serde_json::to_string(&recovered).expect("re-serialize");
    assert_eq!(json1, json2, "JSON round-trip must be lossless");
}

#[test]
fn pretty_json_round_trip() {
    let bundle = make_bundle();
    let pretty = serde_json::to_string_pretty(&bundle).expect("pretty");
    let recovered: ProofBundle = serde_json::from_str(&pretty).expect("parse pretty");
    let proof = recovered.to_proof().expect("to_proof");
    let ok = qssm_api::verify(
        &ProofContext::new(seed()),
        &QssmTemplate::proof_of_age("age-gate-21"),
        &json!({ "claim": { "age_years": 30 } }),
        &proof,
        binding(),
    )
    .expect("verify");
    assert!(ok);
}

// ── Protocol version ─────────────────────────────────────────────────

#[test]
fn bundle_protocol_version_matches_constant() {
    let bundle = make_bundle();
    assert_eq!(bundle.protocol_version, PROTOCOL_VERSION);
}

#[test]
fn wrong_version_rejected() {
    let mut bundle = make_bundle();
    bundle.version = 99;
    let json = serde_json::to_string(&bundle).expect("serialize");
    let parsed: ProofBundle = serde_json::from_str(&json).expect("parse");
    let err = parsed.to_proof().unwrap_err();
    assert!(matches!(err, WireFormatError::UnsupportedVersion(99)));
}

// ── Malformed hex ────────────────────────────────────────────────────

#[test]
fn invalid_hex_in_ms_root_rejected() {
    let mut bundle = make_bundle();
    bundle.ms_root_hex = "not-valid-hex!!".to_string();
    let json = serde_json::to_string(&bundle).unwrap();
    let parsed: ProofBundle = serde_json::from_str(&json).unwrap();
    let err = parsed.to_proof().unwrap_err();
    assert!(matches!(err, WireFormatError::HexDecode { .. }));
}

#[test]
fn truncated_ms_root_rejected() {
    let mut bundle = make_bundle();
    bundle.ms_root_hex = hex::encode([0u8; 16]); // 16 bytes instead of 32
    let json = serde_json::to_string(&bundle).unwrap();
    let parsed: ProofBundle = serde_json::from_str(&json).unwrap();
    let err = parsed.to_proof().unwrap_err();
    assert!(matches!(err, WireFormatError::BadLength { expected: 32, got: 16, .. }));
}

// ── Coefficient count validation ─────────────────────────────────────

#[test]
fn wrong_le_commitment_coeff_count_rejected() {
    let mut bundle = make_bundle();
    bundle.le_commitment_coeffs = vec![0u32; 10]; // should be 256
    let json = serde_json::to_string(&bundle).unwrap();
    let parsed: ProofBundle = serde_json::from_str(&json).unwrap();
    let err = parsed.to_proof().unwrap_err();
    assert!(matches!(err, WireFormatError::BadCoeffCount { expected: 256, got: 10, .. }));
}

#[test]
fn wrong_le_proof_z_coeff_count_rejected() {
    let mut bundle = make_bundle();
    bundle.le_proof_z_coeffs = vec![0u32; 5];
    let json = serde_json::to_string(&bundle).unwrap();
    let parsed: ProofBundle = serde_json::from_str(&json).unwrap();
    let err = parsed.to_proof().unwrap_err();
    assert!(matches!(err, WireFormatError::BadCoeffCount { .. }));
}

// ── Unknown fields rejected ──────────────────────────────────────────

#[test]
fn unknown_json_fields_rejected() {
    let bundle = make_bundle();
    let mut val: serde_json::Value = serde_json::to_value(&bundle).expect("to_value");
    val.as_object_mut().unwrap().insert(
        "injected_field".to_string(),
        serde_json::Value::String("attack".to_string()),
    );
    let json = serde_json::to_string(&val).unwrap();
    let result = serde_json::from_str::<ProofBundle>(&json);
    assert!(result.is_err(), "deny_unknown_fields must reject extra keys");
}

// ── Field name stability ─────────────────────────────────────────────

#[test]
fn json_field_names_are_stable() {
    let bundle = make_bundle();
    let val: serde_json::Value = serde_json::to_value(&bundle).expect("to_value");
    let obj = val.as_object().expect("must be object");
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
    assert_eq!(keys, expected, "wire format field names must match frozen schema");
}

// ── Empty JSON body rejected ─────────────────────────────────────────

#[test]
fn empty_json_object_rejected() {
    let result = serde_json::from_str::<ProofBundle>("{}");
    assert!(result.is_err());
}

#[test]
fn null_rejected() {
    let result = serde_json::from_str::<ProofBundle>("null");
    assert!(result.is_err());
}
