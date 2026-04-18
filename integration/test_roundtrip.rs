//! End-to-end prove → verify round-trip integration tests.
//!
//! These tests exercise the full SDK pipeline across crate boundaries:
//! `qssm-local-prover` → `qssm-api` → `qssm-local-verifier`.

use qssm_api::{ProofContext, verify};
use qssm_local_prover::prove;
use qssm_local_verifier::{verify_proof_offline, verify_proof_with_template};
use qssm_templates::QssmTemplate;
use qssm_utils::hashing::blake3_hash;
use serde_json::json;

fn seed() -> [u8; 32] {
    blake3_hash(b"E2E-ROUNDTRIP-SEED")
}

fn entropy() -> [u8; 32] {
    blake3_hash(b"E2E-ROUNDTRIP-ENTROPY")
}

fn binding() -> [u8; 32] {
    blake3_hash(b"E2E-ROUNDTRIP-BINDING")
}

// ── Direct SDK round-trip ────────────────────────────────────────────

#[test]
fn prove_then_verify_via_api() {
    let ctx = ProofContext::new(seed());
    let template = QssmTemplate::proof_of_age("age-gate-21");
    let claim = json!({ "claim": { "age_years": 30 } });
    let binding_ctx = binding();

    let proof = prove(&ctx, &template, &claim, 100, 50, binding_ctx, entropy())
        .expect("prove must succeed");
    let ok = verify(&ctx, &template, &claim, &proof, binding_ctx)
        .expect("verify must succeed");
    assert!(ok, "valid proof must verify");
}

// ── Local verifier with template ID ──────────────────────────────────

#[test]
fn prove_then_verify_offline_by_id() {
    let ctx = ProofContext::new(seed());
    let template = QssmTemplate::proof_of_age("age-gate-21");
    let claim = json!({ "claim": { "age_years": 25 } });
    let binding_ctx = binding();

    let proof = prove(&ctx, &template, &claim, 100, 50, binding_ctx, entropy())
        .expect("prove must succeed");
    let ok = verify_proof_offline(&ctx, "age-gate-21", &claim, &proof, binding_ctx)
        .expect("offline verify must succeed");
    assert!(ok);
}

// ── Local verifier with explicit template ────────────────────────────

#[test]
fn prove_then_verify_with_explicit_template() {
    let ctx = ProofContext::new(seed());
    let template = QssmTemplate::proof_of_age("age-gate-21");
    let claim = json!({ "claim": { "age_years": 42 } });
    let binding_ctx = binding();

    let proof = prove(&ctx, &template, &claim, 100, 50, binding_ctx, entropy())
        .expect("prove must succeed");
    let ok = verify_proof_with_template(&ctx, &template, &claim, &proof, binding_ctx)
        .expect("verify_proof_with_template must succeed");
    assert!(ok);
}

// ── Determinism: same inputs → same proof ────────────────────────────

#[test]
fn prove_is_deterministic() {
    let ctx1 = ProofContext::new(seed());
    let ctx2 = ProofContext::new(seed());
    let template = QssmTemplate::proof_of_age("age-gate-21");
    let claim = json!({ "claim": { "age_years": 30 } });
    let binding_ctx = binding();
    let ent = entropy();

    let proof1 = prove(&ctx1, &template, &claim, 100, 50, binding_ctx, ent)
        .expect("prove 1");
    let proof2 = prove(&ctx2, &template, &claim, 100, 50, binding_ctx, ent)
        .expect("prove 2");

    let bundle1 = qssm_api::ProofBundle::from_proof(&proof1);
    let bundle2 = qssm_api::ProofBundle::from_proof(&proof2);
    let json1 = serde_json::to_string(&bundle1).unwrap();
    let json2 = serde_json::to_string(&bundle2).unwrap();
    assert_eq!(json1, json2, "identical inputs must produce identical proofs");
}

// ── Different entropy → different proof ──────────────────────────────

#[test]
fn different_entropy_produces_different_proof() {
    let ctx = ProofContext::new(seed());
    let template = QssmTemplate::proof_of_age("age-gate-21");
    let claim = json!({ "claim": { "age_years": 30 } });
    let binding_ctx = binding();

    let proof_a = prove(&ctx, &template, &claim, 100, 50, binding_ctx, entropy())
        .expect("prove a");
    let proof_b = prove(
        &ProofContext::new(seed()),
        &template,
        &claim,
        100,
        50,
        binding_ctx,
        blake3_hash(b"DIFFERENT-ENTROPY"),
    )
    .expect("prove b");

    let json_a = serde_json::to_string(&qssm_api::ProofBundle::from_proof(&proof_a)).unwrap();
    let json_b = serde_json::to_string(&qssm_api::ProofBundle::from_proof(&proof_b)).unwrap();
    assert_ne!(json_a, json_b, "different entropy must yield different proofs");
}

// ── Wire round-trip preserves verifiability ──────────────────────────

#[test]
fn wire_round_trip_preserves_verification() {
    let ctx = ProofContext::new(seed());
    let template = QssmTemplate::proof_of_age("age-gate-21");
    let claim = json!({ "claim": { "age_years": 30 } });
    let binding_ctx = binding();

    let proof = prove(&ctx, &template, &claim, 100, 50, binding_ctx, entropy())
        .expect("prove");
    let bundle = qssm_api::ProofBundle::from_proof(&proof);
    let json = serde_json::to_string(&bundle).expect("serialize");
    let recovered: qssm_api::ProofBundle = serde_json::from_str(&json).expect("deserialize");
    let proof2 = recovered.to_proof().expect("to_proof");

    let ok = verify(&ProofContext::new(seed()), &template, &claim, &proof2, binding_ctx)
        .expect("verify deserialized proof");
    assert!(ok);
}
