//! Negative / adversarial integration tests.
//!
//! Every test here must **fail** in the expected way — these verify that the
//! SDK correctly rejects tampered proofs, wrong claims, and domain mismatches.

use qssm_local_prover::{prove, Proof, ProofBundle, ProofContext, ZkError};
use qssm_local_verifier::{verify, verify_proof_offline, verify_proof_with_template, VerifyError};
use qssm_templates::QssmTemplate;
use qssm_utils::hashing::blake3_hash;
use serde_json::json;

fn seed() -> [u8; 32] {
    blake3_hash(b"E2E-NEGATIVE-SEED")
}

fn entropy() -> [u8; 32] {
    blake3_hash(b"E2E-NEGATIVE-ENTROPY")
}

fn binding() -> [u8; 32] {
    blake3_hash(b"E2E-NEGATIVE-BINDING")
}

fn make_proof() -> (ProofContext, QssmTemplate, serde_json::Value, Proof, [u8; 32]) {
    let template = QssmTemplate::proof_of_age("age-gate-21");
    let ctx = ProofContext::new(seed());
    let claim = json!({ "claim": { "age_years": 30 } });
    let binding_ctx = binding();
    let proof = prove(&ctx, &template, &claim, 100, 50, binding_ctx, entropy())
        .expect("prove must succeed for test setup");
    (ctx, template, claim, proof, binding_ctx)
}

// ── Predicate failures ───────────────────────────────────────────────

#[test]
fn underage_claim_rejected_at_prove() {
    let template = QssmTemplate::proof_of_age("age-gate-21");
    let ctx = ProofContext::new(seed());
    let claim = json!({ "claim": { "age_years": 17 } });
    let err = prove(&ctx, &template, &claim, 100, 50, binding(), entropy())
        .unwrap_err();
    assert!(matches!(err, ZkError::PredicateFailed(_)));
}

#[test]
fn missing_claim_field_rejected() {
    let template = QssmTemplate::proof_of_age("age-gate-21");
    let ctx = ProofContext::new(seed());
    let claim = json!({ "claim": { "name": "Alice" } });
    let err = prove(&ctx, &template, &claim, 100, 50, binding(), entropy())
        .unwrap_err();
    assert!(matches!(err, ZkError::PredicateFailed(_)));
}

// ── Tampered MS root ─────────────────────────────────────────────────

#[test]
fn tampered_ms_root_rejected_via_api() {
    let (ctx, template, claim, proof, binding_ctx) = make_proof();
    let mut bundle = ProofBundle::from_proof(&proof);
    let mut root = hex::decode(&bundle.ms_root_hex).unwrap();
    root[0] ^= 0xFF;
    bundle.ms_root_hex = hex::encode(root);
    let tampered = bundle.to_proof().unwrap();
    let err = verify(&ctx, &template, &claim, &tampered, binding_ctx)
        .unwrap_err();
    assert!(matches!(err, ZkError::MsVerifyFailed));
}

#[test]
fn tampered_ms_root_rejected_via_local_verifier() {
    let (ctx, template, claim, proof, binding_ctx) = make_proof();
    let mut bundle = ProofBundle::from_proof(&proof);
    let mut root = hex::decode(&bundle.ms_root_hex).unwrap();
    root[0] ^= 0xFF;
    bundle.ms_root_hex = hex::encode(root);
    let tampered = bundle.to_proof().unwrap();
    let result = verify_proof_with_template(&ctx, &template, &claim, &tampered, binding_ctx);
    assert!(result.is_err());
}

// ── Wrong binding context ────────────────────────────────────────────

#[test]
fn wrong_binding_context_rejected() {
    let (ctx, template, claim, proof, _) = make_proof();
    let wrong_ctx = blake3_hash(b"WRONG-BINDING-CONTEXT");
    let err = verify(&ctx, &template, &claim, &proof, wrong_ctx)
        .unwrap_err();
    assert!(matches!(err, ZkError::MsVerifyFailed));
}

// ── Wrong claim at verify time ───────────────────────────────────────

#[test]
fn wrong_claim_rejected_at_verify() {
    let (ctx, template, _claim, proof, binding_ctx) = make_proof();
    let wrong_claim = json!({ "claim": { "age_years": 15 } });
    let err = verify(&ctx, &template, &wrong_claim, &proof, binding_ctx)
        .unwrap_err();
    assert!(matches!(err, ZkError::PredicateFailed(_)));
}

// ── Tampered binding entropy ─────────────────────────────────────────

#[test]
fn tampered_binding_entropy_rejected() {
    let (ctx, template, claim, proof, binding_ctx) = make_proof();
    let mut bundle = ProofBundle::from_proof(&proof);
    let mut ent = hex::decode(&bundle.binding_entropy_hex).unwrap();
    ent[0] ^= 0xFF;
    bundle.binding_entropy_hex = hex::encode(ent);
    let tampered = bundle.to_proof().unwrap();
    let result = verify(&ctx, &template, &claim, &tampered, binding_ctx);
    assert!(result.is_err());
}

// ── Tampered value/target ────────────────────────────────────────────

#[test]
fn swapped_value_target_rejected() {
    let (ctx, template, claim, proof, binding_ctx) = make_proof();
    let mut bundle = ProofBundle::from_proof(&proof);
    std::mem::swap(&mut bundle.value, &mut bundle.target);
    let tampered = bundle.to_proof().unwrap();
    let err = verify(&ctx, &template, &claim, &tampered, binding_ctx)
        .unwrap_err();
    assert!(matches!(err, ZkError::MsVerifyFailed));
}

// ── Unknown template ID (offline verifier) ───────────────────────────

#[test]
fn unknown_template_rejected_offline() {
    let (ctx, _template, claim, proof, binding_ctx) = make_proof();
    let result = verify_proof_offline(&ctx, "nonexistent-template-xyz", &claim, &proof, binding_ctx);
    assert!(matches!(result, Err(VerifyError::UnknownTemplate(_))));
}

// ── Cross-context replay ─────────────────────────────────────────────

#[test]
fn proof_from_one_seed_rejected_under_different_seed() {
    let (_ctx, template, claim, proof, binding_ctx) = make_proof();
    let different_ctx = ProofContext::new(blake3_hash(b"DIFFERENT-SEED"));
    let result = verify(&different_ctx, &template, &claim, &proof, binding_ctx);
    assert!(result.is_err(), "proof under seed A must not verify under seed B");
}
