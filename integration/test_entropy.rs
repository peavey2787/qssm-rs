//! Entropy integration tests.
//!
//! Verifies that the deterministic key schedule produces expected properties:
//! same inputs → same outputs, different inputs → different outputs, and that
//! entropy-derived values pass density/distribution checks.

use qssm_local_prover::{prove, ProofBundle, ProofContext};
use qssm_templates::QssmTemplate;
use qssm_utils::hashing::blake3_hash;
use serde_json::json;

fn seed() -> [u8; 32] {
    blake3_hash(b"E2E-ENTROPY-SEED")
}

fn binding() -> [u8; 32] {
    blake3_hash(b"E2E-ENTROPY-BINDING")
}

fn template() -> QssmTemplate {
    QssmTemplate::proof_of_age("age-gate-21")
}

fn claim() -> serde_json::Value {
    json!({ "claim": { "age_years": 30 } })
}

// ── Deterministic key schedule ───────────────────────────────────────

#[test]
fn same_entropy_seed_produces_identical_ms_root() {
    let ent = blake3_hash(b"DETERMINISTIC-ENTROPY");
    let b = binding();
    let ctx = ProofContext::new(seed());
    let proof1 = prove(&ctx, &template(), &claim(), 100, 50, b, ent).expect("prove 1");
    let ctx2 = ProofContext::new(seed());
    let proof2 = prove(&ctx2, &template(), &claim(), 100, 50, b, ent).expect("prove 2");

    let b1 = ProofBundle::from_proof(&proof1);
    let b2 = ProofBundle::from_proof(&proof2);
    assert_eq!(b1.ms_root_hex, b2.ms_root_hex);
    assert_eq!(b1.binding_entropy_hex, b2.binding_entropy_hex);
    assert_eq!(b1.external_entropy_hex, b2.external_entropy_hex);
}

#[test]
fn different_entropy_seeds_produce_different_ms_roots() {
    let b = binding();
    let ctx = ProofContext::new(seed());
    let proof1 = prove(
        &ctx,
        &template(),
        &claim(),
        100,
        50,
        b,
        blake3_hash(b"ENTROPY-A"),
    )
    .expect("prove 1");
    let ctx2 = ProofContext::new(seed());
    let proof2 = prove(
        &ctx2,
        &template(),
        &claim(),
        100,
        50,
        b,
        blake3_hash(b"ENTROPY-B"),
    )
    .expect("prove 2");

    let b1 = ProofBundle::from_proof(&proof1);
    let b2 = ProofBundle::from_proof(&proof2);
    assert_ne!(b1.ms_root_hex, b2.ms_root_hex);
}

#[test]
fn different_binding_context_produces_different_proofs() {
    let ent = blake3_hash(b"SAME-ENTROPY");
    let ctx1 = ProofContext::new(seed());
    let proof1 = prove(
        &ctx1,
        &template(),
        &claim(),
        100,
        50,
        blake3_hash(b"BINDING-A"),
        ent,
    )
    .expect("prove 1");
    let ctx2 = ProofContext::new(seed());
    let proof2 = prove(
        &ctx2,
        &template(),
        &claim(),
        100,
        50,
        blake3_hash(b"BINDING-B"),
        ent,
    )
    .expect("prove 2");

    let b1 = ProofBundle::from_proof(&proof1);
    let b2 = ProofBundle::from_proof(&proof2);
    assert_ne!(b1.ms_root_hex, b2.ms_root_hex);
    assert_ne!(b1.binding_entropy_hex, b2.binding_entropy_hex);
}

// ── Entropy field properties ─────────────────────────────────────────

#[test]
fn external_entropy_is_32_bytes_hex() {
    let ctx = ProofContext::new(seed());
    let proof = prove(
        &ctx,
        &template(),
        &claim(),
        100,
        50,
        binding(),
        blake3_hash(b"CHECK-LENGTH"),
    )
    .expect("prove");
    let bundle = ProofBundle::from_proof(&proof);
    let decoded = hex::decode(&bundle.external_entropy_hex).expect("valid hex");
    assert_eq!(decoded.len(), 32, "external_entropy must be 32 bytes");
}

#[test]
fn binding_entropy_is_32_bytes_hex() {
    let ctx = ProofContext::new(seed());
    let proof = prove(
        &ctx,
        &template(),
        &claim(),
        100,
        50,
        binding(),
        blake3_hash(b"CHECK-BINDING-LEN"),
    )
    .expect("prove");
    let bundle = ProofBundle::from_proof(&proof);
    let decoded = hex::decode(&bundle.binding_entropy_hex).expect("valid hex");
    assert_eq!(decoded.len(), 32, "binding_entropy must be 32 bytes");
}

// ── Entropy audit utility ────────────────────────────────────────────

#[test]
fn entropy_seed_passes_basic_distribution_check() {
    // validate_entropy_full requires >= 256 bytes (MIN_RAW_BYTES).
    // Build a deterministic 512-byte buffer from repeated blake3 hashes.
    let mut buf = Vec::with_capacity(512);
    for i in 0u32..16 {
        let chunk = blake3_hash(&i.to_le_bytes());
        buf.extend_from_slice(&chunk);
    }
    let result = qssm_utils::validate_entropy_full(&buf);
    assert!(
        result.is_ok(),
        "deterministic blake3 buffer must pass entropy audit: {result:?}"
    );
}

#[test]
fn all_zero_entropy_fails_distribution_check() {
    let bad = [0u8; 300];
    let result = qssm_utils::validate_entropy_full(&bad);
    assert!(result.is_err(), "all-zero input must fail entropy audit");
}

#[test]
fn all_ff_entropy_fails_distribution_check() {
    let bad = [0xFFu8; 300];
    let result = qssm_utils::validate_entropy_full(&bad);
    assert!(result.is_err(), "all-0xFF input must fail entropy audit");
}
