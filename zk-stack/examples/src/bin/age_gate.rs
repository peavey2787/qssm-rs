//! Age-gate verification demo with a static root anchor.
//!
//! ```text
//! cargo run -p zk-examples --bin age_gate
//! ```

use qssm_utils::hashing::blake3_hash;
use serde_json::json;
use zk_api::ProofContext;

fn main() {
    println!("=== QSSM Age Gate Demo ===\n");

    let seed = blake3_hash(b"DEMO-SEED-age-gate");
    let ctx = ProofContext::new(seed);

    let template = template_lib::resolve("age-gate-21")
        .expect("age-gate-21 template should exist");

    // Static anchor: hash of a known root (no blockchain needed).
    let anchor = blake3_hash(b"static-root-anchor-2026-04-16");
    println!("Anchor: {}", hex::encode(&anchor[..16]));

    // Scenario 1: Valid claim (age 25).
    let claim_ok = json!({ "claim": { "age_years": 25 } });
    let proof = zk_api::prove(&ctx, &template, &claim_ok, 100, 50, anchor)
        .expect("prove should succeed for age 25");
    let ok = zk_api::verify(&ctx, &template, &claim_ok, &proof, anchor)
        .expect("verify should succeed");
    println!("Age 25 => verified: {ok}");
    assert!(ok);

    // Scenario 2: Underage claim (age 17) — prove should fail at predicate check.
    let claim_bad = json!({ "claim": { "age_years": 17 } });
    let err = zk_api::prove(&ctx, &template, &claim_bad, 100, 50, anchor);
    println!("Age 17 => prove result: {}", if err.is_err() { "rejected (correct)" } else { "ERROR: should have been rejected" });
    assert!(err.is_err(), "underage claim should be rejected");

    println!("\n=== Done ===");
}
