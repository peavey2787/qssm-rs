//! Age-gate verification demo with a static root anchor.
//!
//! ```text
//! cargo run -p zk-examples --bin age_gate
//! ```

use serde_json::json;
use zk_examples::SdkSetup;

fn main() {
    println!("=== QSSM Age Gate Demo ===\n");

    let setup = SdkSetup::from_label(b"static-root-anchor-2026-04-16");
    println!("Anchor: {}", &hex::encode(&setup.binding_ctx)[..32]);

    let template = template_lib::resolve("age-gate-21")
        .expect("age-gate-21 template should exist");

    // Scenario 1: Valid claim (age 25).
    let claim_ok = json!({ "claim": { "age_years": 25 } });
    let entropy_seed = setup.fresh_entropy();
    let proof = zk_api::prove(&setup.ctx, &template, &claim_ok, 100, 50, setup.binding_ctx, entropy_seed)
        .expect("prove should succeed for age 25");
    let ok = zk_api::verify(&setup.ctx, &template, &claim_ok, &proof, setup.binding_ctx)
        .expect("verify should succeed");
    println!("Age 25 => verified: {ok}");
    assert!(ok);

    // Scenario 2: Underage claim (age 17) — prove should fail at predicate check.
    let claim_bad = json!({ "claim": { "age_years": 17 } });
    let err = zk_api::prove(&setup.ctx, &template, &claim_bad, 100, 50, setup.binding_ctx, entropy_seed);
    println!("Age 17 => prove result: {}", if err.is_err() { "rejected (correct)" } else { "ERROR: should have been rejected" });
    assert!(err.is_err(), "underage claim should be rejected");

    println!("\n=== Done ===");
}
