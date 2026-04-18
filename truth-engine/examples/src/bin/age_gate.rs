//! Age-gate verification demo with a static root anchor.
//!
//! ```text
//! cargo run -p zk-examples --bin age_gate
//! ```

use qssm_api::{compile, prove, verify};

fn main() {
    println!("=== QSSM Age Gate Demo ===\n");

    let blueprint = compile("age-gate-21").expect("compile failed");
    println!("Blueprint compiled: age-gate-21");

    let salt = [7u8; 32];

    // Scenario 1: Valid claim (age 25).
    let claim_ok = br#"{"claim":{"age_years":25}}"#;
    let proof = prove(claim_ok, &salt, &blueprint).expect("prove failed");
    let ok = verify(&proof, &blueprint);
    println!("Age 25 => verified: {ok}");
    assert!(ok);

    // Scenario 2: Underage claim (age 17) — prove returns Err.
    let claim_bad = br#"{"claim":{"age_years":17}}"#;
    let result = prove(claim_bad, &salt, &blueprint);
    println!(
        "Age 17 => prove result: {}",
        if result.is_err() { "rejected (correct)" } else { "ERROR: should have been rejected" }
    );
    assert!(result.is_err(), "underage claim should be rejected");

    println!("\n=== Done ===");
}
