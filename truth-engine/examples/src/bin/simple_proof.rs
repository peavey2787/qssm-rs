//! Minimal 5-call prove/verify demo with no blockchain dependencies.
//!
//! ```text
//! cargo run -p zk-examples --bin simple_proof
//! ```

use serde_json::json;
use zk_examples::{hex_short, SdkSetup};

fn main() {
    println!("=== QSSM Simple Proof Demo ===\n");

    // 1. Create SDK context from hardware entropy.
    let setup = SdkSetup::from_label(b"simple-proof-demo-binding");
    println!("[1] ProofContext created (seed: {})", hex_short(&setup.ctx.seed()));

    // 2. Load a template.
    let template = qssm_templates::resolve("age-gate-21")
        .expect("age-gate-21 template should exist");
    println!("[2] Template loaded: age-gate-21");

    // 3. Build the public claim.
    let claim = json!({ "claim": { "age_years": 30 } });
    println!("[3] Claim: age_years = 30");

    // 4. Prove.
    let entropy_seed = setup.fresh_entropy();
    let proof = qssm_local_prover::prove(&setup.ctx, &template, &claim, 100, 50, setup.binding_ctx, entropy_seed)
        .expect("prove failed");
    println!("[4] Proof generated (MS root: {})", hex_short(proof.ms_root()));

    // 5. Verify.
    let ok = qssm_api::verify(&setup.ctx, &template, &claim, &proof, setup.binding_ctx)
        .expect("verify failed");
    println!("[5] Verified: {ok}");
    assert!(ok, "proof should verify");

    println!("\n=== Done ===");
}
