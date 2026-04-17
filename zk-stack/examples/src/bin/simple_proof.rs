//! Minimal 5-call prove/verify demo with no blockchain dependencies.
//!
//! ```text
//! cargo run -p zk-examples --bin simple_proof
//! ```

use qssm_utils::hashing::blake3_hash;
use serde_json::json;
use zk_api::ProofContext;

fn main() {
    println!("=== QSSM Simple Proof Demo ===\n");

    // 1. Create a proof context from a seed.
    let seed = blake3_hash(b"DEMO-SEED-simple-proof");
    let ctx = ProofContext::new(seed);
    println!("[1] ProofContext created (seed: {})", hex_short(&seed));

    // 2. Load a template.
    let template = template_lib::resolve("age-gate-21")
        .expect("age-gate-21 template should exist");
    println!("[2] Template loaded: age-gate-21");

    // 3. Build the public claim.
    let claim = json!({ "claim": { "age_years": 30 } });
    println!("[3] Claim: age_years = 30");

    // 4. Prove.
    let binding_ctx = blake3_hash(b"simple-proof-demo-binding");
    let proof = zk_api::prove(&ctx, &template, &claim, 100, 50, binding_ctx)
        .expect("prove failed");
    println!("[4] Proof generated (MS root: {})", hex_short(&proof.ms_root));

    // 5. Verify.
    let ok = zk_api::verify(&ctx, &template, &claim, &proof, binding_ctx)
        .expect("verify failed");
    println!("[5] Verified: {ok}");
    assert!(ok, "proof should verify");

    println!("\n=== Done ===");
}

fn hex_short(bytes: &[u8]) -> String {
    let h = hex::encode(bytes);
    format!("{}...{}", &h[..8], &h[h.len() - 8..])
}
