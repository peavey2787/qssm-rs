//! Chain 10 proofs into a JSONL proof stream.
//!
//! ```text
//! cargo run -p zk-examples --bin proof_stream
//! ```

use qssm_utils::hashing::blake3_hash;
use serde_json::json;
use zk_api::ProofContext;

fn main() {
    println!("=== QSSM Proof Stream Demo ===\n");

    let seed = blake3_hash(b"DEMO-SEED-proof-stream");
    let ctx = ProofContext::new(seed);
    let binding_ctx = blake3_hash(b"proof-stream-demo-binding");

    // Create a temporary directory for the stream.
    let dir = tempfile::tempdir().expect("tempdir");
    let _mgr = zk_api::create_proof_stream(dir.path(), binding_ctx)
        .expect("create_proof_stream failed");
    println!("Stream root: {}", dir.path().display());

    let template = template_lib::resolve("age-gate-21")
        .expect("age-gate-21 template should exist");

    // Generate and append 10 proofs.
    for i in 0..10 {
        let age = 21 + i;
        let claim = json!({ "claim": { "age_years": age } });
        let proof = zk_api::prove(&ctx, &template, &claim, 100, 50, binding_ctx)
            .expect("prove failed");

        // Verify before appending.
        let ok = zk_api::verify(&ctx, &template, &claim, &proof, binding_ctx)
            .expect("verify failed");
        assert!(ok, "proof {i} should verify");

        println!("[step {i:>2}] age={age}, MS root={}, verified={ok}",
            &hex::encode(&proof.ms_root)[..16]);
    }

    println!("\n=== {n} proofs generated and verified ===", n = 10);
}
