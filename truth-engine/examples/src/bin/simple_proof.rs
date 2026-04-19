//! Minimal 5-call prove/verify demo with no blockchain dependencies.
//!
//! ```text
//! cargo run -p zk-examples --bin simple_proof
//! ```

use qssm_api::{commit, compile, open, prove, verify};
use zk_examples::hex_short;

fn main() {
    println!("=== QSSM Simple Proof Demo ===\n");

    // 1. Compile a template into a blueprint (byte array).
    let blueprint = compile("age-gate-21").expect("compile failed");
    println!("[1] Blueprint compiled: age-gate-21");

    // 2. Commit a secret for later reveal (32 bytes).
    let secret = b"my-secret-data";
    let salt = [42u8; 32];
    let commitment = commit(secret, &salt);
    println!("[2] Commitment: {}", hex_short(&commitment));

    // 3. Prove a claim (returns a proof byte array).
    let claim = br#"{"claim":{"age_years":30}}"#;
    let proof = prove(claim, &salt, &blueprint).expect("prove failed");
    println!("[3] Proof generated ({} bytes)", proof.len());

    // 4. Verify.
    let ok = verify(&proof, &blueprint);
    println!("[4] Verified: {ok}");
    assert!(ok, "proof should verify");

    // 5. Open — simple reveal. Compare with == .
    let revealed = open(secret, &salt);
    assert_eq!(revealed, commitment, "reveal must match commitment");
    println!("[5] Reveal matches commitment");

    println!("\n=== Done ===");
}
