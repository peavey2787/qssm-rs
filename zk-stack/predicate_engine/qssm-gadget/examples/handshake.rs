//! **Sovereign handshake demo** -- simulates an anchor-based binding, rolls up two state leaves with **`merkle_parent`**, then runs the **Sovereign Digest** path (Phase 8 entropy floor + opportunistic NIST booster) for Engine A.
//!
//! Writes to **`assets/`** via [`ProverPackageBuilder`](qssm_gadget::poly_ops::ProverPackageBuilder) (no manual `prover_package` JSON).
//!
//! Run: `cargo run -p qssm-gadget --example handshake`
//!
//! Phase 8: **500 ms** NIST beacon timeout -- if the server is not ready, the **anchor || local** BLAKE3 floor is used alone (**`nist_included = false`**).

use qssm_gadget::entropy::EntropyProvider;
use qssm_gadget::lattice_bridge::verify_limb_binding_json;
use qssm_gadget::poly_ops::{
    SovereignHandshakeArtifacts, MerkleParentBlake3Op, ProverPackageBuilder, SovereignLimbV2Params,
};
use qssm_gadget::prover_json::merkle_parent_private_wire_count;
use qssm_utils::hashing::{blake3_hash, hash_domain, DOMAIN_MSSQ_ROLLUP_CONTEXT};
use std::path::Path;

fn run() {
    let assets_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets");
    std::fs::create_dir_all(&assets_dir).expect("create assets dir");

    let mut anchor_id = [0u8; 32];
    anchor_id[..16].copy_from_slice(b"SIM_ANCHOR_HASH1");

    let leaf_left = blake3_hash(b"STATE_LEAF_LEFT");
    let leaf_right = blake3_hash(b"STATE_LEAF_RIGHT");
    let rollup_ctx = hash_domain(DOMAIN_MSSQ_ROLLUP_CONTEXT, &[anchor_id.as_slice()]);
    let challenge = blake3_hash(b"FS_CHALLENGE_V1");
    let local_entropy = blake3_hash(b"LOCAL_ENTROPY_V1");

    eprintln!("Phase 8 -- NIST Down (simulated timeout / offline): anchor || local floor only");
    let (ent_down, nist_down) = EntropyProvider::simulate_nist_down()
        .generate_sovereign_entropy(anchor_id, local_entropy);
    eprintln!(
        "  nist_included={nist_down} sovereign_entropy_hex={}",
        hex::encode(ent_down)
    );

    let sim_pulse = blake3_hash(b"SIM_NIST_PULSE_V1");
    eprintln!("Phase 8 -- NIST Up (simulated 200 OK pulse XOR into floor)");
    let (ent_up, nist_up) = EntropyProvider::simulate_nist_up(sim_pulse)
        .generate_sovereign_entropy(anchor_id, local_entropy);
    eprintln!(
        "  nist_included={nist_up} sovereign_entropy_hex={}",
        hex::encode(ent_up)
    );

    let prov = EntropyProvider::default();
    let (sovereign_entropy, nist_included) =
        prov.generate_sovereign_entropy(anchor_id, local_entropy);
    eprintln!("Phase 8 -- Production policy (<=500ms NIST try): nist_included={nist_included}");

    let pipe =
        MerkleParentBlake3Op::new(leaf_left, leaf_right).pipe_sovereign(SovereignLimbV2Params {
            binding_context: rollup_ctx,
            n: 7,
            k: 3,
            bit_at_k: 1,
            challenge,
            sovereign_entropy,
            nist_included,
            device_entropy_link: None,
        });

    let out = ProverPackageBuilder::build_sovereign_handshake_v1(
        &assets_dir,
        &pipe,
        &SovereignHandshakeArtifacts {
            anchor_hash: anchor_id,
            leaf_left,
            leaf_right,
            nist_included,
        },
    )
    .expect("build_sovereign_handshake_v1");

    eprintln!(
        "Wrote prover_package.json, sovereign_witness.json, merkle_parent_witness.json, r1cs_merkle_parent.manifest.txt ({} constraints, {} merkle private wires)",
        out.merkle.r1cs_text.lines().count(),
        merkle_parent_private_wire_count(&out.merkle.witness)
    );

    verify_limb_binding_json(&assets_dir).expect("verify_limb_binding_json");
    println!("PATH A VERIFIED: Anchor state bound to Lattice Proof successfully.");

    #[cfg(feature = "lattice-bridge")]
    {
        use qssm_gadget::lattice_bridge::verify_handshake_with_le;
        verify_handshake_with_le(&assets_dir).expect("verify_handshake_with_le");
        println!("PATH A + LE: PublicInstance and RqPoly::embed_constant coeff0 OK.");
    }
}

fn main() {
    const STACK: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(run)
        .expect("spawn handshake worker")
        .join()
        .expect("handshake worker panicked");
}
