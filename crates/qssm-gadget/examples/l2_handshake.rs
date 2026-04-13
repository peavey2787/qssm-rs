//! **L2 handshake demo** — simulates a Kaspa L1 block binding, rolls up two state leaves with **`merkle_parent`**, then runs the **Sovereign Digest** path for Engine A.
//!
//! Writes to the **current working directory**:
//! - **`prover_package.json`** — sovereign + Merkle witness JSON + metadata for Engine A.
//! - **`r1cs_merkle_parent.manifest.txt`** — **65 184** constraint lines (`Blake3Gadget::export_r1cs`).
//!
//! Run: `cargo run -p qssm-gadget --example l2_handshake`

use qssm_gadget::binding::{encode_proof_metadata_v1, SovereignWitness};
use qssm_gadget::blake3_compress::hash_merkle_parent_witness;
use qssm_gadget::lattice_bridge::verify_limb_binding_json;
use qssm_gadget::prover_json::{merkle_parent_private_wire_count, sovereign_private_wire_count};
use qssm_gadget::r1cs::Blake3Gadget;
use qssm_utils::hashing::{blake3_hash, hash_domain, DOMAIN_MSSQ_ROLLUP_CONTEXT};
use serde_json::json;
use std::path::Path;

fn run() {
    let mut kaspa_block_id = [0u8; 32];
    kaspa_block_id[..19].copy_from_slice(b"SIM_KASPA_PARENT_V1");

    let leaf_left = blake3_hash(b"L2_ROLLUP_LEAF_LEFT");
    let leaf_right = blake3_hash(b"L2_ROLLUP_LEAF_RIGHT");
    let merkle_w = hash_merkle_parent_witness(&leaf_left, &leaf_right);
    assert!(merkle_w.validate());
    let state_root = merkle_w.digest();

    let rollup_ctx = hash_domain(DOMAIN_MSSQ_ROLLUP_CONTEXT, &[kaspa_block_id.as_slice()]);
    let challenge = blake3_hash(b"L2_FS_CHALLENGE_V1");
    let meta = encode_proof_metadata_v1(7, 3, 1, &challenge);
    let sovereign = SovereignWitness::bind(state_root, rollup_ctx, meta);
    assert!(sovereign.validate());

    let r1cs_text = Blake3Gadget::export_r1cs(&merkle_w);
    assert_eq!(r1cs_text.lines().count(), 65_184);

    let sovereign_json = sovereign.to_prover_json();
    std::fs::write("sovereign_witness.json", sovereign_json.as_str())
        .expect("sovereign_witness.json");

    let merkle_json = merkle_w.to_prover_json();
    std::fs::write("merkle_parent_witness.json", merkle_json.as_str())
        .expect("merkle_parent_witness.json");

    let sovereign_private_wires = sovereign_private_wire_count();
    let merkle_wires = merkle_parent_private_wire_count(&merkle_w);

    let package = json!({
        "package_version": "qssm-l2-handshake-v1",
        "description": "Kaspa-anchored L2 handshake: Merkle parent (BLAKE3 compress witness) + Sovereign limb for Engine A",
        "sim_kaspa_parent_block_id_hex": hex::encode(kaspa_block_id),
        "merkle_leaf_left_hex": hex::encode(leaf_left),
        "merkle_leaf_right_hex": hex::encode(leaf_right),
        "rollup_state_root_hex": hex::encode(state_root),
        "engine_a_public": {
            "message_limb_u30": sovereign.message_limb,
        },
        "artifacts": {
            "sovereign_witness_json": "sovereign_witness.json",
            "merkle_parent_witness_json": "merkle_parent_witness.json",
            "r1cs_merkle_manifest_txt": "r1cs_merkle_parent.manifest.txt",
        },
        "witness_wire_counts": {
            "sovereign_private_bit_wires": sovereign_private_wires,
            "merkle_parent_private_bit_wires": merkle_wires,
        },
        "r1cs": {
            "constraint_line_count": r1cs_text.lines().count(),
            "manifest_file": "r1cs_merkle_parent.manifest.txt",
            "line_format": "xor|full_adder|equal with tab-separated var indices",
        },
    });

    std::fs::write(
        "prover_package.json",
        serde_json::to_string_pretty(&package).expect("package json"),
    )
    .expect("write prover_package.json");
    std::fs::write("r1cs_merkle_parent.manifest.txt", r1cs_text.as_str())
        .expect("write r1cs manifest");

    eprintln!(
        "Wrote prover_package.json, sovereign_witness.json, merkle_parent_witness.json, r1cs_merkle_parent.manifest.txt ({} constraints, {} merkle private wires)",
        r1cs_text.lines().count(),
        merkle_wires
    );

    verify_limb_binding_json(Path::new(".")).expect("verify_limb_binding_json");
    println!("PATH A VERIFIED: Kaspa State bound to Lattice Proof successfully.");

    #[cfg(feature = "lattice-bridge")]
    {
        use qssm_gadget::lattice_bridge::verify_handshake_with_le;
        verify_handshake_with_le(Path::new(".")).expect("verify_handshake_with_le");
        println!("PATH A + LE: PublicInstance and RqPoly::embed_constant coeff0 OK.");
    }
}

fn main() {
    // Large compress witnesses + JSON serialization need more than the default Windows stack (1 MiB).
    const STACK: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(run)
        .expect("spawn l2_handshake worker")
        .join()
        .expect("l2_handshake worker panicked");
}
