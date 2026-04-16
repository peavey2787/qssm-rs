//! Golden-style check: Poly-Ops builder reproduces the same `engine_a_public` as direct `SovereignWitness::bind`.
//!
//! Merkle BLAKE3 witness synthesis needs a larger stack than the default test thread (same as `l2_handshake` example).

use qssm_gadget::binding::SovereignWitness;
use qssm_gadget::poly_ops::{
    l2_merkle_sovereign_pipe, L2HandshakeArtifacts, LatticePolyOp, MerkleParentBlake3Op,
    PolyOpContext, ProverPackageBuilder, SovereignLimbV2Params,
};
use qssm_gadget::R1csLineExporter;
use qssm_utils::hashing::{blake3_hash, hash_domain, DOMAIN_MSSQ_ROLLUP_CONTEXT};

fn polyops_engine_a_public_matches_direct_sovereign_bind_inner() {
    let dir = tempfile::tempdir().expect("tempdir");
    let kaspa = [0xabu8; 32];
    let left = blake3_hash(b"L2_ROLLUP_LEAF_LEFT");
    let right = blake3_hash(b"L2_ROLLUP_LEAF_RIGHT");
    let rollup = hash_domain(DOMAIN_MSSQ_ROLLUP_CONTEXT, &[kaspa.as_slice()]);
    let challenge = blake3_hash(b"L2_FS_CHALLENGE_V1");
    let entropy = blake3_hash(b"L2_LOCAL_ENTROPY_V1");

    let merkle = MerkleParentBlake3Op::new(left, right);
    let mut ctx = PolyOpContext::new("t");
    let mut exporter = R1csLineExporter::new();
    let state_root = merkle
        .synthesize_with_context((), &mut exporter, &mut ctx)
        .expect("merkle")
        .state_root;

    let direct = SovereignWitness::bind(state_root.0, rollup, 7, 3, 1, challenge, entropy, false);
    assert!(direct.validate());

    let pipe = l2_merkle_sovereign_pipe(
        MerkleParentBlake3Op::new(left, right),
        SovereignLimbV2Params {
            rollup_context_digest: rollup,
            n: 7,
            k: 3,
            bit_at_k: 1,
            challenge,
            sovereign_entropy: entropy,
            nist_included: false,
            device_entropy_link: None,
        },
    );

    ProverPackageBuilder::build_l2_handshake_v1(
        dir.path(),
        &pipe,
        &L2HandshakeArtifacts {
            kaspa_parent: kaspa,
            leaf_left: left,
            leaf_right: right,
            nist_included: false,
        },
    )
    .expect("build");

    let pkg_raw =
        std::fs::read_to_string(dir.path().join("prover_package.json")).expect("read package");
    let pkg: serde_json::Value = serde_json::from_str(&pkg_raw).expect("parse package");
    let ep = &pkg["engine_a_public"];
    assert_eq!(
        ep["message_limb_u30"].as_u64().expect("limb"),
        direct.message_limb
    );
    let arr = ep["digest_coeff_vector_u4"].as_array().expect("coeffs");
    assert_eq!(arr.len(), direct.digest_coeff_vector.len());
    for (i, v) in arr.iter().enumerate() {
        assert_eq!(v.as_u64().unwrap() as u32, direct.digest_coeff_vector[i]);
    }
}

#[test]
fn polyops_engine_a_public_matches_direct_sovereign_bind() {
    const STACK: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(polyops_engine_a_public_matches_direct_sovereign_bind_inner)
        .expect("spawn")
        .join()
        .expect("join panicked");
}

fn prover_package_refresh_arrays_present_inner() {
    let dir = tempfile::tempdir().expect("tempdir");
    let kaspa = [2u8; 32];
    let left = blake3_hash(b"REFRESH_LEFT");
    let right = blake3_hash(b"REFRESH_RIGHT");
    let rollup = hash_domain(DOMAIN_MSSQ_ROLLUP_CONTEXT, &[kaspa.as_slice()]);
    let pipe = l2_merkle_sovereign_pipe(
        MerkleParentBlake3Op::new(left, right),
        SovereignLimbV2Params {
            rollup_context_digest: rollup,
            n: 0,
            k: 0,
            bit_at_k: 0,
            challenge: [0u8; 32],
            sovereign_entropy: [1u8; 32],
            nist_included: false,
            device_entropy_link: None,
        },
    );
    ProverPackageBuilder::build_l2_handshake_v1(
        dir.path(),
        &pipe,
        &L2HandshakeArtifacts {
            kaspa_parent: kaspa,
            leaf_left: left,
            leaf_right: right,
            nist_included: false,
        },
    )
    .expect("build");
    let raw = std::fs::read_to_string(dir.path().join("prover_package.json")).expect("read");
    let pkg: serde_json::Value = serde_json::from_str(&raw).expect("parse");
    assert!(pkg["refresh_metadata"].is_array());
    assert_eq!(pkg["refresh_metadata"].as_array().unwrap().len(), 0);
    assert!(pkg["warnings"].is_array());
    assert!(pkg["warnings"].as_array().unwrap().is_empty());
}

#[test]
fn prover_package_refresh_arrays_present() {
    const STACK: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(prover_package_refresh_arrays_present_inner)
        .expect("spawn")
        .join()
        .expect("join panicked");
}

fn engine_a_public_key_order_in_package_inner() {
    let dir = tempfile::tempdir().expect("tempdir");
    let kaspa = [1u8; 32];
    let left = blake3_hash(b"X");
    let right = blake3_hash(b"Y");
    let rollup = hash_domain(DOMAIN_MSSQ_ROLLUP_CONTEXT, &[kaspa.as_slice()]);
    let ch = [2u8; 32];
    let ent = [3u8; 32];
    let pipe = l2_merkle_sovereign_pipe(
        MerkleParentBlake3Op::new(left, right),
        SovereignLimbV2Params {
            rollup_context_digest: rollup,
            n: 0,
            k: 0,
            bit_at_k: 0,
            challenge: ch,
            sovereign_entropy: ent,
            nist_included: false,
            device_entropy_link: None,
        },
    );
    ProverPackageBuilder::build_l2_handshake_v1(
        dir.path(),
        &pipe,
        &L2HandshakeArtifacts {
            kaspa_parent: kaspa,
            leaf_left: left,
            leaf_right: right,
            nist_included: false,
        },
    )
    .unwrap();
    let raw = std::fs::read_to_string(dir.path().join("prover_package.json")).unwrap();
    // Keys must appear in transcript order: message_limb first, then digest vector.
    let msg_pos = raw.find("\"message_limb_u30\"").expect("message_limb");
    let dig_pos = raw.find("\"digest_coeff_vector_u4\"").expect("digest");
    assert!(
        msg_pos < dig_pos,
        "engine_a_public key order must match TranscriptMap"
    );
}

#[test]
fn engine_a_public_key_order_in_package() {
    const STACK: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(engine_a_public_key_order_in_package_inner)
        .expect("spawn")
        .join()
        .expect("join panicked");
}
