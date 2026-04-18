//! Ghost-Mirror adversarial cases: false inequality, bad paths, tampered FS binding.

use qssm_ms::{commit, prove, verify, GhostMirrorProof, MsError, Root};

const BINDING_CTX: [u8; 32] = [0x66; 32];

fn setup() -> ([u8; 32], [u8; 32]) {
    ([0x11; 32], [0x22; 32])
}

#[test]
fn equal_values_no_proof() {
    let (seed, binding_ent) = setup();
    let (_root, salts) = commit(seed, binding_ent).unwrap();
    let err = prove(42, 42, &salts, binding_ent, b"ctx", &BINDING_CTX).unwrap_err();
    assert!(matches!(err, qssm_ms::MsError::NoValidRotation));
}

#[test]
fn value_not_greater_than_target() {
    let (seed, binding_ent) = setup();
    let (_root, salts) = commit(seed, binding_ent).unwrap();
    assert!(prove(50, 100, &salts, binding_ent, b"ctx", &BINDING_CTX).is_err());
}

#[test]
fn verify_fails_when_values_do_not_satisfy_inequality() {
    let (_seed, binding_ent) = setup();
    let alice = 10_000u64;
    let bob = 5_000u64;
    let (root_alice, salts_alice) = commit([7u8; 32], binding_ent).unwrap();
    let proof = prove(alice, bob, &salts_alice, binding_ent, b"ctx", &BINDING_CTX).unwrap();
    // Same proof bytes, but claim the weaker direction — opening bit / FS binding must fail.
    assert!(!verify(
        root_alice,
        &proof,
        binding_ent,
        bob,
        alice,
        b"ctx",
        &BINDING_CTX,
    ));
}

#[test]
fn verify_rejects_wrong_root() {
    let (seed, binding_ent) = setup();
    let (root, salts) = commit(seed, binding_ent).unwrap();
    let proof = prove(9, 1, &salts, binding_ent, b"x", &BINDING_CTX).unwrap();
    let other = Root::new([0xFF; 32]);
    assert!(!verify(other, &proof, binding_ent, 9, 1, b"x", &BINDING_CTX));
    let _ = root;
}

#[test]
fn verify_rejects_tampered_merkle_sibling() {
    let (seed, binding_ent) = setup();
    let (root, salts) = commit(seed, binding_ent).unwrap();
    let proof = prove(100, 1, &salts, binding_ent, b"y", &BINDING_CTX).unwrap();
    // Tamper with the first Merkle sibling by reconstructing with a flipped byte.
    let mut tampered_path: Vec<[u8; 32]> = proof.path().to_vec();
    if let Some(s) = tampered_path.first_mut() {
        s[0] ^= 0x01;
    }
    let tampered = qssm_ms::GhostMirrorProof::new(
        proof.n(), proof.k(), proof.bit_at_k(),
        *proof.opened_salt(), tampered_path, *proof.challenge(),
    ).unwrap();
    assert!(!verify(root, &tampered, binding_ent, 100, 1, b"y", &BINDING_CTX));
}

#[test]
fn verify_rejects_tampered_fs_challenge() {
    let (seed, binding_ent) = setup();
    let (root, salts) = commit(seed, binding_ent).unwrap();
    let proof = prove(50, 10, &salts, binding_ent, b"z", &BINDING_CTX).unwrap();
    let mut bad_challenge = *proof.challenge();
    bad_challenge[0] ^= 0x80;
    let tampered = qssm_ms::GhostMirrorProof::new(
        proof.n(), proof.k(), proof.bit_at_k(),
        *proof.opened_salt(), proof.path().to_vec(), bad_challenge,
    ).unwrap();
    assert!(!verify(root, &tampered, binding_ent, 50, 10, b"z", &BINDING_CTX));
}

#[test]
fn verify_rejects_mutated_opening_fields() {
    let (seed, binding_ent) = setup();
    let (root, salts) = commit(seed, binding_ent).unwrap();
    let proof = prove(80, 20, &salts, binding_ent, b"w", &BINDING_CTX).unwrap();
    let flipped_bit = proof.bit_at_k() ^ 1;
    let tampered = qssm_ms::GhostMirrorProof::new(
        proof.n(), proof.k(), flipped_bit,
        *proof.opened_salt(), proof.path().to_vec(), *proof.challenge(),
    ).unwrap();
    assert!(!verify(root, &tampered, binding_ent, 80, 20, b"w", &BINDING_CTX));
}

#[test]
fn verify_fails_on_mismatched_binding_context() {
    let (seed, binding_ent) = setup();
    let (root, salts) = commit(seed, binding_ent).unwrap();
    let ctx_a = [1u8; 32];
    let ctx_b = [2u8; 32];
    let proof = prove(10, 0, &salts, binding_ent, b"ctx", &ctx_a).unwrap();
    assert!(!verify(root, &proof, binding_ent, 10, 0, b"ctx", &ctx_b));
}

#[test]
fn worst_case_nonce_scan_still_finds_proof_when_relation_holds() {
    let (seed, binding_ent) = setup();
    let (root, salts) = commit(seed, binding_ent).unwrap();
    let proof = prove(255, 0, &salts, binding_ent, b"nonce-scan", &BINDING_CTX).unwrap();
    assert!(verify(
        root,
        &proof,
        binding_ent,
        255,
        0,
        b"nonce-scan",
        &BINDING_CTX,
    ));
}

// ── Phase 5: Hardening tests ──────────────────────────────────────────

#[test]
fn boundary_u64_max_vs_zero_may_exceed_nonce_budget() {
    // u64::MAX vs 0 is an extreme gap. With 256 nonce trials the rotation
    // may or may not find a valid crossing — both outcomes are correct.
    let (seed, be) = setup();
    let (root, salts) = commit(seed, be).unwrap();
    match prove(u64::MAX, 0, &salts, be, b"b", &BINDING_CTX) {
        Ok(proof) => assert!(verify(root, &proof, be, u64::MAX, 0, b"b", &BINDING_CTX)),
        Err(MsError::NoValidRotation) => {} // acceptable
        Err(e) => panic!("unexpected error: {e:?}"),
    }
}

#[test]
fn boundary_u64_max_vs_max_minus_one() {
    let (seed, be) = setup();
    let (root, salts) = commit(seed, be).unwrap();
    let proof = prove(u64::MAX, u64::MAX - 1, &salts, be, b"b", &BINDING_CTX).unwrap();
    assert!(verify(root, &proof, be, u64::MAX, u64::MAX - 1, b"b", &BINDING_CTX));
}

#[test]
fn boundary_one_vs_zero() {
    let (seed, be) = setup();
    let (root, salts) = commit(seed, be).unwrap();
    let proof = prove(1, 0, &salts, be, b"b", &BINDING_CTX).unwrap();
    assert!(verify(root, &proof, be, 1, 0, b"b", &BINDING_CTX));
}

#[test]
fn boundary_2pow63_vs_2pow63_minus_one() {
    let (seed, be) = setup();
    let (root, salts) = commit(seed, be).unwrap();
    let a = 1u64 << 63;
    let b = a - 1;
    let proof = prove(a, b, &salts, be, b"b", &BINDING_CTX).unwrap();
    assert!(verify(root, &proof, be, a, b, b"b", &BINDING_CTX));
}

#[test]
fn boundary_2pow32_vs_zero() {
    let (seed, be) = setup();
    let (root, salts) = commit(seed, be).unwrap();
    let a = 1u64 << 32;
    let proof = prove(a, 0, &salts, be, b"b", &BINDING_CTX).unwrap();
    assert!(verify(root, &proof, be, a, 0, b"b", &BINDING_CTX));
}

#[test]
fn constructor_rejects_bit_at_k_two() {
    let err = GhostMirrorProof::new(0, 0, 2, [0; 32], vec![[0; 32]; 7], [0; 32]).unwrap_err();
    assert!(matches!(err, MsError::InvalidProofField(_)));
}

#[test]
fn constructor_rejects_k_64() {
    let err = GhostMirrorProof::new(0, 64, 0, [0; 32], vec![[0; 32]; 7], [0; 32]).unwrap_err();
    assert!(matches!(err, MsError::InvalidProofField(_)));
}

#[test]
fn constructor_rejects_path_len_zero() {
    let err = GhostMirrorProof::new(0, 0, 0, [0; 32], vec![], [0; 32]).unwrap_err();
    assert!(matches!(err, MsError::InvalidProofField(_)));
}

#[test]
fn constructor_rejects_path_len_six() {
    let err = GhostMirrorProof::new(0, 0, 0, [0; 32], vec![[0; 32]; 6], [0; 32]).unwrap_err();
    assert!(matches!(err, MsError::InvalidProofField(_)));
}

#[test]
fn constructor_accepts_valid_fields() {
    let p = GhostMirrorProof::new(0, 63, 1, [0xAA; 32], vec![[0xBB; 32]; 7], [0xCC; 32]).unwrap();
    assert_eq!(p.n(), 0);
    assert_eq!(p.k(), 63);
    assert_eq!(p.bit_at_k(), 1);
    assert_eq!(p.path().len(), 7);
}

#[test]
fn deterministic_commit() {
    let (seed, be) = setup();
    let (r1, _) = commit(seed, be).unwrap();
    let (r2, _) = commit(seed, be).unwrap();
    assert_eq!(r1, r2);
}

#[test]
fn deterministic_prove() {
    let (seed, be) = setup();
    let (_, salts) = commit(seed, be).unwrap();
    let p1 = prove(100, 1, &salts, be, b"d", &BINDING_CTX).unwrap();
    let p2 = prove(100, 1, &salts, be, b"d", &BINDING_CTX).unwrap();
    assert_eq!(p1.n(), p2.n());
    assert_eq!(p1.k(), p2.k());
    assert_eq!(p1.bit_at_k(), p2.bit_at_k());
    assert_eq!(*p1.challenge(), *p2.challenge());
}

#[test]
fn cross_context_replay_rejected() {
    let (seed, be) = setup();
    let (root, salts) = commit(seed, be).unwrap();
    let proof = prove(10, 1, &salts, be, b"ctx-A", &BINDING_CTX).unwrap();
    // Replay the same proof under a different purpose tag.
    assert!(!verify(root, &proof, be, 10, 1, b"ctx-B", &BINDING_CTX));
}

#[test]
fn different_seeds_different_roots() {
    let be = [0x22; 32];
    let (r1, _) = commit([1u8; 32], be).unwrap();
    let (r2, _) = commit([2u8; 32], be).unwrap();
    assert_ne!(r1, r2);
}

#[test]
fn salt_uniqueness_all_128() {
    let (seed, be) = setup();
    let (_, salts) = commit(seed, be).unwrap();
    let mut seen = std::collections::HashSet::new();
    for i in 0..128 {
        assert!(seen.insert(salts[i]), "duplicate salt at index {i}");
    }
}

#[test]
fn debug_redacts_secrets() {
    let (seed, be) = setup();
    let (_, salts) = commit(seed, be).unwrap();
    let proof = prove(10, 1, &salts, be, b"d", &BINDING_CTX).unwrap();
    let dbg = format!("{:?}", proof);
    assert!(!dbg.contains(&format!("{:02x}", proof.opened_salt()[0])));
    let salt_dbg = format!("{:?}", salts);
    assert!(salt_dbg.contains("REDACTED"));
}
