//! Ghost-Mirror adversarial cases: false inequality, bad paths, tampered FS binding.

use qssm_ms::{commit, prove, verify, Root};

fn setup() -> ([u8; 32], [u8; 32]) {
    ([0x11; 32], [0x22; 32])
}

#[test]
fn equal_values_no_proof() {
    let (seed, ledger) = setup();
    let v = 42u64;
    let (_root, salts) = commit(v, seed, ledger).unwrap();
    let err = prove(v, v, &salts, ledger, b"ctx").unwrap_err();
    assert!(matches!(err, qssm_ms::MsError::NoValidRotation));
}

#[test]
fn value_not_greater_than_target() {
    let (seed, ledger) = setup();
    let (_root, salts) = commit(100u64, seed, ledger).unwrap();
    assert!(prove(50, 100, &salts, ledger, b"ctx").is_err());
}

#[test]
fn verify_fails_when_values_do_not_satisfy_inequality() {
    let (_seed, ledger) = setup();
    let alice = 10_000u64;
    let bob = 5_000u64;
    let (root_alice, salts_alice) = commit(alice, [7u8; 32], ledger).unwrap();
    let proof = prove(alice, bob, &salts_alice, ledger, b"ctx").unwrap();
    // Same proof bytes, but claim the weaker direction — opening bit / FS binding must fail.
    assert!(!verify(
        root_alice,
        &proof,
        ledger,
        bob,
        alice,
        b"ctx"
    ));
}

#[test]
fn verify_rejects_wrong_root() {
    let (seed, ledger) = setup();
    let (root, salts) = commit(9u64, seed, ledger).unwrap();
    let proof = prove(9, 1, &salts, ledger, b"x").unwrap();
    let other = Root([0xFF; 32]);
    assert!(!verify(other, &proof, ledger, 9, 1, b"x"));
    let _ = root;
}

#[test]
fn verify_rejects_tampered_merkle_sibling() {
    let (seed, ledger) = setup();
    let (root, salts) = commit(100u64, seed, ledger).unwrap();
    let mut proof = prove(100, 1, &salts, ledger, b"y").unwrap();
    if let Some(s) = proof.path.first_mut() {
        s[0] ^= 0x01;
    }
    assert!(!verify(root, &proof, ledger, 100, 1, b"y"));
}

#[test]
fn verify_rejects_tampered_fs_challenge() {
    let (seed, ledger) = setup();
    let (root, salts) = commit(50u64, seed, ledger).unwrap();
    let mut proof = prove(50, 10, &salts, ledger, b"z").unwrap();
    proof.challenge[0] ^= 0x80;
    assert!(!verify(root, &proof, ledger, 50, 10, b"z"));
}

#[test]
fn verify_rejects_mutated_opening_fields() {
    let (seed, ledger) = setup();
    let (root, salts) = commit(80u64, seed, ledger).unwrap();
    let mut proof = prove(80, 20, &salts, ledger, b"w").unwrap();
    proof.bit_at_k ^= 1;
    assert!(!verify(root, &proof, ledger, 80, 20, b"w"));
}

#[test]
fn worst_case_nonce_scan_still_finds_proof_when_relation_holds() {
    let (seed, ledger) = setup();
    let (root, salts) = commit(255u64, seed, ledger).unwrap();
    let proof = prove(255, 0, &salts, ledger, b"nonce-scan").unwrap();
    assert!(verify(root, &proof, ledger, 255, 0, b"nonce-scan"));
}
