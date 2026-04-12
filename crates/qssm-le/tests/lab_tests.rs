//! Lyubashevsky FS + rejection: prove/verify and failure modes.

use qssm_le::{
    commit_mlwe, prove_arithmetic, prove_with_witness, verify_lattice, Commitment, LatticeProof,
    LeError, PublicInstance, RqPoly, VerifyingKey, Witness, BETA, MAX_MESSAGE,
};
use rand::thread_rng;

const CTX: [u8; 32] = [0xA1; 32];

#[test]
fn prove_verify_roundtrip() {
    let vk = VerifyingKey::from_seed([0xC0u8; 32]);
    let public = PublicInstance { message: 42 };
    let mut r = [0i32; 64];
    r[0] = 1;
    r[1] = -1;
    let witness = Witness { r };
    let (commitment, proof) = prove_arithmetic(&vk, &public, &witness, &CTX).unwrap();
    assert!(verify_lattice(&vk, &public, &commitment, &proof, &CTX).unwrap());
}

#[test]
fn message_out_of_range_rejected_at_commit() {
    let vk = VerifyingKey::from_seed([1u8; 32]);
    let public = PublicInstance {
        message: MAX_MESSAGE,
    };
    let w = Witness { r: [0i32; 64] };
    let err = commit_mlwe(&vk, &public, &w).unwrap_err();
    assert!(matches!(err, LeError::MessageOutOfRange));
}

#[test]
fn witness_shortness_violation_rejected() {
    let vk = VerifyingKey::from_seed([2u8; 32]);
    let public = PublicInstance { message: 0 };
    let mut r = [0i32; 64];
    r[0] = (BETA as i32) + 1;
    let w = Witness { r };
    let err = commit_mlwe(&vk, &public, &w).unwrap_err();
    assert!(matches!(err, LeError::RejectedSample));
}

#[test]
fn verify_rejects_wrong_commitment_for_same_proof() {
    let vk = VerifyingKey::from_seed([3u8; 32]);
    let public = PublicInstance { message: 7 };
    let w = Witness { r: [0i32; 64] };
    let (c_real, proof) = prove_arithmetic(&vk, &public, &w, &CTX).unwrap();
    let other = PublicInstance { message: 8 };
    let c_other = commit_mlwe(&vk, &other, &w).unwrap();
    assert!(!verify_lattice(&vk, &public, &c_other, &proof, &CTX).unwrap());
    let _ = c_real;
}

#[test]
fn verify_rejects_wrong_context() {
    let vk = VerifyingKey::from_seed([4u8; 32]);
    let public = PublicInstance { message: 99 };
    let w = Witness { r: [0i32; 64] };
    let (c, proof) = prove_arithmetic(&vk, &public, &w, &CTX).unwrap();
    let bad = [0xFFu8; 32];
    assert!(!verify_lattice(&vk, &public, &c, &proof, &bad).unwrap());
}

#[test]
fn verify_rejects_tampered_challenge() {
    let vk = VerifyingKey::from_seed([5u8; 32]);
    let public = PublicInstance { message: 3 };
    let w = Witness { r: [0i32; 64] };
    let (c, mut proof) = prove_arithmetic(&vk, &public, &w, &CTX).unwrap();
    proof.challenge[0] ^= 0x01;
    assert!(!verify_lattice(&vk, &public, &c, &proof, &CTX).unwrap());
}

#[test]
fn verify_rejects_bogus_z() {
    let vk = VerifyingKey::from_seed([6u8; 32]);
    let public = PublicInstance { message: 1 };
    let w = Witness { r: [0i32; 64] };
    let c = commit_mlwe(&vk, &public, &w).unwrap();
    let mut rng = thread_rng();
    let mut proof = prove_with_witness(&vk, &public, &w, &c, &CTX, &mut rng).unwrap();
    proof.z = RqPoly::zero();
    assert!(!verify_lattice(&vk, &public, &c, &proof, &CTX).unwrap());
}

#[test]
fn commitment_type_distinct_from_proof() {
    let vk = VerifyingKey::from_seed([7u8; 32]);
    let public = PublicInstance { message: 11 };
    let w = Witness { r: [0i32; 64] };
    let (c, p) = prove_arithmetic(&vk, &public, &w, &CTX).unwrap();
    let _: Commitment = c;
    let _: LatticeProof = p;
}
