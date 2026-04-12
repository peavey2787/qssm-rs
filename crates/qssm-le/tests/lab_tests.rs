//! LaBRADOR Beta smoke: prove/verify roundtrip and algebraic rejection paths.

use qssm_le::{
    prove_arithmetic, verify_lattice, Commitment, LatticeProof, LeError, PublicInstance, VerifyingKey,
    Witness, BETA, MAX_MESSAGE,
};

#[test]
fn prove_verify_roundtrip() {
    let vk = VerifyingKey::from_seed([0xC0u8; 32]);
    let public = PublicInstance { message: 42 };
    let mut r = [0i32; 64];
    r[0] = 1;
    r[1] = -1;
    let witness = Witness { r };
    let (commitment, proof) = prove_arithmetic(&vk, &public, &witness).unwrap();
    assert!(verify_lattice(&vk, &public, &commitment, &proof).unwrap());
}

#[test]
fn message_out_of_range_rejected_at_commit() {
    let vk = VerifyingKey::from_seed([1u8; 32]);
    let public = PublicInstance {
        message: MAX_MESSAGE,
    };
    let w = Witness { r: [0i32; 64] };
    let err = qssm_le::commit_mlwe(&vk, &public, &w).unwrap_err();
    assert!(matches!(err, LeError::MessageOutOfRange));
}

#[test]
fn witness_shortness_violation_rejected() {
    let vk = VerifyingKey::from_seed([2u8; 32]);
    let public = PublicInstance { message: 0 };
    let mut r = [0i32; 64];
    r[0] = (BETA as i32) + 1;
    let w = Witness { r };
    let err = qssm_le::commit_mlwe(&vk, &public, &w).unwrap_err();
    assert!(matches!(err, LeError::RejectedSample));
}

#[test]
fn verify_rejects_wrong_commitment_for_same_proof_opening() {
    let vk = VerifyingKey::from_seed([3u8; 32]);
    let public = PublicInstance { message: 7 };
    let w = Witness { r: [0i32; 64] };
    let (c_real, proof) = prove_arithmetic(&vk, &public, &w).unwrap();
    let other = PublicInstance { message: 8 };
    let c_other = qssm_le::commit_mlwe(&vk, &other, &w).unwrap();
    assert!(!verify_lattice(&vk, &public, &c_other, &proof).unwrap());
    let _ = c_real;
}

#[test]
fn verify_rejects_tampered_transcript() {
    let vk = VerifyingKey::from_seed([4u8; 32]);
    let public = PublicInstance { message: 99 };
    let w = Witness { r: [0i32; 64] };
    let (c, mut proof) = prove_arithmetic(&vk, &public, &w).unwrap();
    proof.transcript[0] ^= 0x01;
    assert!(!verify_lattice(&vk, &public, &c, &proof).unwrap());
}

#[test]
fn verify_rejects_tampered_opening_coeffs() {
    let vk = VerifyingKey::from_seed([5u8; 32]);
    let public = PublicInstance { message: 3 };
    let w = Witness { r: [0i32; 64] };
    let (c, mut proof) = prove_arithmetic(&vk, &public, &w).unwrap();
    proof.r_opening[0] = 1;
    assert!(!verify_lattice(&vk, &public, &c, &proof).unwrap());
}

#[test]
fn verify_rejects_commitment_with_garbage_proof_structure() {
    let vk = VerifyingKey::from_seed([6u8; 32]);
    let public = PublicInstance { message: 1 };
    let w = Witness { r: [0i32; 64] };
    let (c, _) = prove_arithmetic(&vk, &public, &w).unwrap();
    let bad = LatticeProof {
        r_opening: [1i32; 64],
        transcript: [0u8; 32],
    };
    assert!(!verify_lattice(&vk, &public, &c, &bad).unwrap());
}

#[test]
fn commitment_type_is_distinct_from_proof_bundle() {
    let vk = VerifyingKey::from_seed([7u8; 32]);
    let public = PublicInstance { message: 11 };
    let w = Witness { r: [0i32; 64] };
    let (c, p) = prove_arithmetic(&vk, &public, &w).unwrap();
    let _: Commitment = c;
    let _: LatticeProof = p;
}
