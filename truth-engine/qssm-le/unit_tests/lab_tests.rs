//! Lyubashevsky FS + rejection: prove/verify and failure modes.

use qssm_le::{
    commit_mlwe, prove_arithmetic, verify_lattice, Commitment, LatticeProof,
    LeError, PublicBinding, PublicInstance, RqPoly, VerifyingKey, Witness, BETA, N,
    PUBLIC_DIGEST_COEFFS, PUBLIC_DIGEST_COEFF_MAX,
};

const CTX: [u8; 32] = [0xA1; 32];
const TEST_RNG_SEED: [u8; 32] = [0xBB; 32];

#[test]
fn prove_verify_roundtrip() {
    let vk = VerifyingKey::from_seed([0xC0u8; 32]);
    let public = PublicInstance::from_u64_nibbles(42);
    let mut r = [0i32; N];
    r[0] = 1;
    r[1] = -1;
    let witness = Witness::new(r);
    let (commitment, proof) = prove_arithmetic(&vk, &public, &witness, &CTX, TEST_RNG_SEED).unwrap();
    assert!(verify_lattice(&vk, &public, &commitment, &proof, &CTX).unwrap());
}

#[test]
fn digest_coeff_out_of_range_rejected_at_commit() {
    let mut bad_coeffs = [0u32; PUBLIC_DIGEST_COEFFS];
    bad_coeffs[0] = PUBLIC_DIGEST_COEFF_MAX + 1;
    let public = PublicInstance::digest_coeffs(bad_coeffs);
    assert!(public.is_err());
    assert!(matches!(public, Err(LeError::OversizedInput)));
}

#[test]
fn witness_shortness_violation_rejected() {
    let vk = VerifyingKey::from_seed([2u8; 32]);
    let public = PublicInstance::digest_coeffs([0u32; PUBLIC_DIGEST_COEFFS]).unwrap();
    let mut r = [0i32; N];
    r[0] = (BETA as i32) + 1;
    let w = Witness::new(r);
    let err = commit_mlwe(&vk, &public, &w).unwrap_err();
    assert!(matches!(err, LeError::RejectedSample));
}

#[test]
fn verify_rejects_wrong_commitment_for_same_proof() {
    let vk = VerifyingKey::from_seed([3u8; 32]);
    let public = PublicInstance::from_u64_nibbles(7);
    let w = Witness::new([0i32; N]);
    let (c_real, proof) = prove_arithmetic(&vk, &public, &w, &CTX, TEST_RNG_SEED).unwrap();
    let other = PublicInstance::from_u64_nibbles(8);
    let c_other = commit_mlwe(&vk, &other, &w).unwrap();
    assert!(matches!(
        verify_lattice(&vk, &public, &c_other, &proof, &CTX),
        Err(LeError::DomainMismatch)
    ));
    let _ = c_real;
}

#[test]
fn verify_rejects_wrong_context() {
    let vk = VerifyingKey::from_seed([4u8; 32]);
    let public = PublicInstance::from_u64_nibbles(99);
    let w = Witness::new([0i32; N]);
    let (c, proof) = prove_arithmetic(&vk, &public, &w, &CTX, TEST_RNG_SEED).unwrap();
    let bad = [0xFFu8; 32];
    assert!(matches!(
        verify_lattice(&vk, &public, &c, &proof, &bad),
        Err(LeError::DomainMismatch)
    ));
}

#[test]
fn verify_rejects_tampered_challenge() {
    let vk = VerifyingKey::from_seed([5u8; 32]);
    let public = PublicInstance::from_u64_nibbles(3);
    let w = Witness::new([0i32; N]);
    let (c, mut proof) = prove_arithmetic(&vk, &public, &w, &CTX, TEST_RNG_SEED).unwrap();
    proof.challenge_seed[0] ^= 0x01;
    assert!(matches!(
        verify_lattice(&vk, &public, &c, &proof, &CTX),
        Err(LeError::DomainMismatch)
    ));
}

#[test]
fn verify_rejects_bogus_z() {
    let vk = VerifyingKey::from_seed([6u8; 32]);
    let public = PublicInstance::from_u64_nibbles(1);
    let w = Witness::new([0i32; N]);
    let (c, mut proof) = prove_arithmetic(&vk, &public, &w, &CTX, TEST_RNG_SEED).unwrap();
    proof.z = RqPoly::zero();
    assert!(matches!(
        verify_lattice(&vk, &public, &c, &proof, &CTX),
        Err(LeError::DomainMismatch)
    ));
}

#[test]
fn commitment_type_distinct_from_proof() {
    let vk = VerifyingKey::from_seed([7u8; 32]);
    let public = PublicInstance::from_u64_nibbles(11);
    let w = Witness::new([0i32; N]);
    let (c, p) = prove_arithmetic(&vk, &public, &w, &CTX, TEST_RNG_SEED).unwrap();
    let _: Commitment = c;
    let _: LatticeProof = p;
}

// ── New tests (bank-grade hardening 2026-04-17) ──────────────────────────────

#[test]
fn prove_verify_roundtrip_digest_coeffs() {
    let vk = VerifyingKey::from_seed([0xD0u8; 32]);
    let coeffs = [0x0Au32; PUBLIC_DIGEST_COEFFS];
    let public = PublicInstance::digest_coeffs(coeffs).unwrap();
    let w = Witness::new([0i32; N]);
    let (commitment, proof) = prove_arithmetic(&vk, &public, &w, &CTX, TEST_RNG_SEED).unwrap();
    assert!(verify_lattice(&vk, &public, &commitment, &proof, &CTX).unwrap());
}

#[test]
fn crs_expansion_golden_value() {
    let vk = VerifyingKey::from_seed([0x42u8; 32]);
    let a = vk.matrix_a_poly();
    // Pin first 4 coefficients to detect silent BLAKE3 or domain-string changes.
    let pinned: [u32; 4] = [a.0[0], a.0[1], a.0[2], a.0[3]];
    // Re-expand and verify determinism.
    let a2 = vk.matrix_a_poly();
    assert_eq!(a, a2, "CRS expansion must be deterministic");
    // Golden values: if these change, the DOMAIN_LE, hash_domain, or BLAKE3 changed.
    // Regenerate with: VerifyingKey::from_seed([0x42u8; 32]).matrix_a_poly().0[0..4]
    assert_eq!(
        pinned,
        [7_960_407, 1_320_365, 6_344_295, 2_508_853],
        "CRS golden values drifted — DOMAIN_LE or hash construction changed"
    );
    // Also verify all coefficients are canonical.
    for &c in &a.0 {
        assert!(c < qssm_le::Q, "CRS coefficient must be in [0, Q)");
    }
}

#[test]
fn commitment_is_deterministic() {
    let vk = VerifyingKey::from_seed([0xE1u8; 32]);
    let public = PublicInstance::from_u64_nibbles(777);
    let w = Witness::new([0i32; N]);
    let c1 = commit_mlwe(&vk, &public, &w).unwrap();
    let c2 = commit_mlwe(&vk, &public, &w).unwrap();
    assert_eq!(c1.0, c2.0, "Same inputs must produce same commitment");
}

#[test]
fn proof_is_deterministic_with_same_seed() {
    let vk = VerifyingKey::from_seed([0xE2u8; 32]);
    let public = PublicInstance::from_u64_nibbles(888);
    let w = Witness::new([0i32; N]);
    let (c1, p1) = prove_arithmetic(&vk, &public, &w, &CTX, TEST_RNG_SEED).unwrap();
    let (c2, p2) = prove_arithmetic(&vk, &public, &w, &CTX, TEST_RNG_SEED).unwrap();
    assert_eq!(c1.0, c2.0, "Commitment must be deterministic");
    assert_eq!(p1.t, p2.t, "Masking commitment must be deterministic");
    assert_eq!(p1.z, p2.z, "Response must be deterministic");
    assert_eq!(
        p1.challenge_seed, p2.challenge_seed,
        "Challenge seed must be deterministic"
    );
}

#[test]
fn from_u64_nibbles_golden_encoding() {
    let public = PublicInstance::from_u64_nibbles(0xFEDC_BA98_7654_3210);
    let coeffs = match public.binding() {
        PublicBinding::DigestCoeffVector { coeffs } => coeffs,
        _ => panic!("unexpected PublicBinding variant"),
    };
    let expected = [
        0x0u32, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
        0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
    ];
    assert_eq!(&coeffs[..16], &expected);
    assert!(coeffs[16..].iter().all(|&coeff| coeff == 0));
}
