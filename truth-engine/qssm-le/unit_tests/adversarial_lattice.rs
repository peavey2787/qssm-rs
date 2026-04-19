use std::mem::MaybeUninit;

use qssm_le::{
    encode_rq_coeffs_le, prove_arithmetic, verify_lattice, Commitment, CommitmentRandomness,
    LatticeProof, LeError, PublicBinding, PublicInstance, RqPoly, ScrubbedPoly, VerifyingKey,
    Witness, GAMMA, N, PUBLIC_DIGEST_COEFFS, Q,
};
use qssm_utils::hashing::DOMAIN_MS;

const DOMAIN_LE_FS: &str = "QSSM-LE-FS-LYU-v1.0";
const CROSS_PROTOCOL_BINDING_LABEL: &[u8] = b"cross_protocol_digest_v1";
const DST_LE_COMMIT: [u8; 32] = *b"QSSM-LE-V1-COMMIT...............";
const DST_MS_VERIFY: [u8; 32] = *b"QSSM-MS-V1-VERIFY...............";

fn fs_seed_for_public(
    binding_context: &[u8; 32],
    vk: &VerifyingKey,
    public: &PublicInstance,
    commitment: &Commitment,
    t: &RqPoly,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN_LE_FS.as_bytes());
    h.update(&DST_LE_COMMIT);
    h.update(&DST_MS_VERIFY);
    h.update(CROSS_PROTOCOL_BINDING_LABEL);
    h.update(DOMAIN_MS.as_bytes());
    h.update(b"fs_v2");
    h.update(binding_context);
    h.update(vk.crs_seed.as_slice());
    match public.binding() {
        PublicBinding::DigestCoeffVector { coeffs } => {
            h.update(&[0x01u8]);
            for &c in coeffs {
                h.update(&c.to_le_bytes());
            }
        }
        _ => panic!("unexpected PublicBinding variant"),
    }
    h.update(&encode_rq_coeffs_le(&commitment.0));
    h.update(&encode_rq_coeffs_le(t));
    *h.finalize().as_bytes()
}

#[test]
fn verifier_rejects_out_of_bound_signature() {
    let vk = VerifyingKey::from_seed([0x77; 32]);
    let public = PublicInstance::digest_coeffs([0u32; PUBLIC_DIGEST_COEFFS]).unwrap();
    let commitment = Commitment(RqPoly::zero());
    let mut z_coeffs = [0u32; N];
    z_coeffs[0] = GAMMA + 1;
    let z = RqPoly(z_coeffs);
    let t = vk.matrix_a_poly().mul(&z).expect("az");
    let ctx = [0x44u8; 32];
    let challenge_seed = fs_seed_for_public(&ctx, &vk, &public, &commitment, &t);
    let forged = LatticeProof {
        t,
        z,
        challenge_seed,
    };
    let verdict = verify_lattice(&vk, &public, &commitment, &forged, &ctx);
    assert!(matches!(verdict, Err(LeError::InvalidNorm)));
}

#[test]
fn test_secret_zeroization() {
    let mut witness_slot = MaybeUninit::new(Witness::new([7i32; N]));
    let w_ptr = witness_slot.as_mut_ptr();
    unsafe {
        std::ptr::drop_in_place(w_ptr);
        let raw = std::ptr::read(w_ptr);
        assert_eq!(raw.coeffs()[0], 0);
        assert_eq!(raw.coeffs()[N - 1], 0);
        std::mem::forget(raw);
    }

    let mut nonce_slot = MaybeUninit::new(CommitmentRandomness::new([3i32; N]));
    let nonce_ptr = nonce_slot.as_mut_ptr();
    unsafe {
        std::ptr::drop_in_place(nonce_ptr);
        let raw = std::ptr::read(nonce_ptr);
        assert_eq!(raw.coeffs()[0], 0);
        assert_eq!(raw.coeffs()[N - 1], 0);
        std::mem::forget(raw);
    }
}

// ── New adversarial tests (bank-grade hardening 2026-04-17) ──────────────────

#[test]
fn test_scrubbed_poly_zeroization() {
    let poly = RqPoly([42u32; N]);
    let mut slot = MaybeUninit::new(ScrubbedPoly::from_public(&poly));
    let ptr = slot.as_mut_ptr();
    unsafe {
        // Verify it was non-zero before drop.
        let pre = std::ptr::read(ptr);
        assert_eq!(pre.as_public().0[0], 42);
        std::mem::forget(pre);
        // Drop and verify zeroization.
        std::ptr::drop_in_place(ptr);
        // Read raw bytes — ZeroizeOnDrop should have zeroed the coeffs field.
        let raw = std::ptr::read(ptr);
        assert_eq!(
            raw.as_public().0[0],
            0,
            "ScrubbedPoly must be zeroed after drop"
        );
        assert_eq!(
            raw.as_public().0[N - 1],
            0,
            "ScrubbedPoly must be zeroed after drop"
        );
        std::mem::forget(raw);
    }
}

#[test]
fn verifier_rejects_non_canonical_polynomial() {
    let vk = VerifyingKey::from_seed([0x88; 32]);
    let public = PublicInstance::digest_coeffs([0u32; PUBLIC_DIGEST_COEFFS]).unwrap();
    let commitment = Commitment(RqPoly::zero());
    // z[0] = Q is NOT in [0, Q) — non-canonical.
    let mut z_coeffs = [0u32; N];
    z_coeffs[0] = Q;
    let z = RqPoly(z_coeffs);
    let t = RqPoly::zero();
    let forged = LatticeProof {
        t,
        z,
        challenge_seed: [0u8; 32],
    };
    let verdict = verify_lattice(&vk, &public, &commitment, &forged, &[0u8; 32]);
    assert!(
        matches!(verdict, Err(LeError::OversizedInput)),
        "Non-canonical z must be rejected"
    );
}

#[test]
fn verifier_rejects_non_canonical_commitment() {
    let vk = VerifyingKey::from_seed([0x89; 32]);
    let public = PublicInstance::digest_coeffs([0u32; PUBLIC_DIGEST_COEFFS]).unwrap();
    let commitment = Commitment(RqPoly([u32::MAX; N]));
    let forged = LatticeProof {
        t: RqPoly::zero(),
        z: RqPoly::zero(),
        challenge_seed: [0u8; 32],
    };
    let verdict = verify_lattice(&vk, &public, &commitment, &forged, &[0u8; 32]);
    assert!(
        matches!(verdict, Err(LeError::OversizedInput)),
        "Non-canonical commitment must be rejected"
    );
}

#[test]
fn verifier_rejects_large_negative_centered_z() {
    let vk = VerifyingKey::from_seed([0x99; 32]);
    let public = PublicInstance::digest_coeffs([0u32; PUBLIC_DIGEST_COEFFS]).unwrap();
    let commitment = Commitment(RqPoly::zero());
    // Q - GAMMA - 1 when centered mod Q gives -(GAMMA + 1), so |z|∞ = GAMMA + 1.
    let mut z_coeffs = [0u32; N];
    z_coeffs[0] = Q - GAMMA - 1;
    let z = RqPoly(z_coeffs);
    let t = vk.matrix_a_poly().mul(&z).expect("az");
    let ctx = [0x55u8; 32];
    let challenge_seed = fs_seed_for_public(&ctx, &vk, &public, &commitment, &t);
    let forged = LatticeProof {
        t,
        z,
        challenge_seed,
    };
    let verdict = verify_lattice(&vk, &public, &commitment, &forged, &ctx);
    assert!(
        matches!(verdict, Err(LeError::InvalidNorm)),
        "Large negative centered z must be rejected"
    );
}

#[test]
fn seed_reuse_produces_identical_proof() {
    let vk = VerifyingKey::from_seed([0xAA; 32]);
    let public = PublicInstance::from_u64_nibbles(42);
    let w = Witness::new([0i32; N]);
    let ctx = [0xBB; 32];
    let seed = [0xCC; 32];
    let (c1, p1) = prove_arithmetic(&vk, &public, &w, &ctx, seed).unwrap();
    let (c2, p2) = prove_arithmetic(&vk, &public, &w, &ctx, seed).unwrap();
    assert_eq!(c1.0, c2.0, "Deterministic: same seed = same commitment");
    assert_eq!(p1.t, p2.t, "Deterministic: same seed = same t");
    assert_eq!(p1.z, p2.z, "Deterministic: same seed = same z");
    assert_eq!(
        p1.challenge_seed, p2.challenge_seed,
        "Deterministic: same seed = same challenge"
    );
}

#[test]
fn scrubbed_poly_debug_is_redacted() {
    let poly = RqPoly([123u32; N]);
    let s = ScrubbedPoly::from_public(&poly);
    let debug_str = format!("{:?}", s);
    assert!(
        debug_str.contains("[REDACTED]"),
        "ScrubbedPoly Debug must not leak coefficients"
    );
    assert!(
        !debug_str.contains("123"),
        "ScrubbedPoly Debug must not contain actual coefficient values"
    );
}

#[test]
fn witness_debug_is_redacted() {
    let w = Witness::new([7i32; N]);
    let debug_str = format!("{:?}", w);
    assert!(
        debug_str.contains("[REDACTED]"),
        "Witness Debug must not leak coefficients"
    );
    assert!(
        !debug_str.contains("7, 7"),
        "Witness Debug must not contain coefficient values"
    );
}

#[test]
fn commitment_randomness_debug_is_redacted() {
    let cr = CommitmentRandomness::new([3i32; N]);
    let debug_str = format!("{:?}", cr);
    assert!(
        debug_str.contains("[REDACTED]"),
        "CommitmentRandomness Debug must not leak coefficients"
    );
    assert!(
        !debug_str.contains("3, 3"),
        "CommitmentRandomness Debug must not contain coefficient values"
    );
}
