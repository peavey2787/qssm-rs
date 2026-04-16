use std::mem::MaybeUninit;

use qssm_le::{
    encode_rq_coeffs_le, verify_lattice, Commitment, CommitmentRandomness, LatticeProof, LeError,
    PublicInstance, RqPoly, SecretKey, VerifyingKey, Witness, GAMMA, N,
};
use qssm_utils::hashing::DOMAIN_MS;

const DOMAIN_LE_FS: &str = "QSSM-LE-FS-LYU-v1.0";
const CROSS_PROTOCOL_BINDING_LABEL: &[u8] = b"cross_protocol_digest_v1";
const DST_LE_COMMIT: [u8; 32] = *b"QSSM-LE-V1-COMMIT...............";
const DST_MS_VERIFY: [u8; 32] = *b"QSSM-MS-V1-VERIFY...............";

fn fs_seed_for_legacy_public(
    rollup_context_digest: &[u8; 32],
    vk: &VerifyingKey,
    public_message: u64,
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
    h.update(rollup_context_digest);
    h.update(vk.crs_seed.as_slice());
    h.update(&[0u8]);
    h.update(&public_message.to_le_bytes());
    h.update(&encode_rq_coeffs_le(&commitment.0));
    h.update(&encode_rq_coeffs_le(t));
    *h.finalize().as_bytes()
}

#[test]
fn verifier_rejects_out_of_bound_signature() {
    let vk = VerifyingKey::from_seed([0x77; 32]);
    let public_message = 0u64;
    let public = PublicInstance::legacy_message(public_message);
    let commitment = Commitment(RqPoly::embed_constant(public_message));
    let mut z_coeffs = [0u32; N];
    z_coeffs[0] = GAMMA + 1;
    let z = RqPoly(z_coeffs);
    let t = vk.matrix_a_poly().mul(&z).expect("az");
    let ctx = [0x44u8; 32];
    let challenge_seed = fs_seed_for_legacy_public(&ctx, &vk, public_message, &commitment, &t);
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
    let mut witness_slot = MaybeUninit::new(Witness { r: [7i32; N] });
    let w_ptr = witness_slot.as_mut_ptr();
    unsafe {
        std::ptr::drop_in_place(w_ptr);
        assert_eq!((*w_ptr).r[0], 0);
        assert_eq!((*w_ptr).r[N - 1], 0);
    }

    let mut sk_slot = MaybeUninit::new(SecretKey { r: [9i32; N] });
    let sk_ptr = sk_slot.as_mut_ptr();
    unsafe {
        std::ptr::drop_in_place(sk_ptr);
        assert_eq!((*sk_ptr).r[0], 0);
        assert_eq!((*sk_ptr).r[N - 1], 0);
    }

    let mut nonce_slot = MaybeUninit::new(CommitmentRandomness { y: [3i32; N] });
    let nonce_ptr = nonce_slot.as_mut_ptr();
    unsafe {
        std::ptr::drop_in_place(nonce_ptr);
        assert_eq!((*nonce_ptr).y[0], 0);
        assert_eq!((*nonce_ptr).y[N - 1], 0);
    }
}
