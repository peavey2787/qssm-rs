//! Cross-engine domain separation: MS v2 value-commitment / statement material vs LE CRS row.

use qssm_le::{commit_mlwe, PublicInstance, VerifyingKey, Witness};
use qssm_ms::commit_value_v2;
use qssm_utils::hashing::{hash_domain, DOMAIN_LE, DOMAIN_MS};

#[test]
fn ms_salt_expansion_differs_from_le_crs_row() {
    let seed = [9u8; 32];
    let ms_salt = hash_domain(
        DOMAIN_MS,
        &[b"salt", seed.as_slice(), &0u32.to_le_bytes(), &[0u8]],
    );
    let le_row = hash_domain(DOMAIN_LE, &[b"A_row", seed.as_slice(), &0u32.to_le_bytes()]);
    assert_ne!(ms_salt, le_row);
}

#[test]
fn ms_v2_commitment_digest_differs_from_mlwe_commitment() {
    let seed = [3u8; 32];
    let ledger = [4u8; 32];
    let (commitment, _) = commit_value_v2(100, seed, ledger).unwrap();
    let ms_digest = commitment.digest();
    let vk = VerifyingKey::from_seed(seed);
    let w = Witness::new([0i32; qssm_le::N]);
    let public = PublicInstance::from_u64_nibbles(12345);
    let c = commit_mlwe(&vk, &public, &w).unwrap();
    let mut le_prefix = [0u8; 32];
    for i in 0..8 {
        le_prefix[i * 4..(i + 1) * 4].copy_from_slice(&c.0 .0[i].to_le_bytes());
    }
    assert_ne!(ms_digest, le_prefix);
}
