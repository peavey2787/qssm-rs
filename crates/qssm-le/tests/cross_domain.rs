//! Cross-engine domain separation: MS vs LE digests must not replay across crates.

use qssm_le::{commit_mlwe, PublicInstance, VerifyingKey, Witness};
use qssm_ms::commit;
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
fn ms_commitment_root_differs_from_mlwe_commitment() {
    let seed = [3u8; 32];
    let ledger = [4u8; 32];
    let (root_ms, _) = commit(12345u64, seed, ledger).unwrap();
    let vk = VerifyingKey::from_seed(seed);
    let w = Witness {
        r: [0i32; qssm_le::N],
    };
    let public = PublicInstance::legacy_message(12345);
    let c = commit_mlwe(&vk, &public, &w).unwrap();
    let mut le_prefix = [0u8; 32];
    for i in 0..8 {
        le_prefix[i * 4..(i + 1) * 4].copy_from_slice(&c.0 .0[i].to_le_bytes());
    }
    assert_ne!(root_ms.0, le_prefix);
}
