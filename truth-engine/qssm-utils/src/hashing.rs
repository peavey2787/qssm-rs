//! Single source of truth for protocol domain strings (v1.0 hygiene).

/// **Bump when** `qssm-le` `fs_challenge_bytes` input order or `public_binding_fs_bytes` serialization
/// changes anything that gadget `TranscriptMap` / Engine A package JSON must mirror. Shared by `qssm-le`
/// and `qssm-gadget` via this crate.
pub const LE_FS_PUBLIC_BINDING_LAYOUT_VERSION: u32 = 1;

pub const DOMAIN_MS: &str = "QSSM-MS-v1.0";
pub const DOMAIN_LE: &str = "QSSM-LE-v1.0";
/// Parent-node hashing for binary Merkle trees.
pub const DOMAIN_MERKLE_PARENT: &str = "QSSM-MERKLE-PARENT-v1.0";
/// SDK layer: derive MS seed from entropy seed + binding context.
pub const DOMAIN_SDK_MS_SEED: &str = "QSSM-SDK-MS-SEED-v1";
/// SDK layer: derive LE witness coefficients from entropy seed + binding context.
pub const DOMAIN_SDK_LE_WITNESS: &str = "QSSM-SDK-LE-WITNESS-v1";
/// SDK layer: derive LE masking CSPRNG seed from entropy seed + binding context.
pub const DOMAIN_SDK_LE_MASK: &str = "QSSM-SDK-LE-MASK-v1";

#[inline]
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Domain-separated hash: `domain` as UTF-8 prefix, then each chunk in order.
pub fn hash_domain(domain: &str, chunks: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(domain.as_bytes());
    for c in chunks {
        h.update(c);
    }
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_tags_diverge_for_same_chunks() {
        let chunk: &[u8] = b"shared-payload";
        assert_ne!(
            hash_domain(DOMAIN_MS, &[chunk]),
            hash_domain(DOMAIN_LE, &[chunk])
        );
        assert_ne!(
            hash_domain(DOMAIN_SDK_MS_SEED, &[chunk]),
            hash_domain(DOMAIN_SDK_LE_WITNESS, &[chunk])
        );
        assert_ne!(
            hash_domain(DOMAIN_SDK_LE_MASK, &[chunk]),
            hash_domain(DOMAIN_MERKLE_PARENT, &[chunk])
        );
    }
}
