//! Fiat-Shamir binding transcript for the Ghost-Mirror protocol.

use qssm_utils::hashing::{hash_domain, DOMAIN_MS};

#[allow(clippy::too_many_arguments)]
pub(crate) fn fs_challenge(
    root: &[u8; 32],
    n: u8,
    k: u8,
    entropy: &[u8; 32],
    value: u64,
    target: u64,
    context: &[u8],
    rollup_context_digest: &[u8; 32],
) -> [u8; 32] {
    hash_domain(
        DOMAIN_MS,
        &[
            b"fs_v2",
            root.as_slice(),
            &[n],
            &[k],
            entropy.as_slice(),
            &value.to_le_bytes(),
            &target.to_le_bytes(),
            context,
            rollup_context_digest.as_slice(),
        ],
    )
}
