//! MSSQ slot seed and PQ-friendly leader scores (BLAKE3 only).
#![forbid(unsafe_code)]

use crate::hashing::{hash_domain, DOMAIN_MSSQ_LEADER_SCORE, DOMAIN_MSSQ_SEED};

/// $$\text{Seed}_k = \text{BLAKE3}(\text{DOMAIN\_MSSQ\_SEED} \,\|\, \text{Kaspa\_Block\_Hash}_{k-1} \,\|\, \text{Latest\_QRNG\_Value})$$
/// (domain string is hashed first inside `hash_domain`, then the two 32-byte limbs.)
#[must_use]
pub fn mssq_seed_k(
    kaspa_block_hash_k_minus_1: &[u8; 32],
    latest_qrng_value: &[u8; 32],
) -> [u8; 32] {
    hash_domain(
        DOMAIN_MSSQ_SEED,
        &[
            kaspa_block_hash_k_minus_1.as_slice(),
            latest_qrng_value.as_slice(),
        ],
    )
}

/// Deterministic leader digest `y` (lexicographic compare / min-wins).
#[must_use]
pub fn leader_score_digest(seed_k: &[u8; 32], candidate_public_id: &[u8; 32]) -> [u8; 32] {
    hash_domain(
        DOMAIN_MSSQ_LEADER_SCORE,
        &[seed_k.as_slice(), candidate_public_id.as_slice()],
    )
}

/// Tie-break / lottery scalar: first 8 bytes of `leader_score_digest` (LE).
#[must_use]
pub fn leader_score_u64(digest: &[u8; 32]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_changes_when_either_limb_changes() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let s0 = mssq_seed_k(&a, &b);
        let s1 = mssq_seed_k(&b, &b);
        let s2 = mssq_seed_k(&a, &a);
        assert_ne!(s0, s1);
        assert_ne!(s0, s2);
    }

    #[test]
    fn deterministic_recomputation() {
        let h = [3u8; 32];
        let q = [4u8; 32];
        assert_eq!(mssq_seed_k(&h, &q), mssq_seed_k(&h, &q));
    }

    #[test]
    fn qrng_circuit_breaker_changes_seed() {
        let bh = [5u8; 32];
        let q0 = [6u8; 32];
        let q1 = [7u8; 32];
        assert_ne!(mssq_seed_k(&bh, &q0), mssq_seed_k(&bh, &q1));
    }
}
