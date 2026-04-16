//! Single source of truth for protocol domain strings (v1.0 hygiene).

/// **Bump when** `qssm-le` `fs_challenge_bytes` input order or `public_binding_fs_bytes` serialization
/// changes anything that gadget `TranscriptMap` / Engine A package JSON must mirror. Shared by `qssm-le`
/// and `qssm-gadget` via this crate.
pub const LE_FS_PUBLIC_BINDING_LAYOUT_VERSION: u32 = 1;

pub const DOMAIN_MS: &str = "QSSM-MS-v1.0";
pub const DOMAIN_LE: &str = "QSSM-LE-v1.0";
pub const DOMAIN_LE_REF_STUB: &str = "QSSM-LE-REF-STUB-v1.0";
pub const DOMAIN_MSSQ_STATE: &str = "MSSQ-STATE-v1.0";
pub const DOMAIN_MOCK_KASPA_ENTROPY: &str = "MOCK-KASPA-ENTROPY-v1.0";
/// MSSQ election seed: `Seed_k = BLAKE3(domain ‖ parent_block_hash ‖ latest_qrng)`.
pub const DOMAIN_MSSQ_SEED: &str = "MSSQ-SEED-v2.0";
/// PQ-friendly leader lottery: `y = BLAKE3(domain ‖ Seed_k ‖ candidate_id)`.
pub const DOMAIN_MSSQ_LEADER_SCORE: &str = "MSSQ-LEADER-SCORE-v2.0";
/// Mock Kaspa parent block hash (high-velocity ~100 ms narrative).
pub const DOMAIN_MOCK_KASPA_BLOCK: &str = "MOCK-KASPA-BLOCK-v2.0";
/// Mock QRNG feed (60 s epoch narrative).
pub const DOMAIN_MOCK_QRNG: &str = "MOCK-QRNG-v2.0";
/// Parent-node hashing for binary Merkle trees (shared by engines / batcher).
pub const DOMAIN_MERKLE_PARENT: &str = "QSSM-MERKLE-PARENT-v1.0";
/// Binds LE/MS/leader to finalized Kaspa + QRNG (rollup context).
pub const DOMAIN_MSSQ_ROLLUP_CONTEXT: &str = "MSSQ-ROLLUP-CONTEXT-v1.0";
/// SMT key for Millionaire’s Duel leaderboard leaf (`hash_domain(DOMAIN ‖ "MSSQ_DUEL_LEADERBOARD_V1")`).
pub const DOMAIN_MSSQ_DUEL_LEADERBOARD: &str = "MSSQ-DUEL-LEADERBOARD-V1.0";

/// Cryptographic [`[u8; 32]`](https://doc.rust-lang.org/std/primitive.array.html) SMT slot for duel prestige state.
#[must_use]
pub fn duel_leaderboard_key() -> [u8; 32] {
    hash_domain(DOMAIN_MSSQ_DUEL_LEADERBOARD, &[b"MSSQ_DUEL_LEADERBOARD_V1"])
}

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
            hash_domain(DOMAIN_MSSQ_SEED, &[chunk]),
            hash_domain(DOMAIN_MSSQ_LEADER_SCORE, &[chunk])
        );
        assert_ne!(
            hash_domain(DOMAIN_MSSQ_STATE, &[chunk]),
            hash_domain(DOMAIN_MERKLE_PARENT, &[chunk])
        );
    }
}
