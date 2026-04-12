//! Cryptographic utilities: versioned domain strings, BLAKE3, and Merkle trees.
#![forbid(unsafe_code)]

pub mod hashing;
pub mod merkle;
pub mod mssq_seed;

pub use hashing::{
    blake3_hash, hash_domain, DOMAIN_LE, DOMAIN_LE_REF_STUB, DOMAIN_MERKLE_PARENT,
    DOMAIN_MOCK_KASPA_BLOCK, DOMAIN_MOCK_KASPA_ENTROPY, DOMAIN_MOCK_QRNG, DOMAIN_MS,
    DOMAIN_MSSQ_LEADER_SCORE, DOMAIN_MSSQ_SEED, DOMAIN_MSSQ_STATE,
};
pub use mssq_seed::{leader_score_digest, leader_score_u64, mssq_seed_k};
pub use merkle::{merkle_parent, MerkleError, PositionAwareTree};
