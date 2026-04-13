//! Cryptographic utilities: versioned domain strings, BLAKE3, and Merkle trees.
#![forbid(unsafe_code)]

pub mod hashing;
pub mod leader_msg;
pub mod merkle;
pub mod mssq_seed;
pub mod rollup_context;
pub mod smt;

pub use hashing::{
    blake3_hash, duel_leaderboard_key, hash_domain, DOMAIN_LE, DOMAIN_LE_REF_STUB,
    DOMAIN_MERKLE_PARENT, DOMAIN_MOCK_KASPA_BLOCK, DOMAIN_MOCK_KASPA_ENTROPY, DOMAIN_MOCK_QRNG,
    DOMAIN_MS, DOMAIN_MSSQ_DUEL_LEADERBOARD, DOMAIN_MSSQ_LEADER_SCORE, DOMAIN_MSSQ_ROLLUP_CONTEXT,
    DOMAIN_MSSQ_SEED, DOMAIN_MSSQ_STATE,
};
pub use leader_msg::{leader_attestation_signing_bytes, leader_id_from_ml_dsa_public_key};
pub use merkle::{merkle_parent, MerkleError, PositionAwareTree};
pub use mssq_seed::{leader_score_digest, leader_score_u64, mssq_seed_k};
pub use rollup_context::{rollup_context_digest, RollupContext};
pub use smt::StateMirrorTree;
