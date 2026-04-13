//! Workspace integration crate: re-exports for readers and integration tests.
#![forbid(unsafe_code)]

pub mod millionaires_duel;
pub mod verify;

pub use mssq_batcher;
pub use qssm_common;
pub use qssm_kaspa;
pub use qssm_le;
pub use qssm_ms;
pub use qssm_utils;

pub use millionaires_duel::{
    decode_millionaires_proof, duel_holds, encode_millionaires_proof, format_leaf_data_hex,
    format_slot_hex, leaderboard_key, parse_leaderboard_leaf, prestige_payload,
    public_message_for_duel, valid_duel_public_message, MillionairesDuelError,
    MillionairesDuelVerifier, MillionairesProofBundle, ProofWireError, DUEL_SHIFT,
    MAX_DEMO_BALANCE, WEALTHIEST_KNIGHT_TAG,
};
