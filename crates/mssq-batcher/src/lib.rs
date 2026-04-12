//! MSSQ batcher facade: hash-lex ordering, PQ-friendly leader lottery, deterministic state root.
#![forbid(unsafe_code)]

mod error;
mod leader;
mod sequencer;
mod state;

pub use error::BatcherError;
pub use leader::{
    elect_leader, leader_score_for_anchor, mssq_seed_from_anchor, verify_leader_attestation,
    LeaderAttestation,
};
pub use sequencer::sort_lexicographical;
pub use state::apply_batch;
