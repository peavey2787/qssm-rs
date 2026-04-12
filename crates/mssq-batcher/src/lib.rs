//! MSSQ batcher: lex ordering, ML-DSA leader lottery, proof-gated SMT state.
#![forbid(unsafe_code)]

mod error;
mod leader;
mod sequencer;
mod state;

pub use error::BatcherError;
pub use leader::{
    elect_leader, leader_score_for_anchor, mssq_seed_from_anchor, verify_leader_attestation,
    verify_leader_attestation_ctx, LeaderAttestation,
};
pub use qssm_common::{rollup_context_from_l1, RollupState};
pub use qssm_utils::RollupContext;
pub use sequencer::sort_lexicographical;
pub use state::{apply_batch, ProofError, TxProofVerifier};
