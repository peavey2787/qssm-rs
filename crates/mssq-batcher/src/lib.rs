//! MSSQ batcher: lex ordering, ML-DSA leader lottery, proof-gated SMT state.
#![forbid(unsafe_code)]

mod error;
mod causal_dag;
mod leader;
mod merit;
mod sequencer;
mod state;

pub use error::BatcherError;
pub use leader::{
    elect_leader, leader_score_for_anchor, mssq_seed_from_anchor, mssq_seed_from_anchor_and_dag_tips, verify_leader_attestation,
    verify_leader_attestation_ctx, LeaderAttestation,
};
pub use qssm_common::{rollup_context_from_l1, RollupState};
pub use qssm_utils::RollupContext;
pub use sequencer::sort_lexicographical;
pub use state::{apply_batch, prune_state, ProofError, TxProofVerifier};
pub use causal_dag::{lattice_anchor_seed_with_tips, CausalDag, EntropyPulse};
pub use merit::{merit_maturation, MeritState, MeritTier};
