//! MSSQ batcher: lex ordering, ML-DSA leader lottery, proof-gated SMT state.
#![forbid(unsafe_code)]

mod dag;
mod error;
mod roles;
mod state;

pub use dag::causal::{lattice_anchor_seed_with_tips, CausalDag, EntropyPulse};
pub use dag::merit::{merit_maturation, MeritState, MeritTier};
pub use error::BatcherError;
pub use qssm_traits::{rollup_context_from_l1, RollupState};
pub use qssm_utils::RollupContext;
pub use roles::leader::{
    elect_leader, leader_score_for_anchor, mssq_seed_from_anchor,
    mssq_seed_from_anchor_and_dag_tips, verify_leader_attestation, verify_leader_attestation_ctx,
    LeaderAttestation,
};
pub use roles::sequencer::sort_lexicographical;
pub use state::view::{apply_batch, prune_state, ProofError, TxProofVerifier};
