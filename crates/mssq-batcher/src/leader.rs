//! PQ-friendly MSSQ leader lottery: `Seed_k` from anchor limbs + BLAKE3 min-score selection.
#![forbid(unsafe_code)]

use qssm_common::SovereignAnchor;
use qssm_utils::{leader_score_digest, mssq_seed_k};

use crate::BatcherError;

/// Declared leader claim bound to slot, parent block hash, and QRNG epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaderAttestation {
    pub slot: u64,
    pub parent_block_hash: [u8; 32],
    pub qrng_value: [u8; 32],
    pub qrng_epoch: u64,
    pub claimed_leader_id: [u8; 32],
}

/// Recompute `Seed_k` from an anchor (ground truth).
#[must_use]
pub fn mssq_seed_from_anchor<A: SovereignAnchor + ?Sized>(anchor: &A) -> [u8; 32] {
    let p = anchor.parent_block_hash_prev();
    let q = anchor.latest_qrng_value();
    mssq_seed_k(&p, &q)
}

/// Candidate with lexicographically minimal `leader_score_digest(seed, id)` wins.
pub fn elect_leader(seed: &[u8; 32], candidates: &[[u8; 32]]) -> Result<[u8; 32], BatcherError> {
    let first = candidates.first().ok_or(BatcherError::NoCandidates)?;
    let mut best_id = *first;
    let mut best_d = leader_score_digest(seed, first);
    for id in candidates.iter().skip(1) {
        let d = leader_score_digest(seed, id);
        if d < best_d {
            best_d = d;
            best_id = *id;
        }
    }
    Ok(best_id)
}

/// Verify attestation against anchor truth and winner rule.
pub fn verify_leader_attestation<A: SovereignAnchor + ?Sized>(
    anchor: &A,
    att: &LeaderAttestation,
    candidates: &[[u8; 32]],
) -> Result<(), BatcherError> {
    if att.slot != anchor.get_current_slot() {
        return Err(BatcherError::WrongSlot);
    }
    if att.parent_block_hash != anchor.parent_block_hash_prev() {
        return Err(BatcherError::MismatchedParentBlockHash);
    }
    if att.qrng_value != anchor.latest_qrng_value() || att.qrng_epoch != anchor.qrng_epoch() {
        return Err(BatcherError::MismatchedQrng);
    }
    if !candidates.contains(&att.claimed_leader_id) {
        return Err(BatcherError::LeaderNotInCandidateSet);
    }
    let seed = mssq_seed_from_anchor(anchor);
    let winner = elect_leader(&seed, candidates)?;
    if winner != att.claimed_leader_id {
        return Err(BatcherError::NotWinningLeader);
    }
    Ok(())
}

/// Score bytes for a candidate under the current anchor (for observability / tests).
pub fn leader_score_for_anchor<A: SovereignAnchor + ?Sized>(
    anchor: &A,
    candidate_id: &[u8; 32],
) -> [u8; 32] {
    let seed = mssq_seed_from_anchor(anchor);
    leader_score_digest(&seed, candidate_id)
}
