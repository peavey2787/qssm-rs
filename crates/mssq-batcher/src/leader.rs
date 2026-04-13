// Copyright (c) 2026 Peavey Koding. All rights reserved.
// Licensed under the Business Source License 1.1 (BSL-1.1).
// See the LICENSE file in the repository root for full license text.

//! PQ-friendly MSSQ leader lottery + ML-DSA–bound attestations.
#![forbid(unsafe_code)]

use ml_dsa::signature::Verifier;
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use qssm_common::rollup_context_from_l1;
use qssm_common::L1Anchor;
use qssm_utils::{
    leader_attestation_signing_bytes, leader_id_from_ml_dsa_public_key, leader_score_digest,
    mssq_seed_k, RollupContext,
};

use crate::BatcherError;

/// Declared leader claim bound to slot, finalized parent hash, QRNG, optional SMT pre-root, and ML-DSA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaderAttestation {
    pub slot: u64,
    pub parent_block_hash: [u8; 32],
    pub qrng_value: [u8; 32],
    pub qrng_epoch: u64,
    pub claimed_leader_id: [u8; 32],
    /// ML-DSA-65 encoded verifying key (1952 bytes).
    pub signing_public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub smt_root_pre: Option<[u8; 32]>,
}

/// Recompute `Seed_k` from anchor (finalized L1 limbs).
#[must_use]
pub fn mssq_seed_from_anchor<A: L1Anchor + ?Sized>(anchor: &A) -> [u8; 32] {
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

fn verify_mldsa65(pk: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), BatcherError> {
    let enc = EncodedVerifyingKey::<MlDsa65>::try_from(pk)
        .map_err(|_| BatcherError::InvalidSigningKey)?;
    let vk = VerifyingKey::<MlDsa65>::decode(&enc);
    let sig =
        Signature::<MlDsa65>::try_from(sig_bytes).map_err(|_| BatcherError::InvalidSignature)?;
    vk.verify(msg, &sig)
        .map_err(|_| BatcherError::InvalidSignature)
}

/// Verify attestation using a [`RollupContext`] + explicit `slot` (no [`L1Anchor`](qssm_common::L1Anchor)).
pub fn verify_leader_attestation_ctx(
    att: &LeaderAttestation,
    ctx: &RollupContext,
    slot: u64,
    candidates: &[[u8; 32]],
) -> Result<(), BatcherError> {
    if att.slot != slot {
        return Err(BatcherError::WrongSlot);
    }
    if att.parent_block_hash != ctx.finalized_block_hash {
        return Err(BatcherError::MismatchedParentBlockHash);
    }
    if att.qrng_value != ctx.qrng_value || att.qrng_epoch != ctx.qrng_epoch {
        return Err(BatcherError::MismatchedQrng);
    }
    if !candidates.contains(&att.claimed_leader_id) {
        return Err(BatcherError::LeaderNotInCandidateSet);
    }
    let derived_id = leader_id_from_ml_dsa_public_key(&att.signing_public_key);
    if derived_id != att.claimed_leader_id {
        return Err(BatcherError::LeaderKeyIdMismatch);
    }
    let seed = mssq_seed_k(&ctx.finalized_block_hash, &ctx.qrng_value);
    let winner = elect_leader(&seed, candidates)?;
    if winner != att.claimed_leader_id {
        return Err(BatcherError::NotWinningLeader);
    }
    let ctx_digest = ctx.digest();
    let msg = leader_attestation_signing_bytes(
        att.slot,
        &att.parent_block_hash,
        &att.qrng_value,
        att.qrng_epoch,
        &seed,
        &ctx_digest,
        att.smt_root_pre.as_ref(),
        &att.claimed_leader_id,
    );
    verify_mldsa65(&att.signing_public_key, &msg, &att.signature)?;
    Ok(())
}

/// Verify attestation against anchor truth, lottery winner, and ML-DSA signature over canonical bytes.
pub fn verify_leader_attestation<A: L1Anchor>(
    anchor: &A,
    att: &LeaderAttestation,
    candidates: &[[u8; 32]],
) -> Result<(), BatcherError> {
    let ctx = rollup_context_from_l1(anchor);
    verify_leader_attestation_ctx(att, &ctx, anchor.get_current_slot(), candidates)
}

/// Score bytes for a candidate under the current anchor (for observability / tests).
pub fn leader_score_for_anchor<A: L1Anchor + ?Sized>(
    anchor: &A,
    candidate_id: &[u8; 32],
) -> [u8; 32] {
    let seed = mssq_seed_from_anchor(anchor);
    leader_score_digest(&seed, candidate_id)
}
