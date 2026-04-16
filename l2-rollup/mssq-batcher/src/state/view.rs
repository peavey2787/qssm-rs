use std::collections::BTreeSet;

use qssm_traits::{Batch, L2Transaction, RollupState, StorageLease};
use qssm_utils::{RollupContext, SparseMerkleProof, StateMirrorTree};

use crate::BatcherError;

/// Per-transaction proof gate (implemented in `qssm-ref` / node; keeps batcher free of `qssm-le`).
pub trait TxProofVerifier: Send + Sync {
    fn verify_tx(&self, tx: &L2Transaction, ctx: &RollupContext) -> Result<(), ProofError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("invalid or unverifiable transaction proof")]
    Invalid,
}

/// Apply a **sorted** batch: duplicate check, proof verification per tx, then SMT balance update.
///
/// `payload` layout v1: if `len >= 8`, first 8 bytes LE `u64` are added to `tx.id` account balance.
/// Bytes `8..` (up to 24) are copied into the stored leaf `value[8..32]` when present; otherwise
/// `value[8..32]` is left unchanged from the prior leaf (first write starts at zero).
pub fn apply_batch(
    state: &mut RollupState,
    sorted_batch: &Batch,
    ctx: &RollupContext,
    verifier: &dyn TxProofVerifier,
) -> Result<(), BatcherError> {
    let mut seen = BTreeSet::new();
    for tx in &sorted_batch.txs {
        if !seen.insert(tx.id) {
            return Err(BatcherError::DuplicateTxId);
        }
        verifier
            .verify_tx(tx, ctx)
            .map_err(|_| BatcherError::ProofVerificationFailed)?;
        verify_tx_merkle_inclusion(state, tx)?;
        apply_tx_transition(state, tx)?;
        state.pulse_height = state.pulse_height.saturating_add(1);
        state.recent_roots.push_back(state.root());
    }
    Ok(())
}

pub fn prune_state(state: &mut RollupState, keep_depth: u64) {
    let keep = keep_depth as usize;
    while state.recent_roots.len() > keep {
        let _ = state.recent_roots.pop_front();
    }
}

fn apply_tx_transition(state: &mut RollupState, tx: &L2Transaction) -> Result<(), BatcherError> {
    let tx_kind = tx.payload.first().copied().unwrap_or(0x01);
    match tx_kind {
        0x10 => apply_storage_lease_create(state, tx),
        0x11 => apply_storage_lease_por(state, tx),
        0x12 => apply_storage_lease_slash(state, tx),
        _ => {
            apply_balance_delta(state, tx);
            Ok(())
        }
    }
}

fn apply_balance_delta(state: &mut RollupState, tx: &L2Transaction) {
    let key = tx.id;
    let mut cur = [0u8; 32];
    let mut bal = 0u64;
    if let Some(v) = state.smt.get(&key) {
        cur = *v;
        bal = u64::from_le_bytes(cur[0..8].try_into().unwrap_or([0u8; 8]));
    }
    let add = if tx.payload.len() >= 9 && tx.payload[0] == 0x01 {
        u64::from_le_bytes(tx.payload[1..9].try_into().unwrap_or([0u8; 8]))
    } else if tx.payload.len() >= 8 {
        u64::from_le_bytes(tx.payload[0..8].try_into().unwrap_or([0u8; 8]))
    } else {
        0
    };
    let nb = bal.saturating_add(add);
    cur[0..8].copy_from_slice(&nb.to_le_bytes());
    if tx.payload.len() > 9 && tx.payload[0] == 0x01 {
        let meta = &tx.payload[9..];
        let n = meta.len().min(24);
        cur[8..8 + n].copy_from_slice(&meta[..n]);
        cur[8 + n..32].fill(0);
    } else if tx.payload.len() > 8 {
        let meta = &tx.payload[8..];
        let n = meta.len().min(24);
        cur[8..8 + n].copy_from_slice(&meta[..n]);
        cur[8 + n..32].fill(0);
    }
    state.smt.insert(key, cur);
}

fn apply_storage_lease_create(
    state: &mut RollupState,
    tx: &L2Transaction,
) -> Result<(), BatcherError> {
    if tx.payload.len() < 1 + 32 + 32 + 8 + 32 {
        return Err(BatcherError::InvalidStorageLeasePayload);
    }
    let mut lease_id = [0u8; 32];
    lease_id.copy_from_slice(&tx.payload[1..33]);
    let mut provider = [0u8; 32];
    provider.copy_from_slice(&tx.payload[33..65]);
    let rent = u64::from_le_bytes(
        tx.payload[65..73]
            .try_into()
            .map_err(|_| BatcherError::InvalidStorageLeasePayload)?,
    );
    let mut user_leaf_key = [0u8; 32];
    user_leaf_key.copy_from_slice(&tx.payload[73..105]);
    state.leases.insert(
        lease_id,
        StorageLease {
            lease_id,
            user_id: tx.id,
            provider_node_id: provider,
            rent_per_epoch: rent,
            user_leaf_key,
            next_due_pulse: state.pulse_height.saturating_add(1024),
            active: true,
            slashed: false,
        },
    );
    Ok(())
}

fn apply_storage_lease_por(
    state: &mut RollupState,
    tx: &L2Transaction,
) -> Result<(), BatcherError> {
    if tx.payload.len() < 1 + 32 + 2 {
        return Err(BatcherError::InvalidStorageLeasePayload);
    }
    let mut lease_id = [0u8; 32];
    lease_id.copy_from_slice(&tx.payload[1..33]);
    let proof_len = u16::from_le_bytes(
        tx.payload[33..35]
            .try_into()
            .map_err(|_| BatcherError::InvalidStorageLeasePayload)?,
    ) as usize;
    if tx.payload.len() != 35 + proof_len {
        return Err(BatcherError::InvalidStorageLeasePayload);
    }
    let por = SparseMerkleProof::decode(&tx.payload[35..]).ok_or(BatcherError::PorFailed)?;
    let root = state.root();
    let (lease_active, lease_slashed, lease_key, lease_due, lease_rent, lease_provider) = {
        let lease = state
            .leases
            .get(&lease_id)
            .ok_or(BatcherError::LeaseNotFound)?;
        (
            lease.active,
            lease.slashed,
            lease.user_leaf_key,
            lease.next_due_pulse,
            lease.rent_per_epoch,
            lease.provider_node_id,
        )
    };
    if !lease_active || lease_slashed {
        return Err(BatcherError::PorFailed);
    }
    if por.key != lease_key {
        return Err(BatcherError::PorFailed);
    }
    if !StateMirrorTree::verify_proof(root, &por) {
        return Err(BatcherError::PorFailed);
    }
    if state.pulse_height >= lease_due {
        let provider_key = lease_provider;
        let mut cur = [0u8; 32];
        let mut bal = 0u64;
        if let Some(v) = state.smt.get(&provider_key) {
            cur = *v;
            bal = u64::from_le_bytes(cur[0..8].try_into().unwrap_or([0u8; 8]));
        }
        let nb = bal.saturating_add(lease_rent);
        cur[0..8].copy_from_slice(&nb.to_le_bytes());
        state.smt.insert(provider_key, cur);
        if let Some(lease) = state.leases.get_mut(&lease_id) {
            lease.next_due_pulse = lease.next_due_pulse.saturating_add(1024);
        }
    } else {
        return Err(BatcherError::PorFailed);
    }
    Ok(())
}

fn apply_storage_lease_slash(
    state: &mut RollupState,
    tx: &L2Transaction,
) -> Result<(), BatcherError> {
    if tx.payload.len() < 1 + 32 {
        return Err(BatcherError::InvalidStorageLeasePayload);
    }
    let mut lease_id = [0u8; 32];
    lease_id.copy_from_slice(&tx.payload[1..33]);
    let lease = state
        .leases
        .get_mut(&lease_id)
        .ok_or(BatcherError::LeaseNotFound)?;
    lease.slashed = true;
    lease.active = false;
    Ok(())
}

fn verify_tx_merkle_inclusion(state: &RollupState, tx: &L2Transaction) -> Result<(), BatcherError> {
    let proof = SparseMerkleProof::decode(&tx.proof).ok_or(BatcherError::InvalidMerkleProof)?;
    if proof.key != tx.id {
        return Err(BatcherError::InvalidMerkleProof);
    }
    let existing = state.smt.get(&tx.id).copied();
    if existing.is_none() && proof.value.is_some() {
        return Err(BatcherError::InvalidMerkleProof);
    }
    if let Some(v) = existing {
        if proof.value != Some(v) {
            return Err(BatcherError::InvalidMerkleProof);
        }
    }
    if StateMirrorTree::verify_proof(state.root(), &proof) {
        Ok(())
    } else {
        Err(BatcherError::InvalidMerkleProof)
    }
}
