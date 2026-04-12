use std::collections::BTreeSet;

use qssm_common::{Batch, L2Transaction, RollupState};
use qssm_utils::RollupContext;

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
        apply_balance_delta(state, tx);
    }
    Ok(())
}

fn apply_balance_delta(state: &mut RollupState, tx: &L2Transaction) {
    let key = tx.id;
    let mut cur = [0u8; 32];
    let mut bal = 0u64;
    if let Some(v) = state.smt.get(&key) {
        cur = *v;
        bal = u64::from_le_bytes(cur[0..8].try_into().unwrap_or([0u8; 8]));
    }
    let add = if tx.payload.len() >= 8 {
        u64::from_le_bytes(tx.payload[0..8].try_into().unwrap_or([0u8; 8]))
    } else {
        0
    };
    let nb = bal.saturating_add(add);
    cur[0..8].copy_from_slice(&nb.to_le_bytes());
    if tx.payload.len() > 8 {
        let meta = &tx.payload[8..];
        let n = meta.len().min(24);
        cur[8..8 + n].copy_from_slice(&meta[..n]);
        cur[8 + n..32].fill(0);
    }
    state.smt.insert(key, cur);
}
