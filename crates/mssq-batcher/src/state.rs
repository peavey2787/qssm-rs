use qssm_common::{Batch, L2Transaction, SmtRoot};
use qssm_utils::hashing::{hash_domain, DOMAIN_MSSQ_STATE};

use crate::BatcherError;

fn tx_digest(tx: &L2Transaction) -> [u8; 32] {
    hash_domain(
        DOMAIN_MSSQ_STATE,
        &[
            b"tx",
            tx.id.as_slice(),
            tx.proof.as_slice(),
            tx.payload.as_slice(),
        ],
    )
}

/// Deterministic state transition (Merkle-sum placeholder from plan).
pub fn apply_batch(current_root: SmtRoot, batch: &Batch) -> Result<SmtRoot, BatcherError> {
    let mut seen = std::collections::BTreeSet::new();
    for tx in &batch.txs {
        if !seen.insert(tx.id) {
            return Err(BatcherError::DuplicateTxId);
        }
    }
    let mut h = hash_domain(DOMAIN_MSSQ_STATE, &[b"batch", current_root.0.as_slice()]);
    for tx in &batch.txs {
        let d = tx_digest(tx);
        h = hash_domain(DOMAIN_MSSQ_STATE, &[h.as_slice(), d.as_slice()]);
    }
    Ok(SmtRoot(h))
}
