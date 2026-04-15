//! Default transaction proof verifier (replace with LE/MS decoders in production nodes).

use mssq_batcher::{ProofError, TxProofVerifier};
use qssm_common::L2Transaction;
use qssm_utils::RollupContext;

/// Accepts every transaction proof (smoke tests / scaffolding only).
#[derive(Debug, Default, Clone, Copy)]
pub struct AcceptAllTxVerifier;

impl TxProofVerifier for AcceptAllTxVerifier {
    fn verify_tx(&self, _tx: &L2Transaction, _ctx: &RollupContext) -> Result<(), ProofError> {
        Ok(())
    }
}
